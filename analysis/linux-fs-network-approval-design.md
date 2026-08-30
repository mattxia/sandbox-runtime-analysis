# Linux 文件读写删审批 + 域名网络策略 实现规格建议

> 目标平台：Linux。基于现有沙箱架构（bwrap + apply-seccomp + socat 桥）设计"文件读/写/删除需用户确认授权"与"基于域名的网络访问策略"。
> 参考：`docs/fs-approval-design.md`（macOS fsApproval 设计）、`analysis/linux-sandbox-analysis.md`（现有 Linux 安全机制分析）。

## 一、总体思路

Linux 与 macOS 本质差异决定了实现路径：

| 能力 | macOS 现状 | Linux 可行方案 |
|---|---|---|
| 文件读写删审批 | DYLD interposer（用户态拦截） | **seccomp USER_NOTIF + supervisor**（内核级拦截，复用 apply-seccomp 现有观察通道，升级为强制通道） |
| 域名网络策略 | 无（仅静态） | **netns 强制走代理 + 宿主代理层域名过滤**（内核边界只看 IP 不看域名，域名必须过滤在代理层） |

关键事实：项目已有的 `observe_calls[]` 观察过滤器（捕获 openat/unlinkat/mkdirat/renameat* → USER_NOTIF → `process_vm_readv` 读路径 → CONTINUE）已经把"拦截 + 路径提取"做完了，只是回 CONTINUE 不决策。**升级为审批 = 把 CONTINUE 改成 block + 查 verdict + 回 CONTINUE/EPERM**，成本集中在 supervisor 逻辑。

---

## 二、文件读 / 写 / 删除审批

### 2.1 拦截面（syscall 表）

| 类别 | syscall | 判定依据 | 触发审批 |
|---|---|---|---|
| 读 | openat / open / openat2 | `flags & O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND == 0` | 首次确认 |
| 写 | openat / open / openat2 + creat / truncate / ftruncate / fchmodat / fchownat / utimensat | flags 含写位，或元数据写 | 每次确认 |
| 删除 | unlinkat / unlink / rmdir | 无条件 | 每次确认 |
| 创建/重命名 | mkdirat / mknodat / symlinkat / linkat / renameat / renameat2 | 无条件 | 每次确认 |

不拦截 read/write/pread/pwrite（高频，性能灾难）：**访问模式在 open 时由内核锁定，无法通过 fcntl 提升**，open 时审批已覆盖读写语义；与 macOS 版不同，不需要 fd→路径解析的每调用拦截。

### 2.2 审批流程（单次 syscall）

```
worker (被冻结在 syscall 入口)
  → seccomp USER_NOTIF
  → outer stub supervisor（无 seccomp，在 bwrap 层）
      ├─ 从 args 提取 dirfd + path 指针，process_vm_readv 读路径
      ├─ 相对路径 → 复用 resolve_relative()（/proc/<pid>/cwd、/proc/<pid>/fd/<n>）
      ├─ 与挂载边界匹配（复用 fsApproval 的 isUnder 双副本匹配）：
      │    · 不在任何允许挂载内 → 不审批，直接 CONTINUE（bwrap 静态边界兜底）
      │    · 在允许挂载内 → 查 verdict 缓存
      │         · 命中 → CONTINUE 或 EPERM
      │         · 未命中 → RPC 到审批服务器 → 等 verdict（worker 保持冻结）
      ├─ verdict=allow → CONTINUE；deny → resp.error = -EPERM
      └─ 审计：无论结果，按现有 JSON 行协议写 SRT_OBSERVE_SOCK
```

### 2.3 verdict 语义（复用 macOS fsApproval 模型）

- **读**：首访确认，会话内缓存（session 级）
- **写/删除**：每次确认，仅回调显式返回 `session`/`always` 才缓存
- **fail-closed**：审批服务器未运行 / 超时 / 回调抛错 → EPERM
- 每 PID 在途请求上限（默认 3），防提示刷屏
- **审批 RPC 协议与服务器直接复用** `src/sandbox/fs-approval.ts`（`FsApprovalServer` + verdict 缓存 + 回调），Linux 侧只需新增 supervisor 侧客户端

### 2.4 关键工程点

1. **审批通道与 AF_UNIX 阻断不冲突**：RPC 由 outer stub（bwrap 层，无 seccomp）发起并 connect 到审批 socket，worker 自身不碰 socket。观察通道已证明此模式可行（`connect_observe_sock`）。
2. **路径可信度**：路径来自攻击者内存，有竞态。规格原则：**审批只影响"人工确认内容"，不扩大越权**——真正的强制边界仍是 bwrap 挂载表（只读根 + 允许写路径），即使路径被竞态伪造，写操作也撞不上挂载允许区。可选强校验：supervisor 用 `openat2(proc_root_fd, path, O_PATH|O_NOFOLLOW)` 在冻结窗口内二次解析确认真实路径（worker 单线程时 cwd/fd 稳定）。
3. **fd 语义**：`close/dup` 不跟踪（模式由 open 锁定）；`SCM_RIGHTS` 传 fd 后接收方继承已审批的访问模式，属内核语义，与 fanotify/LSM 同等接受度。
4. **监听者限制**：内核每进程只允许一个 USER_NOTIF listener（EBUSY），必须与现有观察过滤器合并为**同一过滤器**：未授权路径 → CONTINUE（静默），授权路径且写意图 → USER_NOTIF（审批），授权路径读首访 → USER_NOTIF（审批）。`observe_calls[]` 表扩展为"行为"字段（observe / approve-read / approve-write / approve-delete）。

### 2.5 配置项（新增）

```yaml
fsApproval:
  enabled: true
  mode: enforce            # enforce | observe（观察模式=现状，灰度用）
  askCallback: (req) => Promise<Verdict>
  mountScope: [...paths]   # 仅这些路径内的操作触发审批
  cacheReadSession: true
  inflightPerPid: 3
  timeoutMs: 30000
```

---

## 三、基于域名的网络访问策略

### 3.1 现状

`--unshare-net` 已保证沙箱内只剩 loopback（bwrap 自动 up lo），TCP 只能到 `127.0.0.1`；唯一出站路径是：沙箱内 socat `TCP-LISTEN:3128/1080` → bind 进来的 unix socket → 宿主 socat → 宿主代理 → 外部。域名过滤发生在**宿主代理层**（CONNECT host / SOCKS5 domain），`allowedDomains` 语义由代理实现（README 已注明此局限）。

### 3.2 规格建议：三层强制

```
L1 网络可达性（现有，bwrap）：--unshare-net，仅 lo，外部 IP 物理不可达
L2 代理端口白名单（新增，seccomp）：connect()/sendto() 仅放行 127.0.0.1:3128/1080，
                                   其余一律 EPERM —— 纵深防御，防沙箱内进程访问
                                   本 netns lo 上的其他本地服务（SSRF 到沙箱内其他进程）
L3 域名过滤（现有，宿主代理）：CONNECT host / SOCKS5 domain 匹配 allowedDomains
```

### 3.3 补充机制（可选）

| 机制 | 解决的问题 | 说明 |
|---|---|---|
| 沙箱内 DNS 白名单解析器 | 应用先 `getaddrinfo` 再连接（不走代理的客户端） | 把沙箱内 `/etc/resolv.conf` 指向一个白名单 resolver（只对 allowedDomains 返回 IP，其余 NXDOMAIN）。对 `HTTP_PROXY` 体系下的 Node/Python 非必需（CONNECT 直接发 host，不先解析） |
| seccomp 拦裸 DNS | 强制"必须走代理" | 对 `socket(AF_INET, SOCK_DGRAM)` 返回 EPERM 可阻断裸 DNS，配合 L2 即可覆盖"必须先解析再直连"类客户端 |
| SNI 级过滤 | HTTPS 代理降级 / 直连场景 | 需 MITM 或 eBPF，规格不建议首期做（代理 CONNECT 已覆盖主流流量） |

### 3.4 防绕过分析

| 绕过手段 | 被哪层拦住 |
|---|---|
| 沙箱内 connect 外部 IP | L1（netns 无路由） |
| connect `127.0.0.1:非代理端口`（SSRF 沙箱内服务） | L2（seccomp 白名单） |
| 直连 IP 而非法绕过域名检查 | L1（外部不可达）+ L3（无法绕开代理） |
| 裸 DNS 外带（TXT 记录携带数据） | 可选 seccomp 拦 UDP 53 / 沙箱内 DNS 白名单 |
| 已打开 fd 传给恶意进程 | 内核语义，netns + L2 端口白名单兜底 |

### 3.5 配置项（新增）

```yaml
networkPolicy:
  mode: proxy-only            # 现状；可选 dns-allowlist 追加
  proxyPortWhitelist: [3128, 1080]   # 喂给 seccomp BPF 生成器
  allowedDomains: [...]       # 下发宿主代理；供沙箱内 DNS resolver 复用
  resolveSocketPath: ...      # 沙箱内 DNS 白名单 resolver 的 unix socket（可选）
```

---

## 四、建议实现顺序

1. **t1**：apply-seccomp 观察过滤器扩展为"行为分派"（approve-read/write/delete 走 USER_NOTIF，其余继续观察），先以 `observe` 模式灰度（无行为改变，只打日志，验证路径提取质量）
2. **t2**：outer stub 增加 verdict 缓存 + 审批 RPC 客户端（协议复用 fs-approval.ts 的 JSON 行协议），`enforce` 模式切换
3. **t3**：宿主侧挂 `FsApprovalServer` 生命周期（`initialize`/`reset`，对齐 macOS 沙箱管理器集成）
4. **t4**：seccomp 网络端口白名单（BPF 生成器支持放行指定 `connect()` 目标端口）
5. **t5**：可选沙箱内 DNS 白名单 resolver + 测试矩阵（Python/Node/Shell、Go 静态二进制、`env` 注入）

## 五、主要风险

- **USER_NOTIF 高频拦截性能**：解决——只拦 open/unlink/rename 族，不拦 read/write
- **多线程竞态下的路径误读**：解决——bwrap 挂载表兜底 + 可选 openat2 复查
- **每进程单 listener 限制**：解决——合并观察/审批为同一过滤器
- **域过滤依赖代理**：代理必须强制启用（`mode: proxy-only`），否则域名策略为空转

---

## 六、关联文档与配置项引用

- 现有 Linux 沙箱全量配置项（`bwrapPath` / `socatPath` / `seccompConfig.applyPath|argv0` / `allowAllUnixSockets` / `enableWeakerNestedSandbox` / `mandatoryDenySearchDepth` / `observeSocketPath` 等）见 `linux-sandbox-analysis.md` §8.1。
- 本设计新增配置项（`fsApproval` 块、`networkPolicy` 块）见本文档 §2.5、§3.5，与现有配置并列，不修改既有语义。
