# 文件系统操作审批（Fs Approval）设计文档

> 状态：Draft · 目标平台：macOS（Linux/Windows 扩展见 §14）
> 对应需求：1) 约束挂载目录；2) 挂载目录内的读/写/删除需用户确认授权；3) 覆盖 Python / Node.js / Shell 命令。

---

## 1. 背景与目标

现有 sandbox-runtime 对文件系统只有**静态策略**（Seatbelt allow/deny）。本设计在其上新增一层**交互式审批**：沙箱进程对"挂载目录"（受约束目录）发起读/写/删除时，需经宿主侧用户确认后才放行。

目标：

- **挂载目录约束**：挂载目录是进程唯一可读写的文件系统区域，由现有 Seatbelt 静态策略强制（L1）。
- **逐操作授权**：读操作首访确认（会话内缓存）、写与删除每次确认，通过宿主侧回调 API（headless）征求用户决定（L2）。
- **语言无关**：Python / Node.js / Shell 统一覆盖——审批实现在 libc syscall 层，不依赖任何语言运行时。

## 2. 范围与非目标

范围内：

- macOS DYLD interposer（`open/openat/read/write/unlink/rename/…` 拦截）
- 审批服务端（verdict 缓存、ask 回调、失败即拒）
- 配置 schema（`mounts` + `fsAskCallback`）
- 与 `wrapCommandWithSandboxMacOS` 的注入集成

非目标（本阶段）：

- 非挂载目录的动态审批（由静态策略管）
- 持久化授权（写盘记忆"永远允许"）——授权均为**会话级**，不落盘
- 系统二进制（`/bin/cat`、`/usr/bin/rm`）的实时拦截（见 §10 已知限制，由 L1 兜底）
- Linux / Windows 落地（见 §14 设计要点）

## 3. 总体架构：双层策略

```
┌──────────────────────────── 宿主（Host） ────────────────────────────┐
│  SandboxManager                                                       │
│   ├─ fs-approval.ts     审批服务端：Unix socket 监听、verdict 缓存、     │
│  │                      fsAskCallback 调用（headless）                 │
│   └─ proxy servers      现有网络代理（复用 session 生命周期管理）         │
└─────────────────────────────────┬─────────────────────────────────────┘
                                  │ Unix socket RPC（verdict 请求/响应）
┌─────────────────────────────────┴─────────────────────────────────────┐
│  沙箱（sandbox-exec 包裹的进程树）                                        │
│   ┌──────────────────────────────┐                                    │
│   │ DYLD interposer（libc hook） │ ← DYLD_INSERT_LIBRARIES 注入          │
│   │  命中挂载目录 → 问审批服务端    │    Python/Node/Shell 全部经由此层     │
│   └──────────────────────────────┘                                    │
│   L1 Seatbelt 静态策略：mounts → readConfig/writeConfig                │
└─────────────────────────────────────────────────────────────────────────┘
```

| 层 | 职责 | 机制 | 失败语义 |
|---|---|---|---|
| L1 静态约束 | 挂载目录 = 唯一可访问区域；防 mv/rename 绕过 | 现有 `readConfig`/`writeConfig` → Seatbelt | 默认拒绝 |
| L2 交互审批 | 挂载目录内的读/写/删逐操作征求用户授权 | DYLD interposer + 审批服务端 | 超时/无回调 → 拒绝 |

**分工**：L1 是真正的安全边界（即使 interposer 被绕过，进程也出不了挂载目录）；L2 是"用户注意力/同意"的闸门（让 agent 的每次文件操作透明化）。威胁模型详见 §10。

## 4. 配置设计（sandbox-schemas.ts 新增）

```ts
export type FsApprovalOp = 'read' | 'write' | 'delete'

export interface FsMountConfig {
  /** 挂载/受约束目录，绝对路径或支持 ~ 展开 */
  path: string
  /** 该目录下需要审批的操作 */
  ops: FsApprovalOp[]
  /**
   * true（默认）：操作需审批。
   * false：仅静态放行（如解释器运行时目录 site-packages），不走审批，
   * 用于规避启动噪声。
   */
  requireApproval?: boolean
}

export interface FsAskParams {
  op: FsApprovalOp
  /** 触发审批的绝对路径 */
  path: string
  /** 归因命令（来自 sandbox 包装时的 commandId/encodedCommand） */
  command?: string
  /** interposer 上报的进程名 */
  processName?: string
  pid?: number
}

export type FsAskScope = 'once' | 'session' | 'always'

export interface FsAskResult {
  allow: boolean
  /** allow=true 时生效；默认 'once' */
  scope?: FsAskScope
  /** 拒绝原因 / 供上层展示的说明 */
  reason?: string
}

export type FsAskCallback = (params: FsAskParams) => Promise<FsAskResult>
```

顶层配置（`sandbox-config.ts` 解析）：

```jsonc
{
  "fsApproval": {
    "mounts": [
      { "path": "/Users/me/workspace/project", "ops": ["read", "write", "delete"] },
      { "path": "~/.venv/project/lib", "ops": ["read"], "requireApproval": false }
    ],
    // 不落盘；由宿主（如 Claude Code）在 initialize() 时通过 API 传入
    "askCallback": "<FsAskCallback>"
  }
}
```

**挂载目录 → L1 静态策略的展开规则**（在 `wrapCommandWithSandboxMacOS` 内完成）：

- 所有挂载目录（含 `requireApproval:false`）→ 并入 `readConfig.allowWithinDeny`（在 `denyOnly: ["/**"]` 或 `/Users` 等区域之上放行）。
- 挂载目录 + 系统临时目录 → 并入 `writeConfig.allowOnly`。
- 保留现有 `macGetMandatoryDenyPatterns`（危险文件/`.git/hooks`）强制覆盖。

## 5. DYLD Interposer 设计（vendor/srt-macos-interposer/）

### 5.1 拦截符号与操作映射

| libc 符号 | 判定 | 操作 |
|---|---|---|
| `open` / `openat` | flags 含 `O_WRONLY\|O_RDWR\|O_CREAT\|O_TRUNC` | `write` |
| `open` / `openat` | 其余（含 `O_RDONLY`） | `read` |
| `read` / `pread` | fd 追踪表：open 时已批为 `read` 才放行 | 随 open 的 verdict |
| `write` / `pwrite` | fd 追踪表：open 时已批为 `write` 才放行；**未追踪 fd** 拒绝 | `write` |
| `unlink` / `unlinkat` / `rename` / `renameat` / `rmdir` | — | `delete` |
| `mkdir` / `mkdirat` | — | `write`（创建） |
| `truncate` / `ftruncate` | — | `write` |

### 5.2 拦截主流程

```
fs_interpose_open(path, flags):
  op = intent(flags)                    # read | write
  if !underMountDirs(path):             # 非挂载目录：放行（由 L1 管）
    return real_open(path, flags)
  v = cacheLookup(op, path)             # 会话缓存（写入挂载目录提供的共享内存或
                                        # 本进程静态表 + 服务端缓存）
  if v: return real_open(path, flags)   # allow-session/always 命中
  verdict = rpcAsk({op, path, pid, proc})   # 阻塞等待，超时 → deny
  if verdict.allow:
    cacheStore(op, path, verdict.scope)  # read: 强制 session 缓存（首访语义）
    trackFd(op)                          # 记录返回值 fd → op
    return real_open(path, flags)
  errno = EPERM; return -1               # fail-closed
```

- **fd 追踪表**：`open` 通过后记录 `fd → op`；`close` 时清除；`dup`/`dup2`/`fork` 复制条目。`write` 对表中 `write` fd 放行；对表中 `read` fd 或未知 fd 拒绝（fail-closed）。子进程继承表（`fork` 后内存复制，天然成立）。
- **路径判定**：先 `realpath` 归一（对齐现有 `normalizePathForSandbox` 的 `isSymlinkOutsideBoundary` 语义），再前缀匹配挂载目录；命中才审批。
- **防递归**：所有内部调用（socket 写、`realpath`、`dlsym`）通过 `dlsym(RTLD_NEXT, …)` 取原始符号，避免再次进入 hook。
- **非挂载路径零开销**：前缀比较先于任何锁/socket 操作；未命中直接转发。
- **`DYLD_FORCE_FLAT_NAMESPACE=1`**：保证符号绑定替换生效。

### 5.3 注入方式

复用 [wrapCommandWithSandboxMacOS](file:///d:\prj\anthropic\sandbox-runtime-analysis\src\sandbox\macos-sandbox-utils.ts#L1168-L1179) 现有 `env` preamble：

```
env \
  DYLD_INSERT_LIBRARIES=<…>/libsrtfs_approve.dylib \
  DYLD_FORCE_FLAT_NAMESPACE=1 \
  SRT_APPROVE_SOCKET=/tmp/srt-fsapprove-<sessionSuffix>.sock \
  SRT_APPROVE_DIRS=/mount1:/mount2 \
  /usr/bin/sandbox-exec -p <profile> <shell> -c <command>
```

环境变量随 fork/exec 继承 → Python/Node 启动的子进程、Shell 外部命令全部自动覆盖。

### 5.4 构建

对齐 [vendor/seccomp/build.ts](file:///d:\prj\anthropic\sandbox-runtime-analysis\vendor\seccomp\build.ts) 模式：

```
cc -dynamiclib -O2 -fPIC -Wall -Wextra \
   -o libsrtfs_approve.dylib fs_interposer.c
```

产物在 `vendor/srt-macos-interposer/`，经 `resolveDylibPath()`（类似现有 `resolveSrtWin`/`getJavaProxyAgentJarPath`）在 wrap 时定位。

## 6. 审批服务端设计（src/sandbox/fs-approval.ts）

结构与现有 [filterNetworkRequest](file:///d:\prj\anthropic\sandbox-runtime-analysis\src\sandbox\sandbox-manager.ts#L297-L378) 对齐：

```
fsApprovalServer (随 initialize() 启动，reset() 关闭，复用 proxy 生命周期)
  ├─ 监听 SRT_APPROVE_SOCKET（chmod 600；路径含随机 sessionSuffix）
  ├─ 收到 {op, path, pid, proc} →
  │   1. sessionVerdictCache 命中 → 直接回 allow（免打扰）
  │   2. 未命中 → 调 fsAskCallback({op, path, command, processName})
  │      ├─ 无回调（headless 未接）→ 拒绝（fail-closed）并记 violation
  │      └─ 回调异常/超时 → 拒绝并记 violation
  │   3. verdict → 写缓存（scope=session/always 时）→ 回包
  └─ 每次裁决经 SandboxViolationStore 留痕（模型侧可见 <sandbox_violations>）
```

**并发防护**：每 PID 同时在途审批数上限（默认 3）。超限直接拒绝——防止沙箱内进程伪造请求刷屏提示（见 §10 攻击面 2）。

## 7. RPC 协议

- **传输**：Unix domain socket，换行分隔 JSON。
- **请求**（interposer → 服务端）：
  ```json
  {"v":1,"id":"<uuid>","op":"write","path":"/abs/path","pid":1234,"proc":"python3"}
  ```
- **响应**（服务端 → interposer）：
  ```json
  {"id":"<uuid>","allow":true,"scope":"session","reason":"ok"}
  {"id":"<uuid>","allow":false,"reason":"user denied"}
  ```
- **时序**（读首访 / 写每次）：

```
Python: open('/mnt/data.txt','w')
  │ interposer: 前缀命中 → 缓存未命中
  │ ── ask {op:write, path:…} ──► fs-approval
  │                                └─ fsAskCallback → 用户允许 (scope: session)
  │ ◄── allow,session ──
  │ 写缓存 → real_open 放行
  │
Python: open('/mnt/data.txt','r')   （同路径，首访读）
  │ ── ask {op:read, path:…} ──► fs-approval
  │ ◄── allow ── 强制 session 缓存（读首访语义）
  │
Python: 再次读同一路径 / 再次写（session 命中）→ 静默放行
```

- **超时**：interposer 侧 connect/响应超时（默认 5s，可配置）→ **拒绝**（EPERM）。写/删/读一律 fail-closed。

## 8. 会话与 verdict 语义

| scope | interposer 行为 | 服务端行为 | 适用 |
|---|---|---|---|
| `once` | 本次调用放行，不缓存 | 不缓存 | 写/删默认，每次确认 |
| `session` | 本进程树缓存（op+path） | 会话缓存 | 读首访强制；写/删可经用户选择 |
| `always` | 同 session | 同 session（**不落盘**） | 用户"本次会话始终允许" |

- **读首访语义实现**：`read` 的 verdict 在服务端强制 `scope=session`（除非用户显式拒绝），与"读首访确认"需求一致。
- **写/删每次确认**：服务端默认不缓存 `once`；只有回调返回 `session/always` 才缓存。
- 缓存键 = `op + normalized(path)`；`rename` 的目标路径也需审批（源=delete，目标=write，各一次 ask，可合并为一次 `delete+write` ask）。

## 9. 与现有代码集成点

| 文件 | 改动 |
|---|---|
| `src/sandbox/sandbox-schemas.ts` | 新增 `FsMountConfig`/`FsAskParams`/`FsAskResult`/`FsAskCallback` |
| `src/sandbox/sandbox-config.ts` | 解析 `fsApproval.mounts`；新增 `setFsAskCallback()` |
| `src/sandbox/fs-approval.ts` | **新增**：审批服务端 + verdict 缓存 + violation 留痕 |
| `src/sandbox/fs-interposer.ts` | **新增**：socket 注册/路径组装/session 生命周期（对齐 proxy 启动） |
| `src/sandbox/sandbox-manager.ts` | initialize() 启动/关闭 fs-approval 服务；wrap 时传 mounts + socket 路径；扩展 `SandboxManagerOptions` |
| `src/sandbox/macos-sandbox-utils.ts` | `MacOSSandboxParams` 增 `mounts`/`approvalSocketPath`/`interposerDylibPath`；mounts→readConfig/writeConfig 展开；DYLD env 注入 |
| `vendor/srt-macos-interposer/` | **新增**：`fs_interposer.c` + `build.ts` |
| `src/index.ts` | 导出新类型 |

## 10. 安全分析与威胁模型

**边界定位**：L1（Seatbelt）是安全边界；L2（interposer 审批）是**用户同意闸门**。攻击面内假设"进程本身不可信但受 L1 约束"；L2 保护的是"agent（模型）的文件操作必须经用户同意"，而非防住已沦陷进程（已沦陷进程本就只能碰挂载目录）。

| # | 攻击面 | 缓解 |
|---|---|---|
| 1 | 绕过 interposer（静态链接二进制、系统二进制） | L1 静态策略兜底：写/删出不了挂载目录；系统工具走"先禁后问"（见 §11.1） |
| 2 | 沙箱进程向审批 socket 伪造请求刷屏 | 每 PID 在途上限 3；socket chmod 600 + 随机名；服务端只服务本会话 |
| 3 | 审批放行后被同路径滥用（race） | verdict 绑定 `op+path` 且会话缓存；恶意进程仍受 L1 区域约束 |
| 4 | interposer 内 deadlock/自递归 | `RTLD_NEXT` 取原始符号；socket 写用非阻塞+超时；禁止在 hook 内做锁竞争 |
| 5 | 超时/无回调 | fail-closed：读、写、删一律 EPERM，并记 violation |
| 6 | 读首访缓存扩大化 | 缓存键含 op+path；`rename` 后路径重新审批；缓存仅会话级不落盘 |

## 11. 已知限制

### 11.1 系统二进制不受 DYLD 拦截

macOS 10.14+ 对 Apple 签名、位于 `/bin`、`/usr/bin` 的系统二进制剥离 `DYLD_*` 环境变量，`/bin/cat`、`/bin/rm`、`/usr/bin/git` 等**无法实时审批**。对策（采用"先禁后问"模式，复用现有基础设施）：

1. L1 Seatbelt deny 挂载目录外的写/删（已由静态策略保证）。
2. [macOS log monitor](file:///d:\prj\anthropic\sandbox-runtime-analysis\src\sandbox\macos-sandbox-utils.ts#L1204-L1299) 捕获违规 → 宿主弹窗"是否放行并重跑该命令"。
3. 用户允许 → 临时放宽该路径静态规则并重跑。

结论：Python/Node/Shell 内建/三方工具为实时审批；系统工具为事后审批。文档与上层 SDK 需向用户说明这一差异。

### 11.2 启动噪声

Python 解释器会读取 `sys.path`/`.pth`/`site-packages`。建议此类运行时目录用 `requireApproval:false`（静态放行），只对用户数据目录开审批。

### 11.3 继承 fd

`open` 之前由已授权上下文产生的 fd 不可追溯：`write` 到未追踪 fd 直接拒绝（fail-closed）；确需放行（如 socketpair 管道）时按 `path:"<fd:N>"` 兜底审批，后续版本可加白名单。

## 12. 测试计划（对齐现有 bun:test 模式）

| 层 | 用例 |
|---|---|
| 单元（fs-approval.test.ts） | verdict 缓存键语义；read 强制 session；once 不缓存；回调异常/超时 fail-closed；在途上限 |
| 集成（macOS 真机，对齐 [macos-seatbelt.test.ts](file:///d:\prj\anthropic\sandbox-runtime-analysis\test\sandbox\macos-seatbelt.test.ts)） | Python 写文件触发 1 次 ask；同路径再写命中 session 免问；Node 读首访 ask、二次读免问；`rm`/`mv`（Python `os.remove`/`shutil.move`）触发 delete ask；非挂载目录零 ask |
| 协议 | interposer 超时 → EPERM；服务端拒绝 → EPERM；并发 10 个写仅 3 个在途 |
| 构建 | `vendor/srt-macos-interposer/build.ts` 产物加载成功（`DYLD_INSERT_LIBRARIES` 生效冒烟） |

## 13. 实施任务拆分

1. schema + config 解析（sandbox-schemas / sandbox-config）
2. `fs-approval.ts` 服务端 + verdict 缓存 + violation 留痕
3. `vendor/srt-macos-interposer/`：`fs_interposer.c` + `build.ts` + `fs-interposer.ts` 组装
4. `macos-sandbox-utils.ts`：mounts 展开 + DYLD 注入 + wrap 参数贯通
5. `sandbox-manager.ts`：服务生命周期（initialize/reset）+ `SandboxManagerOptions` 扩展
6. 测试（§12）
7. README / 文档更新

## 14. 平台扩展（后续）

- **Linux**：L1 = 现有 bwrap（mount 绑定 + 网络隔离）；L2 = 复用现有 [apply-seccomp.c](file:///d:\prj\anthropic\sandbox-runtime-analysis\vendor\seccomp-src\apply-seccomp.c) + [linux-violation-monitor.ts](file:///d:\prj\anthropic\sandbox-runtime-analysis\src\sandbox\linux-violation-monitor.ts) 的 observer 通道：将"写意图 syscall"从报告升级为"先询问审批服务端再决定放行/拒绝"。无需 DYLD。
- **Windows**：L1 = 现有 srt-win ACL + WFP；逐操作审批需 Minifilter/ETW，改动量大，暂不纳入。
