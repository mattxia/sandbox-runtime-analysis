# 沙箱文件删除需用户确认（deleteAsk）功能设计文档

> 版本: v0.1（设计稿）
> 适用代码基线: sandbox-runtime 0.0.73
> 目标平台: Linux（完整实现）、macOS（DYLD interposer 实现）
> 状态: 待评审

---

## 1. 概述

### 1.1 目标

为沙箱新增文件系统策略 `deleteAsk`：当沙箱内进程尝试删除（unlink/rmdir）或移动覆盖（rename）指定目录下的文件时，**挂起该操作**，向宿主侧调用者（Agent）发起用户确认；用户确认后**继续执行原操作**，拒绝则向沙箱内进程返回 `EPERM`（进程看到正常的删除失败）。

### 1.2 决策原则（重要）

- `deleteAsk` 定位为**软策略（UX 层）**：用于让用户对敏感删除有知情权，**不是安全边界**。
- 安全边界仍由现有硬拒绝兜底：若目标同时命中 `denyWrite`（Linux 挂载层 / macOS seatbelt），**永远拒绝**，不进入询问流程。
- 决策**超时默认拒绝（fail-closed）**；宿主进程退出时对全部挂起请求统一拒绝。
- 挂起期间的路径判定存在内在不可信性（见 §9），必须显式声明并缓解。

### 1.3 范围

| 能力 | Linux | macOS |
|---|---|---|
| unlink/rmdir 删除询问 | ✅ USER_NOTIF 决策模式 | ✅ DYLD interposer |
| rename 覆盖询问 | ✅（可选开关） | ✅（可选开关） |
| 超时 fail-closed | ✅ | ✅ |
| 批量拒绝（宿主退出） | ✅ | ✅ |
| 静态链接二进制 | 内核层天然覆盖 | ❌ 无法覆盖（需声明降级为 deny） |

---

## 2. 总体架构

### 2.1 Linux 数据流

```
沙箱内 python3: os.remove("/project/data/x.csv")
    │  syscall unlinkat(dirfd=5, "x.csv")
    ▼
seccomp USER_NOTIF 过滤器（决策模式，挂起，不回 CONTINUE）
    ▼
apply-seccomp outer stub (supervise 决策循环)
    │  读取路径(process_vm_readv, 目标已冻结) + stat 校验 dev/ino
    │  发帧 {type:"ask-delete", id, dev, ino, path}
    ▼
SRT_OBSERVE_SOCK (unix socket, 双向 JSON Lines)
    ▼
linux-violation-monitor (升级为请求-响应服务器)
    │  按 id 维护 pending；路径是否 ∈ deleteAsk 的最终判定（宿主侧用可信逻辑）
    ▼
SandboxManager.handleFileDeleteAsk()
    ▼
sandboxAskCallback({kind:'file-delete', path, op, resolvedCommand})  ← Agent 弹窗
    │  allow / deny / 超时30s(默认deny)
    ▼
verdict 帧 {type:"verdict", id, allow} ──► outer stub
    │  allow → NOTIF_SEND(CONTINUE) → python 删除继续
    └─ deny  → NOTIF_SEND(EPERM)    → os.remove 抛 OSError
```

### 2.2 macOS 数据流

```
沙箱内 python3: os.remove("/project/data/x.csv")
    │  libc unlinkat → 被 DYLD interposer 拦截（srt-fileops-interposer.dylib）
    ▼
interposer: 解析真实路径 → 判定是否 ∈ deleteAsk
    │  是 → 通过 unix socket (/tmp/claude-ask-<id>.sock) 发 ask-delete 帧
    │       当前线程阻塞等待 verdict（condvar）
    │  否 → 直接直通真实 syscall
    ▼
宿主侧 ask-server（SandboxManager 内新增监听）
    ▼
handleFileDeleteAsk → sandboxAskCallback → verdict 帧回写
    ▼
interposer 收到 verdict:
    │  allow → syscall(SYS_unlinkat, ...) 真实执行（避免递归）
    └─ deny  → 返回 EPERM
```

---

## 3. 数据结构设计

### 3.1 配置层（`src/sandbox/sandbox-config.ts`）

在 `SandboxFilesystemConfig` 中新增（保持 zod schema 与类型同步，参照 `denyWrite` 的既有写法）：

```ts
/** 删除/移动覆盖需用户确认的目录（绝对路径，支持 glob，解析规则同 denyWrite） */
deleteAsk?: string[]

/** 单次决策超时（ms）。默认 30_000；超时按拒绝处理（fail-closed）。0 表示不超时（不推荐）。 */
deleteAskTimeoutMs?: number

/** 是否对 rename* 的覆盖目标同样询问（默认 true）。rename 目标目录也须命中 deleteAsk。 */
deleteAskRename?: boolean
```

**解析时机**：复用 `getFsWriteConfig`（`src/sandbox/sandbox-manager.ts` `resolveFilesystemRestrictions` 同段），Linux 上用 `rg` 展开 glob（同 `denyWrite` 的 glob 过滤逻辑，见 `src/sandbox/sandbox-manager.ts` L1239 附近）；展开失败项忽略并 warn（同 denyWrite 语义）。macOS 上 glob 由 profile/interposer 侧按展开结果匹配，**不引入 glob 通配运行时匹配**（与现状一致）。

### 3.2 回调层（`src/sandbox/sandbox-schemas.ts`）

现有 `SandboxAskCallback` 仅接受 `NetworkHostPattern`（L103-106）。泛化如下，**保持向后兼容**（现有网络调用点仅需适配新签名）：

```ts
export type SandboxAskKind = 'network' | 'file-delete'

/** 统一请求载荷。按 kind 取用字段；其余字段为 undefined。 */
export interface SandboxAskRequest {
  kind: SandboxAskKind
  // ---- network ----
  host?: string
  port?: number
  // ---- file-delete ----
  path?: string
  op?: 'unlink' | 'rmdir' | 'rename'
  /** 归因：解码后的原始命令（经 resolveCommandText/decodeSandboxedCommand） */
  resolvedCommand?: string
}

export type SandboxAskCallback = (req: SandboxAskRequest) => Promise<boolean>
```

**兼容策略**：网络路径（`filterNetworkRequest`）改传 `{ kind:'network', host, port }`；Agent 侧若已按旧签名实现回调，提供一次性适配包装或双签名判别（按 `req.kind` 分流）。

### 3.3 宿主侧会话状态（`src/sandbox/sandbox-manager.ts`）

模块级新增（与 `sandboxViolationStore` 并列，reset() 时清空）：

```ts
/** deleteAsk 决策器：宿主侧最终判定"路径是否属于需确认目录"。 */
let deleteAskResolver: DeleteAskResolver | undefined

/** deleteAsk 目录集合（解析后的具体路径 + 目录 dev/ino 缓存）。 */
let deleteAskDirs: PathMatcher | undefined

/** macOS ask-server 监听句柄。 */
let macAskServer: AskServer | undefined
```

### 3.4 沙箱↔宿主统一帧（TypeScript 侧类型，见 §4）

```ts
export type AskFrame =
  | { type: 'hello'; version: 1; encodedCommand?: string }
  | { type: 'ask-delete'; id: number; pid: number; op: 'unlink'|'rmdir'|'rename';
      dev: number; ino: number; path: string }
  | { type: 'verdict'; id: number; allow: boolean }
  | { type: 'reject-all'; reason?: string }
  | { type: 'bye' }
```

---

## 4. 协议帧格式

### 4.1 传输与编码

- 传输：**文件系统 unix socket**（Linux 必须——bwrap `--unshare-net` 隔离 abstract socket；macOS 可复用同一约定），路径由宿主生成、bind 进沙箱。
- 编码：JSON Lines，每帧一行，`\n` 定界；字段均为小写 snake_case。
- 方向：帧中的 `id` 由**沙箱侧发起方生成**（单调递增），宿主侧回 verdict 时必须携带同一 `id`。
- 帧最大行长 64 KiB（路径上限保护，超长直接判 deny）。

### 4.2 帧定义

| 帧 | 方向 | 字段 | 说明 |
|---|---|---|---|
| `hello` | 沙箱→宿主 | `version`=1；`encodedCommand?` | 连接建立后沙箱侧首帧；`encodedCommand` 用于归因（兼容现有 monitor 首行约定，见 `linux-violation-monitor.ts` L159-163） |
| `ask-delete` | 沙箱→宿主 | `id`、`pid`、`op`、`dev`、`ino`、`path` | 请求确认。`dev/ino` 为 **dirfd（目录文件描述符）** 的 stat 结果（内核可信），`path` 为相对/绝对路径串（不可信，仅辅助展示） |
| `verdict` | 宿主→沙箱 | `id`、`allow` | 决策回复。必须存在；宿主收到 `bye` 或连接断开前需回复全部 pending |
| `reject-all` | 宿主→沙箱 | `reason?` | 宿主退出/重置：沙箱侧对全部 pending 的未决请求按拒绝结算（NOTIF_SEND EPERM / interposer 返回 EPERM） |
| `bye` | 沙箱→宿主 | — | 沙箱侧进程结束，关闭前发送 |

### 4.3 时序状态机（Linux，单请求）

```
S0  idle ── USER_NOTIF(挂起) ──► S1  pending
S1  pending ── 读路径+stat 校验失败(不匹配 deleteAsk) ──► CONTINUE 放行 ──► S0
S1  pending ── 读路径成功、匹配 deleteAsk ── 发 ask-delete ──► S2  awaiting
S2  awaiting ── verdict allow ──► NOTIF_SEND(CONTINUE) ──► S0
S2  awaiting ── verdict deny / 超时 / reject-all ──► NOTIF_SEND(EPERM) ──► S0
S0 ── 连接 EOF / 宿主退出 ──► 全部 pending 按拒绝结算
```

---

## 5. Linux 实现设计

### 5.1 apply-seccomp 改造（`vendor/seccomp-src/apply-seccomp.c`）

#### 5.1.1 新增 CLI 选项

| 选项 | 说明 |
|---|---|
| `--ask-delete` | 开启决策模式（默认关闭，保持现状纯观察） |
| `--ask-timeout-ms N` | 决策超时（仅用于宿主无响应时的本地兜底，默认 30s） |

#### 5.1.2 BPF 过滤器（决策模式）

`install_observe_filter`（L322）当前对所有 write-intent syscall 统一 USER_NOTIF + supervisor 回 CONTINUE。决策模式新增第二层语义：

- **挂起集合**：`unlinkat`、`rmdir`、`renameat`、`renameat2`（后两者是否纳入由 `--ask-delete-rename` 控制，默认纳入）。
- 对这些 syscall 的匹配返回 `SECCOMP_RET_USER_NOTIF`（**不设** CONTINUE 标志，调用者被挂起）。
- 其余 write-intent syscall 维持现状：USER_NOTIF 观察 + CONTINUE。

#### 5.1.3 supervise 决策循环（L516-549 改造）

当前循环：`NOTIF_RECV → 读路径 → NOTIF_SEND(CONTINUE)`。改为：

```
NOTIF_RECV → 读取 req（含 dirfd/dev/ino、args.path）
  ├─ op ∉ 挂起集合 → NOTIF_SEND(CONTINUE)
  ├─ 读取路径（process_vm_readv，目标已冻结）两次并比对（缓解 TOCTOU，见 §9）
  ├─ 本地 stat(path) 校验 dev/ino 与 req 的 dirfd dev/ino 一致
  │    （一致 → 路径可信度提升；不一致 → 视为不可信，直接 CONTINUE 放行并记 warn，
  │      绝不把不可信路径用于"拒绝"决策——拒绝只来自 bwrap 硬边界）
  ├─ 命中判定：路径 ∈ deleteAsk 目录 → 发 ask-delete 帧，登记 pending{id,notify_fd,req}，poll 等待
  └─ 未命中 → NOTIF_SEND(CONTINUE)
收到 verdict{id,allow} → pending 中取 notify_fd → resp.flags = allow ? CONTINUE : EPERM → NOTIF_SEND
收到 reject-all / EOF / 超时 → 全部 pending 按拒绝结算
```

**注意**：`supervise` 中 `NOTIF_SEND` 回复的 `resp.error` 填 `EPERM`（`resp.val` 忽略）实现拒绝；`resp.flags` 仅 allow 时设 `SECCOMP_USER_NOTIF_FLAG_CONTINUE`。

#### 5.1.4 通道复用

复用现有 socketpair + `SRT_OBSERVE_SOCK`（`src/sandbox/linux-sandbox-utils.ts` L1784-1801 的 bind/`--setenv` 注入不变），outer stub 把 SRT_OBSERVE_SOCK 从"只写"改为"读写 + poll 多路复用"。

#### 5.1.5 进程退出兜底

outer stub 在 `supervise` 循环退出（工作负载结束 / 信号）前，向宿主发送 `bye`，并将**尚未回复的挂起请求全部 NOTIF_SEND(EPERM)**（进程退出时挂起即孤儿，绝不允许 hang）。

### 5.2 linux-violation-monitor 升级（`src/sandbox/linux-violation-monitor.ts`）

- 保持现有"监听 + 每连接首行 hello/encodedCommand"语义（L159-163），扩展为**双向**：
  - 入站帧 `ask-delete` → 回调 `onAskDelete(frame)`（由 SandboxManager 注入）；宿主判定后回 `verdict`。
  - 增加 `rejectAll()` 方法（SandboxManager.reset()/exit 时调用，向所有存活连接广播 `reject-all`）。
- `handleEvent`（violation 相交判定，L94 附近）保持不变：ask 流程之外的写意图仍按旧逻辑上报。
- **宿主侧目录判定放这里做**（可信逻辑在宿主侧，不信任沙箱传来的 path）：`onAskDelete` 内对 `dev/ino` + path 做最终 `∈ deleteAsk` 判定与验证，验证失败按 deny 回复。

### 5.3 bwrap 参数（`src/sandbox/linux-sandbox-utils.ts`）

- `wrapCommandWithSandboxLinux`（L1686+）新增参数 `askDeleteDirs: string[]`；
- 观察 socket 的 bind/`--setenv` 逻辑（L1784-1801）不变；
- 若 `deleteAsk` 为空，完全走现状（零性能/行为影响）。

---

## 6. macOS 实现设计

### 6.1 DYLD interposer（新二进制，与 java-proxy-agent 同仓库布局）

新目录 `vendor/fileops-interposer/`，产物 `srt-fileops-interposer.dylib`，`DYLD_INSERT_LIBRARIES` 注入（与项目文件掩码 interposer 规划同机制）。

**挂钩函数**（每个仅封装，真实执行用 `syscall(SYS_...)` 避免递归）：

| 符号 | syscall 映射 | 语义 |
|---|---|---|
| `unlink` / `remove` | `SYS_unlink` / `SYS_unlink` | 删除 |
| `unlinkat` | `SYS_unlinkat` | 删除（含 AT_FDCWD） |
| `rmdir` | `SYS_rmdir` | 删目录 |
| `rename` / `renameat` / `renameat2` | 对应 syscall | 覆盖目标视为删除（`--ask-delete-rename`） |

**流程**：

```
1. 解析绝对路径（realpath 或 dirfd+path 拼接）
2. 判定 ∈ deleteAsk 目录（宿主注入的目录清单经 env 传入，interposer 侧只做字面前缀匹配，
   不做可信决策——最终判定在宿主）
3. 未命中 → syscall 直通
4. 命中 → 写 ask-delete 帧 → 线程阻塞在 condvar 等待（不阻塞其他线程）
   → verdict allow: syscall 直通 / deny: errno=EPERM 返回 -1
```

**线程安全**：全局 pending 表 + mutex/condvar；每个挂钩线程独立等待；`atfork` 注册清理避免 fork 后挂起。

**通道**：`/tmp/claude-ask-<sessionId>.sock`（宿主 ask-server 监听），env 注入 `SRT_ASK_SOCK`；与 Linux 帧格式完全一致（§4）。

### 6.2 与 seatbelt 的协作

- **不依赖 seatbelt 拦截删除**：SBPL 是纯 deny，无法实现"询问后继续"。
- 但保留硬兜底：若目标同时命中 `denyWrite`，seatbelt 的 `file-write-unlink` deny 规则照常生效（`generateReadDenyUnlinkRules` L331-389 逻辑不变），interposer 判定应**优先让位于硬拒绝**——命中 denyWrite 的路径直接返回 EPERM，不进询问。
- 需要确认 `generateReadDenyUnlinkRules` 与 interposer 的先后：interposer 在前（用户态），应内置一份 denyWrite 检查（由宿主注入）以保持与 seatbelt 一致的拒绝语义。

### 6.3 覆盖范围限制（必须声明）

- 仅动态链接、经过 libc 的进程可拦截（python3/JS/PHP 等满足）；**静态链接/直接 syscall 的二进制不受控**。
- 不受控路径的删除策略降级为：命中 deleteAsk 即按 deny 处理（在宿主侧对未知进程不做承诺），或明确文档声明"deleteAsk 在 macOS 仅覆盖动态链接进程"。

---

## 7. 宿主侧改造（`src/sandbox/sandbox-manager.ts`）

| 改造点 | 说明 |
|---|---|
| `initialize()` | 若配置含 `deleteAsk`：解析目录（rg 展开，Linux）、启动 macOS ask-server（`startMacAskServer`）、把目录清单/ask socket env 传入平台封装函数 |
| `wrapWithSandbox()` / `wrapWithSandboxArgv()` | 新增透传参数 `askDeleteDirs`、`askSocketPath`（若有） |
| `filterNetworkRequest`（L356-375） | ask 调用适配新 `SandboxAskRequest` 签名 |
| 新增 `handleFileDeleteAsk(req)` | 目录判定（dev/ino+path，宿主侧可信逻辑）→ `sandboxAskCallback` → 返回 verdict；记录决策（允许/拒绝/超时）到 `SandboxViolationStore` |
| `reset()` / 退出钩子 | 调用 `linuxMonitor.rejectAll()` / `macAskServer.rejectAll()`；清空 deleteAsk 状态 |
| `SandboxViolationStore` | 新增 violation 类型 `file-delete-ask-denied` / `file-delete-ask-timeout`（复用现有 `addViolation` 通道与 stderr 标注） |

---

## 8. 改造点清单

| 文件 | 现有代码 | 改动 |
|---|---|---|
| `src/sandbox/sandbox-config.ts` | `SandboxFilesystemConfig` | +`deleteAsk` / `deleteAskTimeoutMs` / `deleteAskRename`（zod + 类型） |
| `src/sandbox/sandbox-schemas.ts` | `SandboxAskCallback`（L103-106） | 泛化为 `SandboxAskRequest`；新增 `AskFrame` 类型 |
| `src/sandbox/sandbox-manager.ts` | `filterNetworkRequest` ask 段（L356-375）；`resolveFilesystemRestrictions`（L1239 附近 glob）；`initialize`；`wrapWithSandbox`（L1544+）；`reset()` | ask 签名适配；`deleteAsk` 解析；`handleFileDeleteAsk`；ask-server 生命周期；violation 记录 |
| `src/sandbox/linux-sandbox-utils.ts` | `wrapCommandWithSandboxLinux`（L1686+）；observe socket 注入（L1784-1801） | 透传 `deleteAsk`/ask 通道；无新增 bwrap 结构 |
| `src/sandbox/linux-violation-monitor.ts` | `startLinuxSandboxViolationMonitor`；`handleEvent`（L94）；首行 encodedCommand（L159-163） | 升级双向请求-响应；`onAskDelete` 回调；`rejectAll()` |
| `vendor/seccomp-src/apply-seccomp.c` | `install_observe_filter`（L322）；`supervise`（L516-549）；socketpair（L680）；read_path/process_vm_readv（L384） | 决策模式 BPF（挂起集合）；supervise 决策循环 + pending 表 + poll；`bye`/reject 结算；CLI 新选项 |
| `src/sandbox/macos-sandbox-utils.ts` | `wrapCommandWithSandboxMacOS`（L995+）；`generateReadDenyUnlinkRules`（L331-389） | +`DYLD_INSERT_LIBRARIES` 注入 interposer 与 env；denyWrite 清单注入 |
| `vendor/fileops-interposer/`（新增） | — | dylib：unlink/unlinkat/rmdir/rename* 包装 + ask 客户端 |
| `vendor/seccomp/build.ts`（`vendor/seccomp/build.ts`） | 现有构建脚本 | 新增可选构建目标（决策模式为编译期开关 `-DASK_DELETE=1`，避免常开导致性能回归） |
| `src/sandbox/sandbox-violation-store.ts` | 现有 `addViolation` | +新 violation 类型 |
| 测试：`tests/` | 现有 linux/macos 沙箱测试 | 删除询问 E2E（挂起→确认→继续 / 拒绝→EPERM / 超时→deny / 非目标目录→无感直通） |

---

## 9. 安全分析与边界

1. **路径不可信（Linux 核心风险）**：USER_NOTIF 拿到的路径来自被冻结进程内存（`process_vm_readv`），攻击者可伪造。
   - 缓解：主判据用内核可信的 `dirfd` 的 dev/ino + `req` 自身参数；路径串仅作展示与辅助匹配；**"拒绝"决策只信任"命中 denyWrite 的硬边界"**，deleteAsk 的拒绝仅是 UX 层。
   - 残余风险：攻击者可伪造 path 骗取"确认框"（诱导用户误放行）。缓解：确认框展示 `resolvedCommand` + 归因进程名，提示"此路径请求来自沙箱进程，仅供参考"。
2. **挂起死锁**：挂起的进程不可被 kill？—— USER_NOTIF 挂起时进程仍可被信号终止（seccomp 不拦截信号）；但长时间无决策会 hang 工作负载。缓解：宿主 30s 超时兜底 + 连接 EOF 全部拒绝。
3. **拒绝结算原子性**：`NOTIF_SEND(EPERM)` 与进程退出竞争：先广播 `reject-all` 再关闭 socket，supervise 侧先处理完 pending 再退出。
4. **macOS interposer 递归**：真实执行必须走 `syscall(SYS_...)` 直通，禁止调用同名 libc 符号。
5. **性能**：决策模式默认关闭；开启后仅挂起集合内的 syscall 有 USER_NOTIF 开销（与现状观察过滤器相当），目录命中前的本地判定是纯用户态。
6. **覆盖声明**：macOS 不覆盖静态链接/直接 syscall 二进制；该场景降级为 deny（或明确文档声明不受保护）。

---

## 10. 测试计划

| 用例 | 平台 | 期望 |
|---|---|---|
| 删除 `deleteAsk` 目录内文件，用户允许 | L/M | 删除成功，进程无感知 |
| 删除 `deleteAsk` 目录内文件，用户拒绝 | L/M | 进程收到 EPERM（`OSError: [Errno 1]`），Store 记录 |
| 删除非目标目录文件 | L/M | 无询问，直通（性能/行为零影响） |
| 决策超时（20s） | L/M | 默认拒绝，进程收到 EPERM，记录 `-ask-timeout` |
| 宿主进程在决策中退出 | L/M | 全部挂起请求拒绝结算，沙箱内无 hang |
| rename 覆盖目标在 deleteAsk 内 | L/M | 询问（`deleteAskRename` 开）；否则直通 |
| `deleteAsk` 同时命中 `denyWrite` | L/M | 直接 EPERM，不询问 |
| Linux：攻击者构造伪造路径 | L | 校验失败路径不进入确认；仅 denyWrite 硬边界生效 |
| macOS：静态链接二进制删除 | M | 按降级策略（deny 或文档声明） |
| 回归：现有 denyWrite/allowWrite/违规监控全量 | L/M | 行为不变 |

---

## 11. 实施顺序建议

1. **协议层先行**：`AskFrame` 类型 + Linux 线协议（可先在 linux-violation-monitor 与 apply-seccomp 之间用测试桩打通）。
2. **Linux 决策模式**：apply-seccomp 决策 BPF → supervise 决策循环 → monitor 双向化 → SandboxManager 回调桥。
3. **配置与回调泛化**：schema + `SandboxAskRequest`，网络 ask 适配。
4. **macOS interposer**：dylib 挂钩 → ask 客户端 → 宿主 ask-server → 与 denyWrite 协作。
5. **全量测试 + 安全评审**（重点：路径不可信缓解与挂起结算）。
