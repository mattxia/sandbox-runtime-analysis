# Linux 沙箱安全机制分析

> 分析对象：`src/sandbox/linux-sandbox-utils.ts`（外层 bwrap 封装）、`vendor/seccomp-src/apply-seccomp.c`（内层 seccomp supervisor）、`vendor/seccomp-src/seccomp-unix-block.c`（BPF 过滤器生成）、`src/sandbox/linux-violation-monitor.ts`（violation 观察）。
>
> 本文档另附《bwrap 与 seccomp 能力对比》章节（见文末）。

## 一、总体设计

Linux 沙箱采用**两段式**架构：外层由 **bubblewrap (bwrap)** 建立"静态边界"（网络 / PID / 用户 / 挂载命名空间 + bind mounts），内层由自研 **apply-seccomp**（静态编译的 C supervisor）建立"动态强制"（嵌套命名空间 + seccomp-BPF 过滤器）。

两段式设计的核心动机：bwrap 与 seccomp 不能同层共存——网络桥接进程 socat 必须先启动，而它需要 `socket(AF_UNIX)` 创建 Unix socket，同层的 seccomp 过滤器会把它自己也杀死。因此先起 bwrap + socat，再让 apply-seccomp 在更深的嵌套命名空间中、仅对用户命令施加 seccomp。

## 二、分层架构图

```
┌────────────────────────────────────────────────────────────────────────┐
│ L4 宿主应用层 (Bun/Node.js, sandbox-manager.ts)                          │
│   · 依赖检查 checkLinuxDependencies()  · 网络桥初始化 initializeLinuxNetworkBridge()
│   · 策略翻译: readConfig/writeConfig → bwrap 参数 → wrapCommandWithSandboxLinux()
│   · violation 消费: linux-violation-monitor.ts (net.Server 监听 SRT_OBSERVE_SOCK)
├────────────────────────────────────────────────────────────────────────┤
│ L3 外层容器: bubblewrap (bwrap) —— 一次性的进程启动隔离                    │
│   · --unshare-net    网络命名空间（默认全断网）                            │
│   · --unshare-pid    PID 命名空间 + --proc /proc（新鲜 /proc）             │
│   · --unshare-user   用户命名空间 + --cap-drop ALL（强制降权）             │
│   · --ro-bind / --bind / --tmpfs / --dev /dev   文件系统边界              │
│   · --new-session --die-with-parent   生命周期兜底                         │
├────────────────────────────────────────────────────────────────────────┤
│ L2 桥接层: socat (宿主侧 + 沙箱内) —— 唯一合法网络通道                      │
│   · 宿主侧:  UNIX-LISTEN:claude-http-<id>.sock ↔ TCP:localhost:3128(宿主代理)
│   · 沙箱内:  TCP-LISTEN:3128/1080 ↔ UNIX-CONNECT:<bind 进来的 sock>        │
├────────────────────────────────────────────────────────────────────────┤
│ L1 内层: apply-seccomp (vendor/seccomp-src, 静态编译 C supervisor)         │
│   · 嵌套 user ns → CAP_SYS_ADMIN → unshare(CLONE_NEWPID|CLONE_NEWNS)     │
│   · inner init = 嵌套 PID ns 的 PID 1（PR_SET_DUMPABLE=0, 重挂 /proc,     │
│     PR_CAP_AMBIENT_CLEAR_ALL, 信号转发, reaper）                          │
│   · worker: PR_SET_NO_NEW_PRIVS → 观察过滤器(NEW_LISTENER/USER_NOTIF)     │
│     → 主过滤器 prctl(PR_SET_SECCOMP, unix_block_bpf) → execvp             │
├────────────────────────────────────────────────────────────────────────┤
│ L0 用户命令 (Python/Node/Shell)，运行在嵌套 PID ns 的 PID 2                │
└────────────────────────────────────────────────────────────────────────┘
```

### apply-seccomp 内的进程布局

```
bwrap init (PID 1)           <- 外层 PID ns，无 seccomp
  \_ bash / socat ...        <- 外层 PID ns，无 seccomp（socat 可创建 Unix socket）
     \_ apply-seccomp [outer]<- 外层 PID ns，信号转发 + 观察通道 supervisor
        ====================== PID ns 边界 ======================
        \_ apply-seccomp [inner init]  <- 嵌套 PID 1，PR_SET_DUMPABLE=0
           \_ user command             <- 嵌套 PID 2，seccomp 已生效
```

从用户命令视角看，`/proc` 中只有自己的进程树；bwrap init、bash 包装、socat 均不可寻址，无法 ptrace 或经 `/proc/N/mem` 篡改。

## 三、关键组件与调用关系

### 1. 一条命令的完整调用链

```
sandbox-manager.ts
  └─ wrapCommandWithSandboxLinux()            # 组装 bwrap argv
       ├─ checkLinuxDependencies()            # 校验 bwrap/socat/rg/apply-seccomp
       ├─ generateFilesystemArgs()            # 生成 bind mount 参数
       ├─ resolveApplySeccompPrefix()         # 解析 apply-seccomp 调用前缀
       └─ quote([bwrap, --new-session, --die-with-parent,
                 --unsetenv/--setenv, --unshare-net,
                 --bind httpSocketPath, --setenv HTTP_PROXY=…,   # 3128
                 <fs args>, --dev /dev, --unshare-pid,
                 --unshare-user --cap-drop ALL --proc /proc,
                 --, bash, -c, <script>])

bash -c <script>                             # 沙箱内执行的脚本
  ├─ socat TCP-LISTEN:3128 … UNIX-CONNECT:<sock> &   # buildSandboxCommand()
  ├─ socat TCP-LISTEN:1080 … UNIX-CONNECT:<sock> &
  └─ apply-seccomp bash -c <user command>    # seccomp 在 socat 之后生效

apply-seccomp (main)
  ├─ unshare(CLONE_NEWUSER) + 写 /proc/self/{setgroups,uid_map,gid_map}  # 取 CAP_SYS_ADMIN
  ├─ unshare(CLONE_NEWPID|CLONE_NEWNS)
  ├─ fork()
  │   ├─ [outer stub]  signal 转发 → 收 listener fd(SCM_RIGHTS) → poll notify fd
  │   │                → process_vm_readv 读路径 → ioctl NOTIF_SEND(CONTINUE)
  │   │                → pidfd_open() 等子进程退出 → 透传退出码
  │   └─ [inner init/PID 1] PR_SET_DUMPABLE=0 → mount(MS_PRIVATE) → 重挂 /proc
  │                        → PR_CAP_AMBIENT_CLEAR_ALL → fork worker → reap_until()
  │       └─ [worker/PID 2] PR_SET_NO_NEW_PRIVS
  │                         → install_observe_filter()   # NEW_LISTENER 观察过滤器
  │                         → prctl(PR_SET_SECCOMP, unix_block_bpf)
  │                         → execvp(user command)
```

### 2. 组件职责

| 组件 | 文件 | 职责 |
|---|---|---|
| 策略翻译器 | `src/sandbox/linux-sandbox-utils.ts` | read/write 配置 → bwrap bind 参数；环境变量、git safe.directory、proxy env 注入 |
| bwrap | 外部工具（bubblewrap） | 外层命名空间与文件系统边界 |
| socat | 外部工具 | 宿主↔沙箱 socket 桥接（HTTP 3128 / SOCKS 1080） |
| apply-seccomp | `vendor/seccomp-src/apply-seccomp.c` | 嵌套命名空间、双重 seccomp 过滤器、信号转发、观察通道 |
| BPF 过滤器 | `vendor/seccomp-src/seccomp-unix-block.c` + `unix-block-bpf.h` | 编译期生成/内嵌的 BPF，阻断 `socket(AF_UNIX)` 与 io_uring |
| 观察管道 | `src/sandbox/linux-violation-monitor.ts` | 消费 `SRT_OBSERVE_SOCK` 上的 JSON 事件，记录写意图 syscall |
| 资源清理 | `cleanupBwrapMountPoints()` | 引用计数保护（`activeSandboxCount`），延迟删除 bwrap 为不存在 deny 路径创建的挂载点文件 |

### 3. 关键代码位置

- bwrap 参数组装（完整序列）：`wrapCommandWithSandboxLinux()`，`linux-sandbox-utils.ts`
- 沙箱内脚本（socat + apply-seccomp 编排）：`buildSandboxCommand()`
- 文件系统 bind mount 生成：`generateFilesystemArgs()`（含 denyRead tmpfs 重应用、denyWrite 暴露修复、/dev/null 桩、`bwrapMountPoints` 追踪）
- apply-seccomp 主流程与嵌套命名空间：`apply-seccomp.c main()` / `install_observe_filter()` / `supervise()`
- 观察 syscall 表（单点定义，BPF 与 C 侧共用避免漂移）：`observe_calls[]`

## 四、实现的安全机制

1. **网络隔离（全或无 + 代理白名单）**：`--unshare-net` 清空所有网络接口；只有经 socat 桥接到宿主代理的流量可行，域过滤在宿主代理层完成。
2. **文件系统边界（bind mount 组合拳）**：`--ro-bind / /`（写限制时只读根）→ `--bind` 允许写路径 → `--tmpfs`/`--ro-bind /dev/null` 覆盖拒绝读的目录/文件 → `--ro-bind` 重建 allowRead 覆盖。含 symlink 解析（`resolveSymlinkDenyDest`）与嵌套覆盖重排（denyWrite 暴露 denyRead 时重应用）。
3. **强制拒绝路径（ripgrep 扫描）**：`mandatoryDenySearchDepth`（默认 3 层）内用 `rg` 扫描允许写路径下的危险文件（凭据点文件等）；对不存在的路径用 `/dev/null` 桩 + 空文件挂载点实现"创建即拒绝"，并追踪到 `bwrapMountPoints` 清理（防 ghost 文件）。路径解析细节：`resolveSymlinkedDenyPath` 将 symlink 形式的 deny 路径解析到真实目标；`findFirstNonExistentComponent` 求不存在路径的"最深已存在祖先"作为挂载点落点；`hasFileAncestor` 判断祖先链中是否存在文件组件（决定挂载点用文件还是目录）。
4. **进程可见性隔离**：双重 PID 命名空间。用户命令（嵌套 ns 的 PID 2）的 `/proc` 里只有自己的进程树，bwrap/bash/socat/outer stub 全部不可寻址；inner init 设 `PR_SET_DUMPABLE=0`。
5. **能力降级**：bwrap 层 `--unshare-user + --cap-drop ALL`（防止 EUID=0 时残留 CAP_SYS_ADMIN 重挂只读根）；apply-seccomp 内层建完嵌套命名空间后 `PR_CAP_AMBIENT_CLEAR_ALL`，配合 `PR_SET_NO_NEW_PRIVS` 使 worker exec 后归零。
6. **seccomp-BPF Unix socket 阻断**：主过滤器对 `socket(AF_UNIX)` 返回 EPERM，并封堵 `io_uring_setup/enter/register`（防 `IORING_OP_SOCKET` 绕过）。`allowAllUnixSockets: true` 可整体禁用。
7. **写意图观察/审计（fail-open）**：第二道 USER_NOTIF 过滤器捕获 openat/unlinkat/mkdirat/renameat* 等写意图 syscall → outer stub 用 `process_vm_readv` 读取攻击者内存中的路径 → 经 socketpair 与 `SRT_OBSERVE_SOCK` 上报 JSON 行。**只观测、不强制**，一律回 `SECCOMP_USER_NOTIF_FLAG_CONTINUE`。
8. **凭据掩蔽与环境限制**：`maskedFileBinds` 用假文件只读绑定替换真实凭据；`--unsetenv/--setenv` 删改环境变量；git `safe.directory` 处理（userns 下 owner 未映射导致的 dubious ownership）。
9. **生命周期兜底**：`--die-with-parent` + `--new-session`；apply-seccomp 三层逐级转发 TERM/INT/HUP/QUIT/USR1/USR2；inner init 作为 PID 1 reaper，退出即由内核拆毁整个命名空间。

## 五、依赖的 Linux 内核模块 / 机制

| 类别 | 具体机制 | 用途 |
|---|---|---|
| Namespaces | `CLONE_NEWUSER` / `CLONE_NEWPID` / `CLONE_NEWNS` / `CLONE_NEWNET` | 用户/PID/挂载/网络命名空间隔离（bwrap 与 apply-seccomp 各一层） |
| Seccomp | `SECCOMP_SET_MODE_FILTER`、`SECCOMP_FILTER_FLAG_NEW_LISTENER`（≥5.0）、`SECCOMP_RET_USER_NOTIF`、`SECCOMP_USER_NOTIF_FLAG_CONTINUE`（≥5.5）、`SECCOMP_GET_NOTIF_SIZES` | 主过滤器阻 socket；观察过滤器上报写意图 |
| prctl | `PR_SET_NO_NEW_PRIVS`、`PR_SET_DUMPABLE`、`PR_CAP_AMBIENT_CLEAR_ALL`、`PR_GET_DUMPABLE` | 防提权、防 ptrace、降权 |
| /proc 伪文件 | `setgroups`、`uid_map`、`gid_map`；`/proc/<pid>/cwd`、`/proc/<pid>/fd/<n>` magic symlink | userns 映射；观察通道相对路径解析 |
| 进程间读取 | `process_vm_readv` | 读被冻结进程内存中的路径参数（观察通道） |
| fd 传递 | `SCM_RIGHTS` over socketpair | worker → outer stub 传 listener fd |
| 进程监控 | `pidfd_open`（≥4.17） | 避免 pid 复用，配合 poll 等子进程退出 |
| 其他 syscall | `unshare(2)`、`mount(2)`（MS_PRIVATE + proc 重挂）、`readlinkat`（O_PATH /proc 句柄）、`waitid(WNOWAIT)`、信号转发 | 命名空间建立、/proc 遮蔽、路径解析、进程管理 |
| 外部工具 | **bwrap**、**socat**、**ripgrep** | 容器化、网络桥接、deny 扫描 |
| 内核前提 | **unprivileged user namespaces 必须可用且带能力**（Ubuntu 24.04 默认 `kernel.apparmor_restrict_unprivileged_userns=1` 会剥离新 ns 的能力，需 `sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`） | 整个沙箱的根基 |

## 六、安全边界与已知限制

- **观察通道不实施策略**：路径来自攻击者可篡改的内存，带竞态（capture 后 exec 前可改写），官方声明"仅为诊断提示，绝不用于门控策略"；整个通道 fail-open，坏掉只会丢日志。
- **seccomp 只阻"创建"**：不拦截已继承 Unix socket fd 上的 bind/connect/sendto，也不阻止 SCM_RIGHTS 传 fd；仅阻断创建通常已够用。
- **网络隔离是全或无**：域白名单过滤依赖宿主代理实现，沙箱边界不感知域名。
- **无 LSM 加固**：未声明 AppArmor/SELinux profile 防护；隔离完全依赖 kernel namespaces + seccomp。
- **与 macOS 的差异**：Linux 端目前没有 macOS fsApproval 那样的"读/写/删逐操作用户审批"（DYLD interposer + Seatbelt），只有静态 bwrap 边界 + seccomp + 被动观察；`allowUnixSockets` 在 Linux 上不是路径级而是全有/全无（seccomp 无法读用户内存路径）。
- **架构覆盖**：apply-seccomp 仅发布 x64/arm64 预编译静态二进制，其他架构需 `allowAllUnixSockets: true` 退化为无 seccomp。

---

## 七、bwrap 与 seccomp 能力对比

两者解决的是不同维度的安全问题，是互补关系。

### bwrap（bubblewrap）—— 空间隔离 / 资源边界

基于 Linux **命名空间 + 挂载**机制，约束"进程能看到、够到什么"：

- **用户命名空间**（`--unshare-user`）：改变进程的 uid/gid 视角与能力集合（配合 `--cap-drop ALL` 降权）
- **PID 命名空间**（`--unshare-pid` + `--proc /proc`）：只能看到自己进程树内的进程，防 ptrace 宿主进程、防读宿主 `/proc` 泄露信息
- **网络命名空间**（`--unshare-net`）：剥离所有网络接口，默认全断网
- **挂载命名空间 + bind mounts**（`--ro-bind` / `--bind` / `--tmpfs` / `/dev/null`）：重写文件系统视图——把根变成只读、只对指定路径放写、用 tmpfs 抹掉拒绝读的目录、用 /dev/null 掩盖敏感文件

**本质**：不审查"操作"，只是把世界的一部分（文件、进程、网络）从进程眼前移走。属于**静态边界**——建好之后内核直接按挂载表/命名空间裁决，性能开销极小。

### seccomp（BPF 过滤器）—— 系统调用门控

基于内核 seccomp 机制，约束"进程能执行什么操作"。本项目用它做两件事：

1. **主过滤器**（`unix_block_bpf`）：阻断 `socket(AF_UNIX, …)`（返回 EPERM）+ 整个 io_uring 接口。这是 bwrap 做不到的——**网络命名空间只管 TCP/UDP 流量，管不了 AF_UNIX 本地 IPC**，沙箱内进程仍然可以 `socket(AF_UNIX)` 建本地 socket 或与宿主已注入的 fd 交互，seccomp 从 syscall 层面把这个洞堵上。
2. **观察过滤器**（`SECCOMP_RET_USER_NOTIF`）：捕获 openat/unlinkat/mkdirat/renameat 等写意图 syscall，通知到 supervisor 做审计记录——只观测不拦截。

**本质**：在 syscall 入口做策略裁决，属于**动态强制**——它能针对"参数"（如 `args[0] == AF_UNIX`）做判断，粒度到单次系统调用。

### 对比表

| 维度 | bwrap | seccomp |
|---|---|---|
| 机制 | namespaces + mount | 内核 syscall 过滤器（BPF） |
| 约束对象 | 资源可见性（路径/进程/网络） | 操作本身（系统调用） |
| 粒度 | 路径级、命名空间级 | 单次 syscall + 参数 |
| 典型缺口 | 管不了 AF_UNIX socket、管不了 syscall 滥用 | 不改变资源视图 |
| 二者关系 | 静态边界（主要防线） | 动态门控（补 bwrap 表达不了的规则） |

---

## 八、关键配置项与实现细节补充

### 8.1 Linux 沙箱配置项清单

| 配置项 | 含义 | 说明 |
|---|---|---|
| `bwrapPath` / `socatPath` | 显式指定 bwrap / socat 二进制路径 | 设置后依赖检查直接校验该路径而非查 PATH |
| `seccompConfig.applyPath` | apply-seccomp 二进制路径 | 不设置时按架构查预编译包内二进制（x64/arm64） |
| `seccompConfig.argv0` | ARGV0 多路由模式 | 当 apply-seccomp 被编译进宿主二进制时，通过 `ARGV0=<argv0>` 环境变量分派调用（applyPath 不做存在性检查，由调用方保证在 bwrap 命名空间内可解析） |
| `allowAllUnixSockets` | 禁用 seccomp Unix socket 阻断 | `true` 时跳过 apply-seccomp（架构不支持的降级通道） |
| `enableWeakerNestedSandbox` | 弱嵌套沙箱模式 | `true` 时不加 `--proc`，改用 `--bind /proc /proc`——适配无特权 Docker（EUID=0 无 CAP_SYS_ADMIN）且内层无法重挂 /proc 的环境；`false`（默认）为安全模式 `--unshare-user --cap-drop ALL --proc /proc` |
| `mandatoryDenySearchDepth` | 强制拒绝路径的 ripgrep 扫描深度 | 默认 3 层，防深度目录扫描的性能问题 |
| `observeSocketPath` | violation 观察 socket 路径 | 存在时注入 `SRT_OBSERVE_SOCK` / `SRT_ENCODED_CMD`，启用 USER_NOTIF 观察通道 |
| `ripgrepConfig` | ripgrep 二进制与参数 | 默认 `rg` |
| `maskedFileBinds` / `maskedFileStoreDir` | 凭据假文件映射及其存储目录 | 存储目录最终以 `--ro-bind` 覆盖，保证沙箱内不可写（防假文件被替换/符号链接劫持） |
| `needsNetworkRestriction` / `httpSocketPath` / `socksSocketPath` | 网络限制与代理桥接 socket | 未提供 socket 时 `--unshare-net` 全断网 |

### 8.2 实现细节补充

- **嵌套 userns 前的 dumpable 翻转**：若 apply-seccomp 以无读权限模式（如 0111）exec，内核会标记进程 non-dumpable，导致 `/proc/self/{setgroups,uid_map,gid_map}` 归 root 所有、写入 EACCES。apply-seccomp 在映射前 `PR_GET_DUMPABLE` 保存、`PR_SET_DUMPABLE=1` 临时打开，映射完成后恢复（保存值非 1 时恢复为更保守的 0）。存在与 runc/systemd 相同的"几 syscall 窗口内可被同 uid ptrace"的已知取舍。
- **观察过滤器的 x32 防护**：x86_64 下 BPF 先校验 `arch == AUDIT_ARCH_X86_64`，再对 `nr >= 0x40000000`（x32 ABI）直接 ALLOW，防止通过 x32 位号绕过 syscall 匹配；aarch64 无 x32 分支。
- **内核版本探测**：观察过滤器用 `SECCOMP_FILTER_FLAG_TSYNC_ESRCH` 的 NULL-prog 探测（EFAULT=已知、EINVAL=内核过旧）判断 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 是否可用（≥5.5），不可用则整条观察通道 fail-open 跳过。
