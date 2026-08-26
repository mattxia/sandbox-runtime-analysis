# Sandbox Runtime（@anthropic-ai/sandbox-runtime）组件级架构分析

> 分析对象：`d:\prj\anthropic\sandbox-runtime-analysis`（CLI 名 `srt`，版本 0.0.73）
> 概述：通用进程沙箱运行时，以 Node/TypeScript 实现，支持 Linux / macOS / Windows 三平台。
> 运行时要求：Node ≥ 20.11 或 Bun（测试框架使用 bun test）。

## 一、总体分层架构

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 1. 接入层 (Entry)                                                        │
│   cli.ts (commander: run / windows-install / windows-uninstall)         │
│   index.ts (公开库 API 导出)                                             │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ initialize / wrapWithSandbox(Argv) / updateConfig / reset
┌──────────────────────────────▼──────────────────────────────────────────┐
│ 2. 编排层 (Orchestration) — SandboxManager (单例门面, 宿主侧运行)         │
│   • 生命周期: initialize / updateConfig / reset / cleanupAfterCommand   │
│   • 策略解析: getFsReadConfig / getFsWriteConfig / getCredentialRestrictions│
│   • 会话状态: proxyAuthToken / parentProxy / mitmCA / windowsFsStampedSet│
│   • 附属存储: SandboxViolationStore  SentinelRegistry  AwsPairRegistry  │
│               MaskedFileStore (进程内, reset 时清空)                     │
└──┬──────────┬──────────────┬──────────────────┬─────────────────────────┘
   │ 配置读取  │ 凭据构建     │ 启动代理          │ 分发平台封装
┌──▼───────┐ ┌▼──────────┐ ┌▼──────────────────┐ ┌▼──────────────────────┐
│3.配置层   │ │4.凭据策略层│ │5.网络代理层        │ │6.平台适配层(沙箱执行引擎)│
│sandbox-  │ │credential-│ │ mux-proxy(单端口)  │ │ linux-sandbox-utils   │
│config.ts │ │sentinel   │ │  ├─ http-proxy     │ │  (bwrap+socat)        │
│(zod)     │ │mask-env   │ │  ├─ socks-proxy    │ │ macos-sandbox-utils   │
│schemas.ts│ │mask-files │ │  ├─ parent-proxy   │ │  (sandbox-exec/SBPL)  │
│config-   │ │extract    │ │  ├─ tls-terminate  │ │ windows-sandbox-utils │
│loader.ts │ │decode     │ │  ├─ mitm-ca/leaf   │ │  (srt-win.exe 封装)    │
│domain-   │ │aws-pairs  │ │  ├─ request-filter │ │ linux-violation-      │
│pattern.ts│ │           │ │  ├─ body-subst     │ │ monitor               │
│          │ │           │ │  ├─ aws-sigv4      │ │ generate-seccomp-     │
│          │ │           │ │  └─ listen-in-range│ │ filter (apply-seccomp)│
│          │ │           │ │                    │ │ java-proxy-agent      │
└──────────┘ └───────────┘ └────────────────────┘ └──────────┬────────────┘
                                                            │
┌──────────────────────────────┬─────────────────────────────▼──────────┐
│ 7. 通用工具层 (Utils)                                                  │
│ sandbox-utils (路径/代理env/编解码)  platform  debug  which  ripgrep   │
│ shell-quote                                                            │
└──────────────────────────────┬─────────────────────────────────────────┘
┌──────────────────────────────▼─────────────────────────────────────────┐
│ 8. 系统依赖层 (OS + 外部二进制/组件)                                     │
│ Linux:  bwrap · socat · rg · apply-seccomp(C, vendored) · bash         │
│ macOS:  /usr/bin/sandbox-exec · /usr/bin/log stream · env · bash       │
│ Windows: srt-win.exe (Rust, vendored) · UAC · WFP · 沙箱用户账户        │
│ 跨平台: srt-proxy-agent.jar (Java javaagent) · node-forge · socks5-server│
└─────────────────────────────────────────────────────────────────────────┘
```

### 各层职责说明

| 层 | 组件 | 职责 |
|---|---|---|
| 1. 接入层 | `src/cli.ts`、`src/index.ts` | CLI 入口（command 解析、配置文件加载、控制 fd 热更新）与库 API 导出面 |
| 2. 编排层 | `src/sandbox/sandbox-manager.ts` | 全局单例门面，串联配置→策略→代理→平台封装，持有会话级状态 |
| 3. 配置层 | `sandbox-config.ts`(zod 校验)、`sandbox-schemas.ts`、`utils/config-loader.ts`、`domain-pattern.ts` | 配置模型、校验、文件/字符串加载、域名模式匹配与校验（供运行时与校验共用） |
| 4. 凭据策略层 | `credential-sentinel/mask-env/mask-files/extract/decode/aws-pairs.ts` | 环境变量/文件凭据掩码（sentinel 注册表、JWT decode、extract 抽取、AWS SigV4 凭据配对） |
| 5. 网络代理层 | `mux-proxy/http-proxy/socks-proxy/parent-proxy/tls-terminate-proxy/mitm-ca/mitm-leaf/request-filter/body-substitution/aws-sigv4/listen-in-range.ts` | 单端口代理前端、请求过滤、TLS 终结/MITM、凭据替换、SigV4 重签、父代理链 |
| 6. 平台适配层 | `linux/macos/windows-sandbox-utils.ts`、`linux-violation-monitor.ts`、`generate-seccomp-filter.ts`、`java-proxy-agent.ts` | 生成平台沙箱执行命令（bwrap / seatbelt / srt-win），违规监控、seccomp 二进制定位、JVM 代理注入 |
| 7. 通用工具层 | `sandbox-utils.ts`、`utils/platform.ts/debug.ts/which.ts/ripgrep.ts/shell-quote.ts` | 路径规范化、代理环境变量生成、平台识别、调试日志、外部命令定位与执行、POSIX 引号 |
| 8. 系统依赖层 | OS 内核机制 + vendored 二进制 | 见「对 OS 的具体依赖」章节 |

## 二、关键调用关系

### 1. 主流程（沙箱化执行一条命令）

```
cli.ts ──> SandboxManager.initialize(config)
             ├─ resolveParentProxy(config.network.parentProxy)
             ├─ checkDependenciesAsync() → 平台依赖检查
             ├─ [win] srt-win user status / wfp verify / acl stamp+grant / CA 信任
             ├─ startMuxProxyServer()
             │    ├─ createHttpProxyServer({filter: filterNetworkRequest, mitmCA,
             │    │    shouldTerminateTLS, filterRequest, mutateHeaders, planSigv4, parentProxy})
             │    ├─ createSocksProxyServer({filter, parentProxy, probeUnauthenticated})
             │    └─ createMuxProxyServer({httpServer, handleSocksConnection})
             ├─ [linux] initializeLinuxNetworkBridge() → socat UNIX→TCP 桥
             └─ 注册 exit/SIGINT/SIGTERM → reset()

cli.ts ──> SandboxManager.wrapWithSandbox(command)      (macOS/Linux)
             ├─ getCredentialRestrictions() → SentinelRegistry / AwsPairRegistry / MaskedFileStore
             ├─ getFsReadConfig / getFsWriteConfig (union 凭据 denyRead、展开 glob)
             └─ linux/macos-sandbox-utils.wrapCommandWithSandbox*(...) → 生成 shell 命令串
cli.ts ──> SandboxManager.wrapWithSandboxArgv(command)  (Windows)
             └─ windows-sandbox-utils.wrapCommandWithSandboxWindows() → {argv, env} → spawn(shell:false)

子进程退出 ──> cleanupAfterCommand() → cleanupBwrapMountPoints()
```

### 2. 网络请求过滤流水线（HTTP CONNECT / HTTPS）

```
沙箱内进程 →(HTTP_PROXY=localhost:3128 / mux 端口)→ mux-proxy(首字节分流)
    ├─ HTTP 分支 → http-proxy → filterNetworkRequest(host:port 白/黑名单)
    │                  ├─ 通过 → [tlsTerminate? tls-terminate-proxy(peek ClientHello→mitm-leaf 签叶)
    │                  │         → request-filter.filterRequest → body-substitution 换凭据
    │                  │         → aws-sigv4 重签 (credential-aws-pairs) → 上游]
    │                  ├─ mitmProxy? → 转发外部 MITM unix socket
    │                  └─ 拒绝 → 403 + recordProxyViolation → SandboxViolationStore
    └─ SOCKS 分支 → socks-proxy(@pondwader/socks5-server) → 同上 filter → 直连/父代理
上游：parent-proxy.resolveParentProxy/dialDirect/openConnectTunnel (HTTP_PROXY/NO_PROXY)
```

### 3. 违规监控（三类生产者 → 统一 Store）

```
macOS:  /usr/bin/log stream ← seatbelt deny 事件(带 CMD64_ 标签)
Linux:  linux-violation-monitor (unix socket) ← apply-seccomp USER_NOTIF 写意图事件
代理侧: recordProxyViolation (网络 deny) ── 三者统一进入
        SandboxViolationStore(内存, 100条) → annotateStderrWithSandboxFailures()
```

### 4. 凭据掩码流

```
credential-mask-env/files → 读真实值 → credential-extract(正则捕获) / credential-decode(JWT)
    → SentinelRegistry 注册 sentinel(fake_value_uuid) → 沙箱内注入假值
    → 代理侧 substituteInHeaders / body-substitution 还原真值
    → credential-aws-pairs + aws-sigv4 对 SigV4 请求用真密钥重签
```

### 5. 组件依赖要点

- 被引用最广的模块：`parent-proxy.ts`（代理链/规范化/直连）与 `sandbox-utils.ts`（路径/env/编解码）。
- `request-filter.ts` → `body-substitution.ts` → `mitm-*.ts` → `credential-*.ts` 构成「过滤→替换→重签」流水线。
- `credential-sentinel.ts` ↔ `body-substitution.ts`、`mitm-ca.ts` ↔ `mitm-leaf.ts` 存在类型级循环引用（通过 `import type` 安全处理）。
- 跨模块公共底座：`utils/platform.ts`、`utils/debug.ts`、`sandbox-config.ts`、`macos-sandbox-utils.ts`（违规事件类型）。
- `child_process` 使用点仅三处：`utils/ripgrep.ts`(spawn)、`utils/which.ts`(spawnSync)、`generate-seccomp-filter.ts`(execSync `npm root -g`)；代理与凭据核心组件为纯 Node 流/网络实现。

## 三、对 OS 的具体依赖

| 依赖 | Linux | macOS | Windows | 用途 |
|---|---|---|---|---|
| **bwrap** (bubblewrap) | ✅ 必需 | — | — | `--unshare-net/pid/user` 命名空间、`--ro-bind/--tmpfs/--dev` 文件系统隔离、`--cap-drop ALL` |
| **socat** | ✅ 必需 | — | — | UNIX socket↔TCP 桥（宿主侧 2 进程 + 沙箱内 3128/1080 监听），DNS 隧道 |
| **rg** (ripgrep) | ✅ 必需 | — | — | 展开 denyRead/allowRead glob → bwrap 具体路径；只读 deny 依赖（`whichSync`/`spawn`） |
| **apply-seccomp** (vendor C) | ✅ 可选 | — | — | 嵌套 PID/user/mount 命名空间 + seccomp-BPF 阻断 `socket(AF_UNIX)`；要求非特权 userns（Ubuntu 24.04 需关 AppArmor 限制）；x64/arm64 |
| **`/usr/bin/sandbox-exec`** | — | ✅ 必需 | — | 加载 SBPL 内核级 profile：`(deny default)` 起全拒、文件读写/网络/mach-lookup/sysctl/IOKit 细粒度规则 |
| **`/usr/bin/log stream`** | — | ✅ 必需 | — | seatbelt 违规事件监控（`startMacOSSandboxLogMonitor` spawn） |
| **`env` / `which` / shell** | ✅ | ✅ | — | 环境变量 -u/VAR= 注入、shell 解析执行 |
| **srt-win.exe** (vendor Rust) | — | — | ✅ 必需 | WFP 过滤器（按 SID 网禁出口）、`srt-sandbox` 用户账户、CreateProcessWithLogonW 双跳受限 token 启动、ACL stamp/grant（SetSecurityInfo）、证书信任（Root 存储）、Job 对象、注册表/SAM/DPAPI |
| **UAC 提权** | — | — | ✅ | `windows-install` 一次性提权安装 |
| **WFP 回环放行端口段** | — | — | ✅ | 代理必须绑定 60080–60089，mux 后端用 127.0.0.1 TCP |
| **CreateProcessW 限制** | — | — | ✅ | argv ≤ 32767 字符检查 |
| **`nc -X 5`** (BSD) | — | ✅ | — | `GIT_SSH_COMMAND` 走 SOCKS5 代理 |
| **JVM javaagent** | ✅ | ✅ | ✅ | `srt-proxy-agent.jar` 经 `JAVA_TOOL_OPTIONS=-javaagent:` 注入；macOS 另加 `-Djava.net.preferIPv4Stack` |
| **sun_path 长度约束** | — | ✅ | — | unix socket 路径 ≤104 字节（mux 后端、tls-terminate、violation-monitor） |
| **WSL1** | 明确不支持 | — | — | `getWslVersion()==='1'` 拒绝（无 bwrap）；WSL2 视为 Linux |

### 其他 OS 耦合点

- `src/utils/platform.ts`：读 `/proc/version` 识别 WSL 版本（仅 Linux）。
- `src/sandbox/sandbox-utils.ts`：Windows UNC / `\\?\` 扩展前缀 / `%ENV%` 引用展开、盘符大写、git schannel 配置；macOS `/tmp`→`/private/tmp` 规范化、BSD `nc -X 5` 的 GIT_SSH_COMMAND；Linux `socat - PROXY:` 的 GIT_SSH_COMMAND。
- `src/sandbox/mux-proxy.ts`：Windows 后端走 127.0.0.1 TCP 且端口须落在 WFP 放行段，其余平台用 unix socket。
- `src/sandbox/credential-mask-files.ts`：仅 Linux 生效（bwrap ro-bind 掩码）；macOS 上降级为 `mode: "deny"`（SBPL 无法重定向读）。
- `src/sandbox/mitm-ca.ts` / `mitm-leaf.ts`：`crlUrl` 仅 Windows 设置（Schannel 强制叶子 CRL 吊销检查）；叶子证书须带 AKI（Python 3.13 strict verify）与 CDP（Windows git/curl/cargo 硬性吊销检查）。
- `src/sandbox/linux-violation-monitor.ts`：依赖 `apply-seccomp` 作为事件生产者（USER_NOTIF）；因 bwrap `--unshare-net` 必须用文件系统 unix socket（sun_path 108 字节）。
- 外部 npm 依赖仅 3 个：`node-forge`（CA/证书）、`@pondwader/socks5-server`（SOCKS5）、`zod`+`commander`（配置/CLI）。

### 平台沙箱机制对照

| 维度 | Linux | macOS | Windows |
|---|---|---|---|
| 执行引擎 | bwrap（命名空间）+ socat + apply-seccomp | `/usr/bin/sandbox-exec`（Seatbelt/SBPL） | `srt-win.exe`（独立用户 + 受限 token 双跳启动） |
| 文件系统隔离 | 挂载命名空间：`--ro-bind / /` + 白名单 `--bind`、`--tmpfs`/`/dev/null` 掩码 deny、glob 用 rg 展开 | SBPL 规则：`(deny/allow file-read*/write*)`、subpath/regex、移动阻断 | 沙箱用户 SID 的 ACL：deny 打 `(OI)(CI) DENY` 戳、allow 加 `MODIFY_NO_FDC/READ|EXECUTE` 授权 |
| 网络隔离 | `--unshare-net`（全隔离）+ 代理过滤；域过滤发生在宿主代理层 | seatbelt `network-outbound` 内核级过滤 + 代理 | 用户 SID 级 WFP 过滤器围栏 + 代理 |
| 违规监控 | apply-seccomp USER_NOTIF → unix socket | `/usr/bin/log stream` 解析 seatbelt deny | 无独立监控（走代理 deny 记录） |
| 附加工具 | rg、socat、bash | env、bash、nc | srt-win.exe（Rust，WFP/ACL/证书/账户） |
