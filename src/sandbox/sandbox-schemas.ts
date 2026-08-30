// Filesystem restriction configs (internal structures built from permission rules)

/**
 * Read restriction config using a "deny then allow-back" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all reads)
 * - `{denyOnly: []}` = no restrictions (empty deny list = allow all reads)
 * - `{denyOnly: [...paths]}` = deny reads from these paths, allow all others
 * - `{denyOnly: [...paths], allowWithinDeny: [...paths]}` = deny reads from
 *   denyOnly paths, but re-allow reads within allowWithinDeny paths.
 *   Most-specific entry wins: an allowWithinDeny path re-opens the denied
 *   region it sits inside, while a denyOnly entry that is itself more
 *   specific than the allow it lands in — a literal nested under an
 *   allowed directory, or a glob such as `**\/.env` matching files inside
 *   one — stays denied.
 *
 * This is maximally permissive by default - only explicitly denied paths are blocked.
 */
export interface FsReadRestrictionConfig {
  denyOnly: string[]
  allowWithinDeny?: string[]
}

/**
 * Write restriction config using an "allow-only" pattern.
 *
 * Semantics:
 * - `undefined` = no restrictions (allow all writes)
 * - `{allowOnly: [], denyWithinAllow: []}` = maximally restrictive (deny ALL writes)
 * - `{allowOnly: [...paths], denyWithinAllow: [...]}` = allow writes only to these paths,
 *   with exceptions for denyWithinAllow
 *
 * This is maximally restrictive by default - only explicitly allowed paths are writable.
 * Note: Empty `allowOnly` means NO paths are writable (unlike read's empty denyOnly).
 */
export interface FsWriteRestrictionConfig {
  allowOnly: string[]
  denyWithinAllow: string[]
}

/**
 * Credential restriction config (internal structure built from the
 * `credentials` config section).
 *
 * - `denyReadPaths`: paths to merge into the read-deny set
 *   (FsReadRestrictionConfig.denyOnly), unioned with caller-supplied denyRead.
 * - `unsetEnvVars`: environment variable names to unset inside the sandbox.
 * - `setEnvVars`: environment variables to set inside the sandbox to a
 *   sentinel value (overrides the inherited real value).
 * - `maskedFileBinds`: (realPath → fakePath) pairs for whole-file masking;
 *   the platform layer binds fakePath over realPath read-only so the
 *   sandbox reads a sentinel instead of the real bytes (Linux only —
 *   macOS degrades these to denyReadPaths).
 * - `maskedFileStoreDir`: host directory holding the fake files. The
 *   Linux layer ro-binds it over itself so the sandbox cannot tamper
 *   with the bind sources regardless of allowWrite.
 */
export interface CredentialRestrictionConfig {
  denyReadPaths: string[]
  unsetEnvVars: string[]
  setEnvVars: Record<string, string>
  maskedFileBinds: Array<{ realPath: string; fakePath: string }>
  maskedFileStoreDir: string | undefined
}

/**
 * Network restriction config (internal structure built from permission rules).
 *
 * This uses an "allow-only" pattern (like write restrictions):
 * - `allowedHosts` = hosts that are explicitly allowed
 * - `deniedHosts` = hosts that are explicitly denied (checked first, before allowedHosts)
 *
 * Semantics:
 * - `undefined` allowedHosts = no allowlist configured
 * - `{allowedHosts: [], deniedHosts: []}` = allowlist configured with zero entries
 * - `{allowedHosts: [...], deniedHosts: [...]}` = apply allow/deny rules
 *
 * Note: Empty `allowedHosts` means no host matches an allow rule (unlike
 * read's empty denyOnly). Whether an unmatched host is denied outright
 * depends on the ask callback: deniedHosts are checked first and deny
 * unconditionally; a host matching neither list falls through to the
 * registered SandboxAskCallback when one exists, and is denied only when
 * no callback is registered. Hosts needing a hard block-all regardless of
 * callback behavior should use a `deniedHosts` wildcard.
 *
 * Entries are the raw config patterns and may carry an optional `:port`
 * suffix (`api.example.com:443`, `*:22`) meaning "this rule applies only
 * to that destination port". Consumers matching hosts themselves should
 * parse the suffix (see `splitDomainPatternPort`) rather than compare the
 * whole string; a deny-all check must accept `*:<port>` as well as `*`.
 */
export interface NetworkRestrictionConfig {
  allowedHosts?: string[]
  deniedHosts?: string[]
}

export type NetworkHostPattern = {
  host: string
  port: number | undefined
}

export type SandboxAskCallback = (
  params: NetworkHostPattern,
) => Promise<boolean>

/**
 * A filesystem operation that may require interactive approval on a
 * constrained (mount) directory.
 *
 * - `read`: open() without a write intent (O_RDONLY etc.)
 * - `write`: open() with a write intent, or mkdir/truncate
 * - `delete`: unlink / rename / rmdir — anything that removes or moves
 *   an existing path out from under its current name
 */
export type FsApprovalOp = 'read' | 'write' | 'delete'

/**
 * A constrained directory whose filesystem operations are gated on
 * user approval (macOS: the DYLD interposer + approval server).
 *
 * - `requireApproval: true` (default): read/write/delete ops on paths
 *   beneath `path` ask the registered FsAskCallback before proceeding.
 * - `requireApproval: false`: the directory is only statically allowed
 *   (Seatbelt) and never prompts — use for interpreter runtime dirs
 *   (site-packages etc.) whose reads would otherwise prompt on every
 *   process start.
 */
export interface FsMountConfig {
  /** Absolute path (or ~-expandable) of the constrained directory. */
  path: string
  /** Which ops under this path are subject to approval. */
  ops: FsApprovalOp[]
  /** Default true. false = static allow only, never prompts. */
  requireApproval?: boolean
}

export interface FsAskParams {
  op: FsApprovalOp
  /** Absolute path that triggered the approval. */
  path: string
  /** Attributed command (decoded from the interposer's cmd tag). */
  command?: string
  /** Process name reported by the interposer. */
  processName?: string
  pid?: number
}

/** How long an approved verdict stays effective (session-scoped). */
export type FsAskScope = 'once' | 'session' | 'always'

export interface FsAskResult {
  allow: boolean
  /**
   * Effective lifetime of the allow. Default `once` (the next identical
   * operation asks again). `session`/`always` cache op+path for the rest
   * of the sandbox session. Reads are always cached at session scope by
   * the approval server regardless of this value (first-visit semantics).
   */
  scope?: FsAskScope
  /** Deny/allow explanation; also recorded into the violation store. */
  reason?: string
}

/**
 * Headless approval callback for filesystem operations under constrained
 * mount directories. Registered via `SandboxManager.initialize()` options
 * (it cannot live in the JSON config — it's a function). Return
 * `{allow: false}` to deny; a throwing/unresolved callback denies
 * (fail-closed).
 */
export type FsAskCallback = (params: FsAskParams) => Promise<FsAskResult>
