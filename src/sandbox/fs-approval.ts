/**
 * Filesystem approval server (macOS).
 *
 * The host-side half of the fs-approval feature: listens on a Unix socket
 * that the DYLD interposer (vendor/srt-macos-interposer) connects to when a
 * sandboxed process touches a constrained mount directory. Each request is
 * resolved against a session verdict cache and, on a miss, the registered
 * FsAskCallback (headless). Verdicts are session-scoped and never written
 * to disk; every approval/denial is funnelled into the violation store via
 * the onViolation callback so the model sees the agent's filesystem actions
 * in the transcript.
 *
 * Fail-closed: a missing callback, a throwing/hanging callback, an
 * over-limit in-flight count, or a malformed request all deny. The
 * interposer also enforces its own response timeout (SRT_APPROVE_TIMEOUT_MS)
 * and denies on expiry — the server never has to race it.
 */

import { createServer, type Server, type Socket } from 'node:net'
import { rmSync } from 'node:fs'
import { logForDebugging } from '../utils/debug.js'
import {
  decodeSandboxedCommand,
  normalizePathForSandbox,
} from './sandbox-utils.js'
import { sanitizeViolationText } from './sandbox-violation-store.js'
import type {
  FsApprovalOp,
  FsAskCallback,
  FsAskScope,
  FsMountConfig,
} from './sandbox-schemas.js'

const PROTOCOL_VERSION = 1
const DEFAULT_TIMEOUT_MS = 5000
const DEFAULT_MAX_INFLIGHT_PER_PID = 3

interface FsApprovalRequest {
  v: number
  id: string
  op: FsApprovalOp
  path: string
  pid?: number
  proc?: string
  /** Attribution tag: encodedSandboxedCommand of the wrapped invocation. */
  cmd?: string
}

/**
 * Cache key: `op:normalizedPath`. Session-scoped; cleared on reset().
 * Reads are always cached here (first-visit semantics); writes/deletes
 * only when the callback returned scope session/always.
 */
type VerdictCacheKey = string

export interface FsApprovalServerOptions {
  socketPath: string
  /** Constrained dirs; used to bound the cache to mounted paths. */
  mounts: FsMountConfig[]
  askCallback?: FsAskCallback
  /** Map a decoded attribution key (cmd) to command text. */
  resolveCommandText?: (decodedId: string) => string
  /**
   * Record an approval/denial into the violation store. Receives the
   * human-readable line and the raw encoded command tag.
   */
  onViolation?: (line: string, encodedCommand: string | undefined) => void
  timeoutMs?: number
  maxInflightPerPid?: number
}

/**
 * A configured mount plus its path copies used for prefix matching.
 * `raw` keeps the user's spelling (e.g. /tmp/app-data) and `normalized`
 * is the realpath-resolved spelling (e.g. /private/tmp/app-data on a real
 * Mac). A request path is matched against both — the interposer sends the
 * spelling the process used, which may only match one of the two when the
 * mount is a symlink (/tmp) or the target doesn't exist yet. This mirrors
 * the interposer's own dual-copy mount table (see fs_interposer.c).
 */
interface MountEntry {
  config: FsMountConfig
  raw: string
  normalized: string
}

export class FsApprovalServer {
  private readonly socketPath: string
  private readonly mounts: MountEntry[]
  private readonly askCallback: FsAskCallback | undefined
  private readonly resolveCommandText: (decodedId: string) => string
  private readonly onViolation:
    | ((line: string, encodedCommand: string | undefined) => void)
    | undefined
  private readonly timeoutMs: number
  private readonly maxInflightPerPid: number

  private server: Server | undefined
  private readonly cache = new Set<VerdictCacheKey>()
  private readonly inflightByPid = new Map<number, number>()
  private readonly sockets = new Set<Socket>()

  constructor(options: FsApprovalServerOptions) {
    this.socketPath = options.socketPath
    this.mounts = options.mounts.map(config => ({
      config,
      raw: config.path,
      normalized: normalizePathForSandbox(config.path),
    }))
    this.askCallback = options.askCallback
    this.resolveCommandText = options.resolveCommandText ?? ((id: string) => id)
    this.onViolation = options.onViolation
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.maxInflightPerPid =
      options.maxInflightPerPid ?? DEFAULT_MAX_INFLIGHT_PER_PID
  }

  /** Start listening. Throws on bind failure (e.g. socket in use). */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = createServer((socket: Socket) => {
        this.handleConnection(socket)
      })
      server.on('error', (err: Error) => {
        logForDebugging(`[FsApproval] server error: ${err.message}`, {
          level: 'error',
        })
      })
      server.listen(this.socketPath, () => {
        this.server = server
        logForDebugging(`[FsApproval] listening on ${this.socketPath}`)
        resolve()
      })
      // listen() failure (EADDRINUSE etc.) surfaces as an 'error' event
      // before any listening callback; reject the start promise then.
      server.once('error', (err: Error) => {
        if (!this.server) reject(err)
      })
    })
  }

  /** Stop accepting connections, drop any in-flight clients, remove the socket file. */
  async close(): Promise<void> {
    this.cache.clear()
    this.inflightByPid.clear()
    for (const socket of this.sockets) {
      socket.destroy()
    }
    this.sockets.clear()
    const server = this.server
    this.server = undefined
    if (server) {
      await new Promise<void>(resolve => {
        server.close(() => resolve())
      })
    }
    try {
      rmSync(this.socketPath, { force: true })
    } catch (err) {
      logForDebugging(`[FsApproval] socket cleanup error: ${err}`, {
        level: 'error',
      })
    }
  }

  private handleConnection(socket: Socket): void {
    this.sockets.add(socket)
    socket.on('close', () => {
      this.sockets.delete(socket)
    })
    let buffer = ''
    socket.on('data', (data: Buffer) => {
      buffer += data.toString('utf8')
      let nl: number
      while ((nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl)
        buffer = buffer.slice(nl + 1)
        if (line.trim() === '') continue
        this.handleLine(socket, line)
      }
    })
    socket.on('error', err => {
      logForDebugging(`[FsApproval] connection error: ${err.message}`)
    })
  }

  private handleLine(socket: Socket, line: string): void {
    void this.handleRequest(socket, line).catch(err => {
      logForDebugging(`[FsApproval] request handling error: ${err}`, {
        level: 'error',
      })
      // Fail-closed: anything that throws mid-handling denies.
      this.respond(socket, { id: '', allow: false, reason: 'internal error' })
    })
  }

  private async handleRequest(socket: Socket, line: string): Promise<void> {
    let req: FsApprovalRequest
    try {
      const parsed = JSON.parse(line)
      if (
        parsed?.v !== PROTOCOL_VERSION ||
        typeof parsed.id !== 'string' ||
        typeof parsed.op !== 'string' ||
        typeof parsed.path !== 'string' ||
        !['read', 'write', 'delete'].includes(parsed.op)
      ) {
        this.respond(socket, {
          id: parsed?.id ?? '',
          allow: false,
          reason: 'malformed request',
        })
        return
      }
      req = parsed as FsApprovalRequest
    } catch {
      this.respond(socket, {
        id: '',
        allow: false,
        reason: 'malformed request',
      })
      return
    }

    // Only serve paths under a configured mount. Anything else is a
    // protocol misuse — deny without prompting.
    const normalized = normalizePathForSandbox(req.path)
    const entry = this.mounts.find(
      e => isUnder(e.raw, normalized) || isUnder(e.normalized, normalized),
    )
    if (
      !entry ||
      !entry.config.ops.includes(req.op) ||
      entry.config.requireApproval === false
    ) {
      this.respond(socket, {
        id: req.id,
        allow: true,
        scope: 'session',
        reason: 'outside approval scope',
      })
      return
    }

    const pid = req.pid ?? 0
    const cacheKey = `${req.op}:${normalized}`
    if (this.cache.has(cacheKey)) {
      this.respond(socket, { id: req.id, allow: true, scope: 'session' })
      return
    }

    // Prompt-flood protection: a hostile sandboxed process could otherwise
    // spam requests to force prompts. Over the limit → deny immediately.
    const inflight = this.inflightByPid.get(pid) ?? 0
    if (inflight >= this.maxInflightPerPid) {
      const reason = 'too many concurrent approvals'
      this.record(req, reason, 'deny')
      this.respond(socket, { id: req.id, allow: false, reason })
      return
    }
    this.inflightByPid.set(pid, inflight + 1)
    try {
      const command = req.cmd
        ? this.resolveCommandText(decodeSandboxedCommand(req.cmd))
        : undefined
      if (!this.askCallback) {
        const reason = 'no approval callback registered'
        this.record(req, reason, 'deny', command)
        this.respond(socket, { id: req.id, allow: false, reason })
        return
      }
      let result
      try {
        result = await this.withTimeout(
          this.askCallback({
            op: req.op,
            path: normalized,
            command,
            processName: req.proc,
            pid,
          }),
          this.timeoutMs,
        )
      } catch (err) {
        const reason = `approval callback failed: ${(err as Error).message}`
        this.record(req, reason, 'deny', command)
        this.respond(socket, { id: req.id, allow: false, reason })
        return
      }
      if (!result || result.allow !== true) {
        const reason = result?.reason ?? 'user denied'
        this.record(req, reason, 'deny', command)
        this.respond(socket, { id: req.id, allow: false, reason })
        return
      }
      // Reads are first-visit approved and cached for the session
      // regardless of the callback's scope (write/delete only cache on
      // explicit session/always).
      const scope: FsAskScope =
        req.op === 'read' ? 'session' : (result.scope ?? 'once')
      if (scope === 'session' || scope === 'always') {
        this.cache.add(cacheKey)
      }
      this.record(req, result.reason ?? 'ok', 'allow', command)
      this.respond(socket, { id: req.id, allow: true, scope })
    } finally {
      const remaining = (this.inflightByPid.get(pid) ?? 1) - 1
      if (remaining <= 0) this.inflightByPid.delete(pid)
      else this.inflightByPid.set(pid, remaining)
    }
  }

  private record(
    req: FsApprovalRequest,
    reason: string,
    action: 'allow' | 'deny',
    command?: string,
  ): void {
    if (!this.onViolation) return
    // Reuse the violation-store shape used by the seatbelt/seccomp/proxy
    // producers: a single physical line with the operation, path, verdict,
    // and reason. The command is attributed by the manager via the
    // encodedCommand tag, exactly like proxy denials.
    this.onViolation(
      `fs-approval ${action} ${req.op} ${req.path} (${sanitizeViolationText(reason)})`,
      req.cmd,
    )
    // `command` is resolved for debug logging only; attribution for the
    // store goes through the encodedCommand tag above.
    if (command !== undefined) {
      logForDebugging(
        `[FsApproval] ${action} ${req.op} ${req.path} for command ${command}`,
      )
    }
  }

  private respond(
    socket: Socket,
    response: {
      id: string
      allow: boolean
      scope?: FsAskScope
      reason?: string
    },
  ): void {
    if (socket.destroyed) return
    const body: Record<string, string | boolean> = {
      id: response.id,
      allow: response.allow,
    }
    if (response.scope !== undefined) body.scope = response.scope
    if (response.reason !== undefined) body.reason = response.reason
    socket.write(JSON.stringify(body) + '\n')
  }

  private withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`approval timed out after ${ms}ms`))
      }, ms)
      promise.then(
        v => {
          clearTimeout(timer)
          resolve(v)
        },
        e => {
          clearTimeout(timer)
          reject(e)
        },
      )
    })
  }
}

/** Is `candidate` at or beneath literal directory `dir`? */
function isUnder(dir: string, candidate: string): boolean {
  if (dir === '/') return candidate.startsWith('/')
  return (
    candidate === dir ||
    candidate.startsWith(dir.endsWith('/') ? dir : dir + '/')
  )
}

export { DEFAULT_TIMEOUT_MS, DEFAULT_MAX_INFLIGHT_PER_PID }
