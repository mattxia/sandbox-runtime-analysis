import { connect } from 'node:net'
import { existsSync, mkdirSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'bun:test'
import { FsApprovalServer } from '../../src/sandbox/fs-approval.js'
import {
  encodeSandboxedCommand,
  normalizePathForSandbox,
} from '../../src/sandbox/sandbox-utils.js'
import type {
  FsAskParams,
  FsAskResult,
  FsMountConfig,
} from '../../src/sandbox/sandbox-schemas.js'
import { isWindows } from '../helpers/platform.js'

/**
 * Shape of the newline-delimited JSON responses sent by FsApprovalServer.
 * Kept loose (index signature) because error paths may carry extra fields.
 */
interface ApprovalResponse {
  id?: string
  allow?: boolean
  scope?: string
  reason?: string
  [key: string]: unknown
}

/**
 * Unit tests for the host-side fs-approval server (the Unix-socket half of
 * the macOS DYLD-interposer approval flow). The server is pure Node — no
 * macOS-only APIs — so the RPC semantics, verdict-cache rules, fail-closed
 * behaviour and violation-store wiring are exercised on Linux CI and on
 * real macOS alike.
 */

const TEST_ROOT = join(
  tmpdir(),
  'srt-fsapprove-' + process.pid + '-' + Date.now(),
)
const MOUNT = join(TEST_ROOT, 'mount')
const MOUNT_TRAILING_SLASH = MOUNT + '/'
const OTHER = join(TEST_ROOT, 'other')
const OTHER2 = join(TEST_ROOT, 'app2')
const LINK = join(TEST_ROOT, 'link')

const REQUEST_PATH = (name: string) => join(MOUNT, name)

const mountAll: FsMountConfig = {
  path: MOUNT,
  ops: ['read', 'write', 'delete'],
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

/**
 * One-shot RPC over a fresh connection: sends `payload` (or a raw string)
 * and resolves with the first newline-delimited JSON response.
 */
function request(
  socketPath: string,
  payload: unknown,
): Promise<ApprovalResponse> {
  return pipeline(socketPath, [payload]).then(lines => lines[0])
}

/** Pipelined RPC: sends all payloads on one connection, returns responses in order. */
function pipeline(
  socketPath: string,
  payloads: unknown[],
): Promise<ApprovalResponse[]> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath)
    const out: ApprovalResponse[] = []
    let buffer = ''
    sock.setEncoding('utf8')
    sock.on('connect', () => {
      const body = payloads
        .map(p => (typeof p === 'string' ? p : JSON.stringify(p)))
        .join('\n')
      sock.write(body + '\n')
    })
    sock.on('data', (chunk: string) => {
      buffer += chunk
      let nl: number
      while (
        out.length < payloads.length &&
        (nl = buffer.indexOf('\n')) !== -1
      ) {
        const line = buffer.slice(0, nl)
        buffer = buffer.slice(nl + 1)
        out.push(JSON.parse(line))
      }
      if (out.length === payloads.length) {
        sock.destroy()
        resolve(out)
      }
    })
    sock.on('error', reject)
  })
}

/**
 * Like {@link pipeline}, but invokes `release` as soon as `total - 1`
 * responses are in. Used by the in-flight cap test: the server holds the
 * first request on a gate while denying the excess, so the test must let
 * the gate go once it has seen the denials instead of waiting for all.
 */
function collectWhileHeld(
  socketPath: string,
  payloads: unknown[],
  total: number,
  release: () => void,
): Promise<ApprovalResponse[]> {
  return new Promise((resolve, reject) => {
    const sock = connect(socketPath)
    const out: ApprovalResponse[] = []
    let buffer = ''
    let released = false
    sock.setEncoding('utf8')
    sock.on('connect', () => {
      sock.write(payloads.map(p => JSON.stringify(p)).join('\n') + '\n')
    })
    sock.on('error', reject)
    sock.on('data', (chunk: string) => {
      buffer += chunk
      let nl: number
      while (out.length < total && (nl = buffer.indexOf('\n')) !== -1) {
        const line = buffer.slice(0, nl)
        buffer = buffer.slice(nl + 1)
        out.push(JSON.parse(line))
      }
      if (!released && out.length >= total - 1) {
        released = true
        release()
      }
      if (out.length === total) {
        sock.destroy()
        resolve(out)
      }
    })
  })
}

let servers: Array<{ server: FsApprovalServer; socketPath: string }> = []
let socketSeq = 0

async function startServer(options: {
  mounts: FsMountConfig[]
  askCallback?: (params: FsAskParams) => Promise<FsAskResult>
  resolveCommandText?: (decodedId: string) => string
  onViolation?: (line: string, encodedCommand: string | undefined) => void
  timeoutMs?: number
  maxInflightPerPid?: number
}): Promise<{ socketPath: string }> {
  const socketPath = join(TEST_ROOT, `srv-${++socketSeq}.sock`)
  const server = new FsApprovalServer({ socketPath, ...options })
  await server.start()
  servers.push({ server, socketPath })
  return { socketPath }
}

beforeAll(() => {
  rmSync(TEST_ROOT, { recursive: true, force: true })
  mkdirSync(MOUNT, { recursive: true })
  mkdirSync(OTHER, { recursive: true })
  mkdirSync(OTHER2, { recursive: true })
  try {
    symlinkSync(MOUNT, LINK)
  } catch {
    // Symlinks may be unavailable; the dual-copy test is best-effort.
  }
})

afterEach(async () => {
  await Promise.all(servers.map(({ server }) => server.close().catch(() => {})))
  servers = []
})

afterAll(() => {
  rmSync(TEST_ROOT, { recursive: true, force: true })
})

describe.if(!isWindows)('FsApprovalServer verdict cache semantics', () => {
  it('asks a read once per path, then serves the session cache', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
    })
    const p = REQUEST_PATH('a.txt')
    const first = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: p,
    })
    const second = await request(socketPath, {
      v: 1,
      id: '2',
      op: 'read',
      path: p,
    })
    expect(first).toEqual({ id: '1', allow: true, scope: 'session' })
    expect(second).toEqual({ id: '2', allow: true, scope: 'session' })
    expect(calls).toBe(1)
  })

  it('caches reads per path: a different path asks again', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
    })
    await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('a.txt'),
    })
    await request(socketPath, {
      v: 1,
      id: '2',
      op: 'read',
      path: REQUEST_PATH('b.txt'),
    })
    expect(calls).toBe(2)
  })

  it('forces session scope for reads even when the callback says once', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true, scope: 'once' }
      },
    })
    const p = REQUEST_PATH('c.txt')
    const first = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: p,
    })
    await request(socketPath, { v: 1, id: '2', op: 'read', path: p })
    expect(first.scope).toBe('session')
    expect(calls).toBe(1)
  })

  it('does not cache writes when the callback returns the default once scope', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
    })
    const p = REQUEST_PATH('w.txt')
    const first = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'write',
      path: p,
    })
    const second = await request(socketPath, {
      v: 1,
      id: '2',
      op: 'write',
      path: p,
    })
    expect(first.scope).toBe('once')
    expect(second.scope).toBe('once')
    expect(calls).toBe(2)
  })

  it('caches writes when the callback returns session scope', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true, scope: 'session' }
      },
    })
    const p = REQUEST_PATH('ws.txt')
    await request(socketPath, { v: 1, id: '1', op: 'write', path: p })
    await request(socketPath, { v: 1, id: '2', op: 'write', path: p })
    expect(calls).toBe(1)
  })

  it('caches deletes when the callback returns always scope', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true, scope: 'always' }
      },
    })
    const p = REQUEST_PATH('d.txt')
    await request(socketPath, { v: 1, id: '1', op: 'delete', path: p })
    await request(socketPath, { v: 1, id: '2', op: 'delete', path: p })
    expect(calls).toBe(1)
  })

  it('does not cache denials: each identical request asks again', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: false, reason: 'user denied' }
      },
    })
    const p = REQUEST_PATH('deny.txt')
    const first = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'write',
      path: p,
    })
    const second = await request(socketPath, {
      v: 1,
      id: '2',
      op: 'write',
      path: p,
    })
    expect(first).toEqual({ id: '1', allow: false, reason: 'user denied' })
    expect(second.allow).toBe(false)
    expect(calls).toBe(2)
  })
})

describe.if(!isWindows)('FsApprovalServer fail-closed behaviour', () => {
  it('denies when no ask callback is registered', async () => {
    const { socketPath } = await startServer({ mounts: [mountAll] })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res).toEqual({
      id: '1',
      allow: false,
      reason: 'no approval callback registered',
    })
  })

  it('denies when the callback throws', async () => {
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        throw new Error('boom')
      },
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res.allow).toBe(false)
    expect(res.reason).toContain('approval callback failed')
    expect(res.reason).toContain('boom')
  })

  it('denies when the callback exceeds the timeout', async () => {
    const gate = deferred<FsAskResult>()
    const { socketPath } = await startServer({
      mounts: [mountAll],
      timeoutMs: 50,
      askCallback: () => gate.promise,
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res.allow).toBe(false)
    expect(res.reason).toContain('timed out')
  })

  it('denies a request that exceeds the per-pid in-flight cap', async () => {
    const gate = deferred<FsAskResult>()
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      maxInflightPerPid: 1,
      askCallback: async () => {
        calls++
        return gate.promise
      },
    })
    // Pipelined on one connection: the server dispatches all three lines
    // synchronously while the first callback is still pending, so the last
    // two deterministically hit the cap. The two denies arrive without the
    // gate; release it once we have them so the allowed response completes.
    const payloads = [1, 2, 3].map(i => ({
      v: 1,
      id: String(i),
      op: 'write' as const,
      path: REQUEST_PATH(`f${i}.txt`),
    }))
    const responses = await collectWhileHeld(socketPath, payloads, 3, () => {
      gate.resolve({ allow: true })
    })
    expect(calls).toBe(1)
    expect(responses.filter(r => r.allow === true)).toHaveLength(1)
    expect(responses.filter(r => r.allow === false)).toHaveLength(2)
    expect(responses.filter(r => !r.allow)[0].reason).toBe(
      'too many concurrent approvals',
    )
  })

  it('denies malformed requests', async () => {
    const { socketPath } = await startServer({ mounts: [mountAll] })
    const notJson = await request(socketPath, 'this is not json')
    expect(notJson).toEqual({
      id: '',
      allow: false,
      reason: 'malformed request',
    })
    const badVersion = await request(socketPath, {
      v: 99,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('x.txt'),
    })
    expect(badVersion).toEqual({
      id: '1',
      allow: false,
      reason: 'malformed request',
    })
    const badOp = await request(socketPath, {
      v: 1,
      id: '2',
      op: 'chmod',
      path: REQUEST_PATH('x.txt'),
    })
    expect(badOp.allow).toBe(false)
  })
})

describe.if(!isWindows)('FsApprovalServer approval scope', () => {
  it('passes paths outside every mount without asking or recording', async () => {
    let calls = 0
    const violations: string[] = []
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
      onViolation: line => violations.push(line),
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'write',
      path: join(OTHER, 'x.txt'),
    })
    expect(res).toEqual({
      id: '1',
      allow: true,
      scope: 'session',
      reason: 'outside approval scope',
    })
    expect(calls).toBe(0)
    expect(violations).toHaveLength(0)
  })

  it('passes requests for ops not covered by the mount', async () => {
    const { socketPath } = await startServer({
      mounts: [{ path: MOUNT, ops: ['read'] }],
      askCallback: async () => {
        throw new Error('must not be asked')
      },
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'write',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res.allow).toBe(true)
    expect(res.reason).toBe('outside approval scope')
  })

  it('does not ask for requireApproval:false mounts even without a callback', async () => {
    const { socketPath } = await startServer({
      mounts: [
        {
          path: MOUNT,
          ops: ['read', 'write', 'delete'],
          requireApproval: false,
        },
      ],
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'delete',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res.allow).toBe(true)
    expect(res.reason).toBe('outside approval scope')
  })

  it('matches a mount configured with a trailing slash', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [
        { path: MOUNT_TRAILING_SLASH, ops: ['read', 'write', 'delete'] },
      ],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: REQUEST_PATH('x.txt'),
    })
    expect(res.allow).toBe(true)
    expect(calls).toBe(1)
  })

  it('matches a symlinked path via the realpath-resolved mount copy', async () => {
    if (!existsSync(LINK)) return
    let askedPath: string | undefined
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async p => {
        askedPath = p.path
        return { allow: true }
      },
    })
    // LINK -> MOUNT. The raw request spelling (/…/link/f.txt) does not
    // prefix-match the raw mount, but its realpath does — the server must
    // match against the resolved copy to avoid silently treating this as
    // out-of-scope.
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'read',
      path: join(LINK, 'f.txt'),
    })
    expect(res.allow).toBe(true)
    expect(askedPath).toBe(normalizePathForSandbox(join(LINK, 'f.txt')))
  })

  it('does not match a sibling directory with a shared prefix', async () => {
    let calls = 0
    const { socketPath } = await startServer({
      mounts: [mountAll],
      askCallback: async () => {
        calls++
        return { allow: true }
      },
    })
    const res = await request(socketPath, {
      v: 1,
      id: '1',
      op: 'write',
      path: join(OTHER2, 'x.txt'),
    })
    expect(res.allow).toBe(true)
    expect(res.reason).toBe('outside approval scope')
    expect(calls).toBe(0)
  })
})

describe.if(!isWindows)(
  'FsApprovalServer callback params and violation store',
  () => {
    it('passes decoded attribution and normalized path to the callback', async () => {
      const enc = encodeSandboxedCommand('python t.py')
      const seen: Array<{
        op: string
        path: string
        command?: string
        processName?: string
        pid?: number
      }> = []
      const { socketPath } = await startServer({
        mounts: [mountAll],
        resolveCommandText: (id: string) => `<<${id}>>`,
        askCallback: async p => {
          seen.push(p)
          return { allow: true }
        },
      })
      await request(socketPath, {
        v: 1,
        id: '1',
        op: 'read',
        path: REQUEST_PATH('a.txt'),
        pid: 42,
        proc: 'python3',
        cmd: enc,
      })
      expect(seen).toHaveLength(1)
      expect(seen[0].op).toBe('read')
      expect(seen[0].path).toBe(normalizePathForSandbox(REQUEST_PATH('a.txt')))
      expect(seen[0].command).toBe('<<python t.py>>')
      expect(seen[0].processName).toBe('python3')
      expect(seen[0].pid).toBe(42)
    })

    it('records allow/deny into the violation store with the encoded command tag', async () => {
      const enc = encodeSandboxedCommand('rm -rf data')
      const violations: Array<{ line: string; cmd: string | undefined }> = []
      const { socketPath } = await startServer({
        mounts: [mountAll],
        askCallback: async p => {
          if (p.op === 'write') return { allow: false, reason: 'user denied' }
          return { allow: true, reason: 'fine' }
        },
        onViolation: (line, cmd) => violations.push({ line, cmd }),
      })
      const readPath = REQUEST_PATH('r.txt')
      const writePath = REQUEST_PATH('w.txt')
      await request(socketPath, {
        v: 1,
        id: '1',
        op: 'read',
        path: readPath,
        pid: 7,
        proc: 'bash',
        cmd: enc,
      })
      await request(socketPath, {
        v: 1,
        id: '2',
        op: 'write',
        path: writePath,
        pid: 7,
        proc: 'bash',
        cmd: enc,
      })
      expect(violations).toEqual([
        { line: `fs-approval allow read ${readPath} (fine)`, cmd: enc },
        { line: `fs-approval deny write ${writePath} (user denied)`, cmd: enc },
      ])
    })
  },
)
