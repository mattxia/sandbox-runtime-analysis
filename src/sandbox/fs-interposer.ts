/**
 * Filesystem approval: interposer/launcher lookup and env assembly (macOS).
 *
 * Locates the DYLD interposer dylib and the srt-launcher binary built by
 * `npm run build:fs-interposer` into vendor/srt-macos-interposer/<arch>/
 * (same lookup shape as the java-proxy-agent jar), and assembles the
 * SRT_* env values that wire a sandboxed child to the approval server.
 *
 * The DYLD_* vars themselves are NOT set here — /usr/bin/sandbox-exec
 * strips them at exec, so the launcher re-injects them from
 * SRT_INTERPOSER_DYLIB after the sandbox is applied (see
 * vendor/srt-macos-interposer-src/srt-launcher.c).
 */

import { existsSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logForDebugging } from '../utils/debug.js'
import { getGlobalNpmPaths } from './generate-seccomp-filter.js'

export const FS_INTERPOSER_DYLIB_NAME = 'libsrtfs_approve.dylib'
export const FS_LAUNCHER_NAME = 'srt-launcher'

const dylibCache = new Map<string, string | null>()
const launcherCache = new Map<string, string | null>()

function findBinary(
  name: string,
  cache: Map<string, string | null>,
  explicitPath?: string,
): string | null {
  const key = explicitPath ?? ''
  const cached = cache.get(key)
  if (cached !== undefined) return cached
  const found = searchBinary(name, explicitPath)
  cache.set(key, found)
  return found
}

function searchBinary(name: string, explicitPath?: string): string | null {
  if (explicitPath) {
    if (existsSync(explicitPath)) return explicitPath
    logForDebugging(
      `[fs-interposer] explicit path not found: ${explicitPath}`,
      { level: 'warn' },
    )
  }
  const baseDir = dirname(fileURLToPath(import.meta.url))
  const arch =
    process.arch === 'arm64'
      ? 'arm64'
      : process.arch === 'x64'
        ? 'x64'
        : undefined
  if (!arch) {
    logForDebugging(`[fs-interposer] unsupported arch ${process.arch}`)
    return null
  }
  const rel = join('vendor', 'srt-macos-interposer', arch, name)
  const candidates = [
    join(baseDir, rel),
    join(baseDir, '..', '..', rel),
    join(baseDir, '..', rel),
    ...getGlobalNpmPaths().map(base => join(base, rel)),
  ]
  for (const p of candidates) {
    if (existsSync(p)) return p
  }
  logForDebugging(
    `[fs-interposer] ${name} not found; filesystem approval is unavailable ` +
      `(run \`npm run build:fs-interposer\` on macOS)`,
    { level: 'warn' },
  )
  return null
}

/** Absolute path to libsrtfs_approve.dylib, or null when not built. */
export function resolveFsInterposerDylibPath(
  explicitPath?: string,
): string | null {
  return findBinary(FS_INTERPOSER_DYLIB_NAME, dylibCache, explicitPath)
}

/** Absolute path to srt-launcher, or null when not built. */
export function resolveFsLauncherPath(explicitPath?: string): string | null {
  return findBinary(FS_LAUNCHER_NAME, launcherCache, explicitPath)
}

/**
 * A fresh per-session socket path for the approval server. Mirrors the
 * sessionSuffix scheme used by the macOS log monitor so a session's
 * artifacts are recognizable in /tmp.
 */
export function createFsApprovalSocketPath(): string {
  const rand = randomBytes(5).toString('hex')
  return `/tmp/srt-fsapprove-${rand}_SBX.sock`
}

/**
 * Assemble the SRT_* env assignments the sandboxed child needs to reach
 * the approval server. `approvalDirs` are the mount paths with
 * requireApproval !== false — non-approval mounts are excluded so they
 * never prompt. `encodedCommand` is the attribution tag (same value as
 * the proxy username) reported as `cmd` in every approval request.
 */
export function buildFsApprovalEnvVars(opts: {
  socketPath: string
  approvalDirs: string[]
  timeoutMs?: number
  encodedCommand: string
  interposerDylibPath: string
}): string[] {
  const env: string[] = [
    `SRT_APPROVE_SOCKET=${opts.socketPath}`,
    `SRT_APPROVE_DIRS=${opts.approvalDirs.join(':')}`,
    `SRT_ATTRIBUTION=${opts.encodedCommand}`,
    `SRT_INTERPOSER_DYLIB=${opts.interposerDylibPath}`,
  ]
  if (opts.timeoutMs !== undefined) {
    env.push(`SRT_APPROVE_TIMEOUT_MS=${opts.timeoutMs}`)
  }
  return env
}
