/**
 * Build the macOS fs-approval DYLD interposer and launcher
 * (vendor/srt-macos-interposer-src) into
 * vendor/srt-macos-interposer/<arch>/{libsrtfs_approve.dylib,srt-launcher}.
 *
 * Same model as the seccomp / srt-win / java-proxy-agent helpers: only the
 * source is in git; the artifact is built by the release workflow on macOS
 * and shipped in the npm package. Consumers running macOS can build it with:
 *
 *   npm run build:fs-interposer
 *
 * Needs a macOS SDK with clang (cc) on PATH — the default on every mac with
 * Xcode Command Line Tools installed.
 */
import { join } from 'node:path'
import { run, setup } from '../build-common.js'

const { SRC, OUT } = setup({
  importMetaUrl: import.meta.url,
  requirePlatform: 'darwin',
  srcDirName: 'srt-macos-interposer-src',
})

const cc = process.env.CC || 'cc'
const cflags = ['-O2', '-Wall', '-Wextra', '-Werror']

run([
  cc,
  ...cflags,
  '-dynamiclib',
  '-o',
  join(OUT, 'libsrtfs_approve.dylib'),
  join(SRC, 'fs_interposer.c'),
])

run([
  cc,
  ...cflags,
  '-o',
  join(OUT, 'srt-launcher'),
  join(SRC, 'srt-launcher.c'),
])

console.log(`built ${join(OUT, 'libsrtfs_approve.dylib')}`)
console.log(`built ${join(OUT, 'srt-launcher')}`)
