/*
 * srt fs-approval launcher (macOS).
 *
 * /usr/bin/sandbox-exec is an Apple-signed system binary: dyld strips
 * DYLD_* environment variables from its environment at exec, so a plain
 * `env DYLD_INSERT_LIBRARIES=... sandbox-exec ...` chain never delivers
 * the interposer to the sandboxed shell. This tiny launcher sits between
 * sandbox-exec and the shell: it re-injects the DYLD vars itself (from
 * SRT_INTERPOSER_DYLIB, which is not DYLD_* and therefore survives the
 * stripping) and then execs the shell.
 *
 * Invocation (sandboxed):
 *   sandbox-exec -p <profile> <srt-launcher> <shell> -c <command>
 *
 * The shell must itself be a non-restricted binary (e.g. a Homebrew
 * shell) for dyld to honour the injected vars; Apple-signed system
 * shells (and the system binaries they spawn) fall back to the Seatbelt
 * boundary alone.
 */

#define _DARWIN_C_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  /* argv[1..] = [shell, "-c", command, ...] */
  if (argc < 3) return 127;

  const char *dylib = getenv("SRT_INTERPOSER_DYLIB");
  if (dylib && *dylib) {
    setenv("DYLD_INSERT_LIBRARIES", dylib, 1);
    setenv("DYLD_FORCE_FLAT_NAMESPACE", "1", 1);
  }

  execv(argv[1], &argv[1]);
  perror("srt-launcher: execv");
  return 127;
}
