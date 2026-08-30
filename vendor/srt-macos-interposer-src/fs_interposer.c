/*
 * srt fs-approval DYLD interposer (macOS).
 *
 * Interposes the libc entry points a sandboxed process uses to read, write
 * or delete files, and — for paths beneath the configured SRT_APPROVE_DIRS
 * mount directories — asks the host-side approval server (fs-approval.ts)
 * over a Unix socket before letting the operation through.
 *
 * Environment (set by the sandbox wrapper for every child):
 *   SRT_APPROVE_SOCKET    path to the session approval server socket
 *   SRT_APPROVE_DIRS      colon-separated absolute mount directories
 *   SRT_APPROVE_TIMEOUT_MS response timeout (default 5000)
 *   SRT_ATTRIBUTION       base64-encoded command tag (violation attribution)
 *
 * Fail-closed: any RPC failure / timeout / malformed response denies the
 * operation with EPERM. Paths not beneath a mount directory pass through
 * untouched (the Seatbelt profile remains the real boundary).
 *
 * Only non-restricted binaries honour DYLD_INSERT_LIBRARIES (Apple-signed
 * system binaries strip DYLD_* at exec), so the wrapper shell must be a
 * third-party shell (Homebrew bash/zsh, etc.) for this to apply. The
 * srt-launcher companion re-injects the DYLD vars after sandbox-exec
 * strips them.
 */

#define _DARWIN_C_SOURCE 1

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                         \
  __attribute__((used)) static struct {                                 \
    const void *replacement;                                            \
    const void *replacee;                                               \
  } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = \
      {(const void *)(unsigned long)&_replacement,                      \
       (const void *)(unsigned long)&_replacee};

/* ------------------------------------------------------------------ */
/* Real symbols (resolved once via RTLD_NEXT)                          */
/* ------------------------------------------------------------------ */

static int (*real_open)(const char *, int, ...);
static int (*real_openat)(int, const char *, int, ...);
static int (*real_unlink)(const char *);
static int (*real_unlinkat)(int, const char *, int);
static int (*real_rename)(const char *, const char *);
static int (*real_renameat)(int, const char *, int, const char *);
static int (*real_rmdir)(const char *);
static int (*real_mkdir)(const char *, mode_t);
static int (*real_mkdirat)(int, const char *, mode_t);
static int (*real_truncate)(const char *, off_t);
static int (*real_ftruncate)(int, off_t);

static void resolve_reals(void) {
  if (real_open) return;
  real_open = dlsym(RTLD_NEXT, "open");
  real_openat = dlsym(RTLD_NEXT, "openat");
  real_unlink = dlsym(RTLD_NEXT, "unlink");
  real_unlinkat = dlsym(RTLD_NEXT, "unlinkat");
  real_rename = dlsym(RTLD_NEXT, "rename");
  real_renameat = dlsym(RTLD_NEXT, "renameat");
  real_rmdir = dlsym(RTLD_NEXT, "rmdir");
  real_mkdir = dlsym(RTLD_NEXT, "mkdir");
  real_mkdirat = dlsym(RTLD_NEXT, "mkdirat");
  real_truncate = dlsym(RTLD_NEXT, "truncate");
  real_ftruncate = dlsym(RTLD_NEXT, "ftruncate");
}

/* ------------------------------------------------------------------ */
/* Configuration (lazy init from env)                                  */
/* ------------------------------------------------------------------ */

#define MAX_MOUNTS 64
#define MOUNT_COPIES 2 /* raw + realpath-resolved */

static char g_mounts[MAX_MOUNTS][MOUNT_COPIES][PATH_MAX];
static int g_num_mounts = 0;
static char g_socket[sizeof(((struct sockaddr_un *)0)->sun_path)] = "";
static long g_timeout_ms = 5000;
static char g_attribution[512] = "";
static int g_inited = 0;

static void init_config(void) {
  if (g_inited) return;
  g_inited = 1;

  const char *socket_path = getenv("SRT_APPROVE_SOCKET");
  if (socket_path && *socket_path) {
    if (strlen(socket_path) < sizeof(g_socket)) strcpy(g_socket, socket_path);
  }

  const char *dirs = getenv("SRT_APPROVE_DIRS");
  if (dirs) {
    const char *p = dirs;
    while (*p && g_num_mounts < MAX_MOUNTS) {
      const char *colon = strchr(p, ':');
      size_t len = colon ? (size_t)(colon - p) : strlen(p);
      if (len > 0 && len < PATH_MAX) {
        char dir[PATH_MAX];
        memcpy(dir, p, len);
        dir[len] = '\0';
        /* Collapse empty components and duplicates. */
        int seen = 0;
        for (int i = 0; i < g_num_mounts && !seen; i++) {
          if (strcmp(g_mounts[i][0], dir) == 0) seen = 1;
        }
        if (!seen) {
          strcpy(g_mounts[g_num_mounts][0], dir);
          g_mounts[g_num_mounts][1][0] = '\0';
          /* Resolve the mount dir once so /tmp -> /private/tmp and symlinked
           * mounts match paths the caller spelled differently. */
          char resolved[PATH_MAX];
          if (realpath(dir, resolved) != NULL && strcmp(resolved, dir) != 0) {
            strcpy(g_mounts[g_num_mounts][1], resolved);
          }
          g_num_mounts++;
        }
      }
      p = colon ? colon + 1 : p + len;
    }
  }

  const char *timeout = getenv("SRT_APPROVE_TIMEOUT_MS");
  if (timeout && *timeout) {
    long v = strtol(timeout, NULL, 10);
    if (v > 0) g_timeout_ms = v;
  }

  const char *attr = getenv("SRT_ATTRIBUTION");
  if (attr && *attr) {
    if (strlen(attr) < sizeof(g_attribution)) strcpy(g_attribution, attr);
  }
}

/* ------------------------------------------------------------------ */
/* Mount matching                                                      */
/* ------------------------------------------------------------------ */

static bool path_under(const char *dir, const char *p) {
  size_t dl = strlen(dir);
  if (dl == 0 || strncmp(dir, p, dl) != 0) return false;
  if (p[dl] == '\0') return true;
  return p[dl] == '/';
}

/* System roots that get realpath'd on every miss would be pure overhead. */
static bool looks_system_path(const char *p) {
  static const char *const prefixes[] = {
      "/usr/", "/System/", "/Library/", "/bin/", "/sbin/",
      "/etc/", "/dev/", "/private/var/", "/private/etc/",
  };
  for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
    if (strncmp(p, prefixes[i], strlen(prefixes[i])) == 0) return true;
  }
  return false;
}

static bool is_mounted(const char *path) {
  for (int i = 0; i < g_num_mounts; i++) {
    for (int c = 0; c < MOUNT_COPIES; c++) {
      if (g_mounts[i][c][0] && path_under(g_mounts[i][c], path)) return true;
    }
  }
  /* Fallback: a symlinked path reaching into a mount (e.g. /tmp/link ->
   * /Users/me/proj/file) won't prefix-match; resolve and re-check. */
  if (!looks_system_path(path)) {
    char resolved[PATH_MAX];
    if (realpath(path, resolved) != NULL) {
      for (int i = 0; i < g_num_mounts; i++) {
        for (int c = 0; c < MOUNT_COPIES; c++) {
          if (g_mounts[i][c][0] && path_under(g_mounts[i][c], resolved)) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

/* ------------------------------------------------------------------ */
/* Session verdict cache (interposer side): avoids a socket RTT for    */
/* session/always-approved ops. Open addressing, collision = re-ask.   */
/* ------------------------------------------------------------------ */

#define CACHE_BITS 12
#define CACHE_SIZE (1 << CACHE_BITS)
#define CACHE_MASK (CACHE_SIZE - 1)

static uint64_t g_cache_key[CACHE_SIZE];
static uint64_t g_cache_op[CACHE_SIZE];
static uint64_t g_cache_valid[CACHE_SIZE];

static uint64_t djb2(const char *s) {
  uint64_t h = 5381;
  while (*s) h = ((h << 5) + h) ^ (unsigned char)*s++;
  return h;
}

static uint64_t cache_hash(const char *op, const char *path) {
  return djb2(path) ^ (djb2(op) * 1000003);
}

static bool cache_lookup(const char *op, uint64_t h) {
  for (int i = 0; i < CACHE_SIZE; i++) {
    uint64_t idx = (h + (uint64_t)i) & CACHE_MASK;
    if (!g_cache_valid[idx]) return false;
    if (g_cache_key[idx] == h && g_cache_op[idx] == djb2(op)) return true;
  }
  return false;
}

static void cache_store(const char *op, uint64_t h) {
  for (int i = 0; i < CACHE_SIZE; i++) {
    uint64_t idx = (h + (uint64_t)i) & CACHE_MASK;
    if (!g_cache_valid[idx]) {
      g_cache_valid[idx] = 1;
      g_cache_key[idx] = h;
      g_cache_op[idx] = djb2(op);
      return;
    }
  }
  /* Full - drop the request; the server still caches session verdicts. */
}

/* ------------------------------------------------------------------ */
/* RPC to the approval server                                          */
/* ------------------------------------------------------------------ */

static void json_escape(const char *in, char *out, size_t out_sz) {
  size_t o = 0;
  for (const unsigned char *c = (const unsigned char *)in;
       *c && o + 6 < out_sz; c++) {
    switch (*c) {
      case '"':
        out[o++] = '\\';
        out[o++] = '"';
        break;
      case '\\':
        out[o++] = '\\';
        out[o++] = '\\';
        break;
      case '\n':
        out[o++] = '\\';
        out[o++] = 'n';
        break;
      case '\r':
        out[o++] = '\\';
        out[o++] = 'r';
        break;
      case '\t':
        out[o++] = '\\';
        out[o++] = 't';
        break;
      default:
        if (*c < 0x20) {
          static const char hex[] = "0123456789abcdef";
          out[o++] = '\\';
          out[o++] = 'u';
          out[o++] = '0';
          out[o++] = '0';
          out[o++] = hex[(*c >> 4) & 0xf];
          out[o++] = hex[*c & 0xf];
        } else {
          out[o++] = (char)*c;
        }
    }
  }
  out[o] = '\0';
}

/**
 * Ask the approval server for `op` on `path`. Returns 0 on explicit
 * approval (scope copied into scope_out) and -1 on deny or any RPC
 * failure (fail-closed at the caller).
 */
static int ask_server(const char *op, const char *path, char *scope_out,
                      size_t scope_sz) {
  int s = socket(AF_UNIX, SOCK_STREAM, 0);
  if (s < 0) return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(g_socket) >= sizeof(addr.sun_path)) {
    close(s);
    return -1;
  }
  strcpy(addr.sun_path, g_socket);

  if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    close(s);
    return -1;
  }

  /* Escaped buffers sized so a worst-case path/attribution (every byte a
   * control char, 6x expansion) can never truncate the JSON — a truncated
   * request would parse as malformed and wrongly deny the operation. */
  char epath[8192];
  char ecmd[4096];
  char eproc[512];
  json_escape(path, epath, sizeof(epath));
  json_escape(g_attribution, ecmd, sizeof(ecmd));
  const char *proc = getprogname();
  json_escape(proc ? proc : "srt", eproc, sizeof(eproc));

  char req[32768];
  int n = snprintf(req, sizeof(req),
                   "{\"v\":1,\"id\":\"srt\",\"op\":\"%s\",\"path\":\"%s\","
                   "\"pid\":%ld,\"proc\":\"%s\",\"cmd\":\"%s\"}\n",
                   op, epath, (long)getpid(), eproc, ecmd);
  if (n < 0 || (size_t)n >= sizeof(req)) {
    close(s);
    return -1;
  }
  if (write(s, req, (size_t)n) != n) {
    close(s);
    return -1;
  }

  struct pollfd pfd = {.fd = s, .events = POLLIN};
  int pr = poll(&pfd, 1, (int)g_timeout_ms);
  if (pr <= 0) {
    close(s);
    return -1;
  }

  char buf[1024];
  ssize_t r = read(s, buf, sizeof(buf) - 1);
  close(s);
  if (r <= 0) return -1;
  buf[r] = '\0';

  if (strstr(buf, "\"allow\":true") == NULL) return -1;
  if (scope_out && scope_sz) {
    const char *sc = strstr(buf, "\"scope\":");
    if (sc) {
      const char *q1 = strchr(sc + 8, '"');
      if (q1) {
        const char *q2 = strchr(q1 + 1, '"');
        if (q2) {
          size_t len = (size_t)(q2 - q1 - 1);
          if (len < scope_sz) {
            memcpy(scope_out, q1 + 1, len);
            scope_out[len] = '\0';
          }
        }
      }
    }
  }
  return 0;
}

/* ------------------------------------------------------------------ */
/* Approval gate                                                       */
/* ------------------------------------------------------------------ */

/**
 * Decide whether `op` on `path` may proceed. Returns 1 to allow, 0 to
 * deny with EPERM. Non-mounted paths always pass; mounted paths pass
 * only on a cached or freshly approved verdict.
 */
static int approve(const char *op, const char *path) {
  init_config();
  if (g_num_mounts == 0 || g_socket[0] == '\0') return 1;
  if (!is_mounted(path)) return 1;

  uint64_t h = cache_hash(op, path);
  if (cache_lookup(op, h)) return 1;

  char scope[16] = "once";
  if (ask_server(op, path, scope, sizeof(scope)) != 0) return 0; /* fail-closed */
  if (strcmp(scope, "session") == 0 || strcmp(scope, "always") == 0) {
    cache_store(op, h);
  }
  return 1;
}

/* ------------------------------------------------------------------ */
/* Interposed entry points                                             */
/* ------------------------------------------------------------------ */

static int my_open(const char *path, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  resolve_reals();
  const char *op = (flags & (O_WRONLY | O_RDWR | O_CREAT)) ? "write" : "read";
  if (!approve(op, path)) {
    errno = EPERM;
    return -1;
  }
  return real_open(path, flags, mode);
}

/* Resolve dirfd-relative paths; falls back to "pass through" (approve
 * skipped) when the directory fd cannot be resolved to a path. */
static int resolve_dirfd_path(int dirfd, const char *path, char *out,
                              size_t out_sz) {
  if (dirfd == AT_FDCWD) {
    if (path[0] == '/') {
      if (strlen(path) >= out_sz) return -1;
      strcpy(out, path);
      return 0;
    }
    if (getcwd(out, out_sz) == NULL) return -1;
    size_t l = strlen(out);
    if (l + strlen(path) + 2 > out_sz) return -1;
    if (l > 1 && out[l - 1] != '/') {
      out[l++] = '/';
    }
    strcpy(out + l, path);
    return 0;
  }
  /* dirfd -> real path via F_GETPATH (macOS). */
  char fdpath[PATH_MAX];
  if (fcntl(dirfd, F_GETPATH, fdpath) != 0) return -1;
  if (path[0] == '/') {
    if (strlen(path) >= out_sz) return -1;
    strcpy(out, path);
    return 0;
  }
  if (snprintf(out, out_sz, "%s/%s", fdpath, path) >= (int)out_sz) return -1;
  return 0;
}

static int my_openat(int dirfd, const char *path, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list ap;
    va_start(ap, flags);
    mode = (mode_t)va_arg(ap, int);
    va_end(ap);
  }
  resolve_reals();
  char full[PATH_MAX];
  if (resolve_dirfd_path(dirfd, path, full, sizeof(full)) == 0) {
    const char *op = (flags & (O_WRONLY | O_RDWR | O_CREAT)) ? "write" : "read";
    if (!approve(op, full)) {
      errno = EPERM;
      return -1;
    }
  }
  return real_openat(dirfd, path, flags, mode);
}

static int my_unlink(const char *path) {
  resolve_reals();
  if (!approve("delete", path)) {
    errno = EPERM;
    return -1;
  }
  return real_unlink(path);
}

static int my_unlinkat(int dirfd, const char *path, int flag) {
  resolve_reals();
  char full[PATH_MAX];
  if (resolve_dirfd_path(dirfd, path, full, sizeof(full)) == 0) {
    if (!approve("delete", full)) {
      errno = EPERM;
      return -1;
    }
  }
  return real_unlinkat(dirfd, path, flag);
}

static int my_rename(const char *from, const char *to) {
  resolve_reals();
  if (!approve("delete", from)) {
    errno = EPERM;
    return -1;
  }
  if (!approve("write", to)) {
    errno = EPERM;
    return -1;
  }
  return real_rename(from, to);
}

static int my_renameat(int fromfd, const char *from, int tofd, const char *to) {
  resolve_reals();
  char f[PATH_MAX], t[PATH_MAX];
  int fok = resolve_dirfd_path(fromfd, from, f, sizeof(f)) == 0;
  int tok = resolve_dirfd_path(tofd, to, t, sizeof(t)) == 0;
  if (fok && !approve("delete", f)) {
    errno = EPERM;
    return -1;
  }
  if (tok && !approve("write", t)) {
    errno = EPERM;
    return -1;
  }
  return real_renameat(fromfd, from, tofd, to);
}

static int my_rmdir(const char *path) {
  resolve_reals();
  if (!approve("delete", path)) {
    errno = EPERM;
    return -1;
  }
  return real_rmdir(path);
}

static int my_mkdir(const char *path, mode_t mode) {
  resolve_reals();
  if (!approve("write", path)) {
    errno = EPERM;
    return -1;
  }
  return real_mkdir(path, mode);
}

static int my_mkdirat(int dirfd, const char *path, mode_t mode) {
  resolve_reals();
  char full[PATH_MAX];
  if (resolve_dirfd_path(dirfd, path, full, sizeof(full)) == 0) {
    if (!approve("write", full)) {
      errno = EPERM;
      return -1;
    }
  }
  return real_mkdirat(dirfd, path, mode);
}

static int my_truncate(const char *path, off_t length) {
  resolve_reals();
  if (!approve("write", path)) {
    errno = EPERM;
    return -1;
  }
  return real_truncate(path, length);
}

static int my_ftruncate(int fd, off_t length) {
  resolve_reals();
  /* ftruncate has no path argument; resolve the fd so the approval gate
   * sees the real target. An unresolvable fd passes through (approval was
   * already gated at open()). */
  char fdpath[PATH_MAX];
  if (fcntl(fd, F_GETPATH, fdpath) == 0) {
    if (!approve("write", fdpath)) {
      errno = EPERM;
      return -1;
    }
  }
  return real_ftruncate(fd, length);
}

DYLD_INTERPOSE(my_open, open)
DYLD_INTERPOSE(my_openat, openat)
DYLD_INTERPOSE(my_unlink, unlink)
DYLD_INTERPOSE(my_unlinkat, unlinkat)
DYLD_INTERPOSE(my_rename, rename)
DYLD_INTERPOSE(my_renameat, renameat)
DYLD_INTERPOSE(my_rmdir, rmdir)
DYLD_INTERPOSE(my_mkdir, mkdir)
DYLD_INTERPOSE(my_mkdirat, mkdirat)
DYLD_INTERPOSE(my_truncate, truncate)
DYLD_INTERPOSE(my_ftruncate, ftruncate)
