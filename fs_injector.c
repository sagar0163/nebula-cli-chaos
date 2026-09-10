#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>

// Environment variables to look for:
// INJECT_EACCES_PATH
// INJECT_ENOSPC_PATH

static int (*real_open)(const char *pathname, int flags, ...);
static int (*real_open64)(const char *pathname, int flags, ...);
static int (*real_openat)(int dirfd, const char *pathname, int flags, ...);
static ssize_t (*real_write)(int fd, const void *buf, size_t count);

static void init_real_functions() {
    if (!real_open) {
        real_open = dlsym(RTLD_NEXT, "open");
        real_open64 = dlsym(RTLD_NEXT, "open64");
        real_openat = dlsym(RTLD_NEXT, "openat");
        real_write = dlsym(RTLD_NEXT, "write");
    }
}

static int should_inject_eacces(const char* pathname) {
    if (!pathname) return 0;
    const char* eacces_path = getenv("INJECT_EACCES_PATH");
    if (eacces_path && strstr(pathname, eacces_path) != NULL) {
        return 1;
    }
    return 0;
}

static int should_inject_enospc_fd(int fd) {
    const char* enospc_path = getenv("INJECT_ENOSPC_PATH");
    if (!enospc_path) return 0;

    char proc_path[256];
    char file_path[4096];
    snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(proc_path, file_path, sizeof(file_path) - 1);
    if (len != -1) {
        file_path[len] = '\0';
        if (strstr(file_path, enospc_path) != NULL) {
            return 1;
        }
    }
    return 0;
}

int open(const char *pathname, int flags, ...) {
    init_real_functions();
    if (should_inject_eacces(pathname)) {
        errno = EACCES;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_open(pathname, flags, mode);
    } else {
        return real_open(pathname, flags);
    }
}

int open64(const char *pathname, int flags, ...) {
    init_real_functions();
    if (should_inject_eacces(pathname)) {
        errno = EACCES;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_open64(pathname, flags, mode);
    } else {
        return real_open64(pathname, flags);
    }
}

int openat(int dirfd, const char *pathname, int flags, ...) {
    init_real_functions();
    if (should_inject_eacces(pathname)) {
        errno = EACCES;
        return -1;
    }

    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
        return real_openat(dirfd, pathname, flags, mode);
    } else {
        return real_openat(dirfd, pathname, flags);
    }
}

ssize_t write(int fd, const void *buf, size_t count) {
    init_real_functions();
    if (should_inject_enospc_fd(fd)) {
        errno = ENOSPC;
        return -1;
    }
    return real_write(fd, buf, count);
}
