/* Adversarial payload for the explicitly enabled real-container suite. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ใช้ syscall ที่ allowlist อนุญาต เพื่อทดสอบ timeout/cleanup จริง */
static void wait_for_cleanup(void) {
    const struct timespec delay = {3600, 0};
    for (;;) nanosleep(&delay, NULL);
}

int main(int argc, char **argv) {
    if (argc < 2) return 99;
    if (!strcmp(argv[1], "read")) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) return 20;
        char buf[128]; ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) write(STDOUT_FILENO, buf, n);
        close(fd); return 0;
    }
    if (!strcmp(argv[1], "write")) {
        int fd = open(argv[2], O_WRONLY | O_TRUNC);
        if (fd < 0) return 21;
        int ok = write(fd, "changed", 7) == 7; close(fd); return ok ? 0 : 22;
    }
    if (!strcmp(argv[1], "create")) {
        int fd = open(argv[2], O_WRONLY | O_CREAT, 0600);
        if (fd < 0) return 23;
        close(fd); return 0;
    }
    if (!strcmp(argv[1], "exec")) {
        execl(argv[2], argv[2], (char *)NULL); return 24;
    }
    if (!strcmp(argv[1], "reserved-exit")) { fprintf(stderr, "%s", getenv("TEST_SECRET")); return 125; }
    if (!strcmp(argv[1], "socket")) return socket(AF_INET, SOCK_STREAM, 0) < 0 ? 25 : 0;
    if (!strcmp(argv[1], "fork")) {
        int count = 0;
        while (count < 32) {
            pid_t child = fork();
            if (child < 0) { printf("limited:%d\n", count); return errno == EAGAIN ? 0 : 26; }
            if (child == 0) { wait_for_cleanup(); }
            count++;
        }
        return 27;
    }
    if (!strcmp(argv[1], "sleep")) { wait_for_cleanup(); }
    if (!strcmp(argv[1], "memory")) {
        for (;;) {
            volatile unsigned char *p = malloc(1024 * 1024);
            if (!p) { puts("limited"); return 0; }
            for (int i = 0; i < 1024 * 1024; i += 4096) p[i] = 1;
        }
    }
    return 98;
}
