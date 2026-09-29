// Demo only: an intentionally vulnerable C packet handler used to showcase Armorix.
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

void log_packet(int fd) {
    char raw[512];
    char name[64];
    recv(fd, raw, sizeof raw, 0);
    strcpy(name, raw);
    printf(raw);
}

void backup(const char *file) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "tar czf /tmp/backup.tgz %s", file);  // file is trusted here
}
