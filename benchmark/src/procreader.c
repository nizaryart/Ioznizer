/*
 * Benign control: a connection lister, roughly what `ss -t` does.
 *
 * Reads /proc/net/tcp and enumerates /proc for running processes - the exact
 * host-enumeration surface a bot uses to find targets or avoid detection.
 * The point of this control is that reading /proc is not by itself malicious;
 * every process monitor on the system does it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

static void list_tcp_connections(void) {
    char line[512];
    FILE *f = fopen("/proc/net/tcp", "r");

    if (!f) {
        perror("/proc/net/tcp");
        return;
    }

    printf("Active TCP connections:\n");
    /* Skip the header row. */
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return;
    }

    while (fgets(line, sizeof(line), f)) {
        unsigned int local_addr, local_port;
        if (sscanf(line, "%*d: %X:%X", &local_addr, &local_port) == 2) {
            printf("  local port %u\n", local_port);
        }
    }

    fclose(f);
}

static void list_processes(void) {
    struct dirent *entry;
    DIR *proc = opendir("/proc");
    int count = 0;

    if (!proc) {
        perror("/proc");
        return;
    }

    while ((entry = readdir(proc)) != NULL) {
        if (isdigit((unsigned char)entry->d_name[0])) {
            count++;
        }
    }

    closedir(proc);
    printf("Running processes: %d\n", count);
}

int main(void) {
    list_tcp_connections();
    list_processes();
    return 0;
}
