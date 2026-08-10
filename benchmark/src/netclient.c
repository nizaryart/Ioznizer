/*
 * Benign control: a minimal TCP client.
 *
 * Exercises the same primitives a backdoor uses - socket(), connect(),
 * send(), recv(), a hardcoded address - without doing anything malicious.
 * A analyser that flags this as a backdoor is pattern-matching on API calls
 * rather than reading behaviour.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 8080

int main(int argc, char **argv) {
    struct sockaddr_in addr;
    char request[128];
    char response[512];
    int sock;
    ssize_t n;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "could not connect to %s:%d\n", SERVER_IP, SERVER_PORT);
        close(sock);
        return 1;
    }

    snprintf(request, sizeof(request),
             "GET /status HTTP/1.0\r\nHost: %s\r\n\r\n", SERVER_IP);

    if (send(sock, request, strlen(request), 0) < 0) {
        perror("send");
        close(sock);
        return 1;
    }

    n = recv(sock, response, sizeof(response) - 1, 0);
    if (n > 0) {
        response[n] = '\0';
        printf("%s", response);
    }

    close(sock);
    return 0;
}
