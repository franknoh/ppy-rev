/* Reports what a sandboxed program can do: its user, the network, and writable paths. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    printf("uid=%d\n", (int)getuid());
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(53);
    address.sin_addr.s_addr = htonl(0x01010101);
    int connected = sock < 0 ? -2 : connect(sock, (struct sockaddr *)&address, sizeof address);
    printf("connect=%d\n", connected);
    printf("write_root=%d\n", open("/probe", O_WRONLY | O_CREAT, 0600) >= 0);
    printf("write_mount=%d\n", open("/sandbox/probe", O_WRONLY | O_CREAT, 0600) >= 0);
    printf("argv=%d:%s\n", argc, argc > 1 ? argv[1] : "");
    char line[64];
    if (fgets(line, sizeof line, stdin)) {
        printf("stdin=%s", line);
    }
    fflush(stdout);
    if (argc > 2) {
        for (;;) {
        }
    }
    return 3;
}
