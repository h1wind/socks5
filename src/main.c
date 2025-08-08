// main.c

#include <stdio.h>

#include "socks5.h"

int main(int argc, char *argv[]) {
    const char *nameserver = NULL;
    socks5_server_t server;

    if (argc < 4) {
        fprintf(stderr, "usage: socks5 <address> <user> <pass> [nameserver]\n");
        return -1;
    }

    if (argc > 4) {
        nameserver = argv[4];
    }

    printf("address: %s\n", argv[1]);
    printf("user: %s:***\n", argv[2]);

    socks5_server_init(&server, argv[1], argv[2], argv[3], nameserver);
    socks5_server_run(&server);
    socks5_server_free(&server);

    return 0;
}
