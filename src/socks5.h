// socks5.h
// https://datatracker.ietf.org/doc/html/rfc1928
// https://datatracker.ietf.org/doc/html/rfc1929

#ifndef SOCKS5_H
#define SOCKS5_H

#include <stdbool.h>
#include <stdint.h>

#include "event2/bufferevent.h"
#include "event2/listener.h"
#include "event2/event.h"
#include "event2/dns.h"

#include "queue.h"

typedef struct socks5_server_s socks5_server_t;

typedef struct socks5_address_s {
    char host[256];
    uint16_t port;
} socks5_address_t;

typedef struct socks5_session_s {
    LIST_ENTRY(socks5_session_s) entries;
    socks5_server_t *server;
    socks5_address_t saddr;
    socks5_address_t daddr;
    struct bufferevent *source;
    struct bufferevent *dest;
    uint8_t cmd;
    uint8_t atyp;
    uint8_t step;
} socks5_session_t;

typedef LIST_HEAD(socks5_session_list, socks5_session_s) socks5_session_list_t;

struct socks5_server_s {
    socks5_session_list_t sessions;
    struct event_base *event_base;
    struct evdns_base *evdns_base;
    struct evconnlistener *listener;
    char address[512];
    size_t ulen;
    size_t plen;
    char user[256];
    char pass[256];
};

int socks5_server_init(socks5_server_t *server,
                       const char *address,
                       const char *user,
                       const char *pass,
                       const char *nameserver);
void socks5_server_free(socks5_server_t *server);
int socks5_server_run(socks5_server_t *server);

#endif // SOCKS5_H
