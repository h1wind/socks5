// socks5.c

#include "socks5.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <assert.h>

#include "event2/buffer.h"
#include "event2/util.h"

#include "debug.h"

#define SOCKS5_SESSION_TIMEOUT 15

enum {
    NEGOTIATE_AUTH_METHOD = 0x00,
    AUTHENTICATION,
    HANDLE_REQUEST,
};

static void event_cb(struct bufferevent *bufev, short what, void *ptr);

static int socks5_reply(socks5_session_t *session, uint8_t rep) {
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    unsigned char buf[] = {
        0x05,
        rep,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };

    if (evbuffer_add(bufferevent_get_output(session->source),
                     buf,
                     sizeof(buf)) != 0) {
        debug("evbuffer_add failed");
        return -1;
    }
    return 0;
}

static int negotiate_auth_method(socks5_session_t *session) {
    struct evbuffer *input;
    struct evbuffer *output;
    unsigned char buf[264];
    uint8_t nmethods;
    uint8_t *methods;
    ev_ssize_t n;
    bool auth = false;

    input = bufferevent_get_input(session->source);

    // +----+----------+----------+
    // |VER | NMETHODS | METHODS  |
    // +----+----------+----------+
    // | 1  |    1     | 1 to 255 |
    // +----+----------+----------+

    n = evbuffer_copyout(input, buf, 2);
    if (n < 2) {
        assert(n != -1);
        return 0;
    }

    if (buf[0] != 0x05) {
        debug("[socks5_session:%p] [version:0x%02x] no supported",
              session,
              buf[0]);
        return -1;
    }

    nmethods = buf[1];
    if (nmethods == 0) {
        debug("[socks5_session:%p] no authentication method", session);
        return -1;
    }

    n = evbuffer_copyout(input, buf, 2 + nmethods);
    if (n < (2 + nmethods)) {
        assert(n != -1);
        return 0;
    }

    evbuffer_drain(input, 2 + nmethods);

    methods = buf + 2;
    do {
        if (methods[--nmethods] == 0x02) { // X'02' USERNAME/PASSWORD
            auth = true;
            break;
        }
        debug("[socks5_session:%p] [methods:0x%02x]",
              session,
              methods[nmethods]);
    } while (nmethods != 0);

    output = bufferevent_get_output(session->source);
    buf[1] = auth ? 0x02 : 0xff;

    // +----+--------+
    // |VER | METHOD |
    // +----+--------+
    // | 1  |   1    |
    // +----+--------+

    if (evbuffer_add(output, buf, 2) != 0) {
        debug("evbuffer_add failed");
        return -1;
    }

    if (!auth) {
        debug("[socks5_session:%p] no supported authentication "
              "method",
              session);
        return -1;
    }

    session->step = AUTHENTICATION;

    return 0;
}

static int authentication(socks5_session_t *session) {
    socks5_server_t *server;
    struct evbuffer *input;
    struct evbuffer *output;
    unsigned char buf[520];
    uint8_t ulen;
    uint8_t plen;
    size_t size;
    ev_ssize_t n;
    const char *user;
    const char *pass;
    bool succ = false;

    input = bufferevent_get_input(session->source);

    // +----+------+----------+------+----------+
    // |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
    // +----+------+----------+------+----------+
    // | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
    // +----+------+----------+------+----------+
    size = 2; // version + ulen
    n = evbuffer_copyout(input, buf, size);
    if (n < 2) {
        assert(n != -1);
        return 0;
    }

    if (buf[0] != 0x01) {
        debug("[socks5_session:%p] unsupported authentication "
              "protocol "
              "[version:%d]",
              session,
              buf[0]);
        return -1;
    }

    // ver + ulen + user + plen
    ulen = buf[1];
    size += ulen + 1;

    n = evbuffer_copyout(input, buf, size);
    if (n < (ev_ssize_t)size) {
        assert(n != -1);
        return 0;
    }

    // add passwd
    plen = buf[2 + ulen];
    size += plen;

    n = evbuffer_copyout(input, buf, size);
    if (n < (ev_ssize_t)size) {
        assert(n != -1);
        return 0;
    }

    evbuffer_drain(input, size);

    user = (const char *)(buf + 2);
    pass = (const char *)(buf + 2 + ulen + 1);

    debug("[socks5_session:%p] [user:%.*s pass:%.*s]",
          session,
          ulen,
          user,
          plen,
          pass);

    server = session->server;

    if (ulen == server->ulen && plen == server->plen &&
        memcmp(user, server->user, ulen) == 0 &&
        memcmp(pass, server->pass, plen) == 0) {
        succ = true;
    }

    buf[1] = succ ? 0 : 1;
    output = bufferevent_get_output(session->source);

    //  +----+--------+
    //  |VER | STATUS |
    //  +----+--------+
    //  | 1  |   1    |
    //  +----+--------+
    if (evbuffer_add(output, buf, 2) != 0) {
        debug("evbuffer_add failed");
        return -1;
    }

    if (!succ) {
        debug("[socks5_session:%p] wrong username and password", session);
        return -1;
    }

    session->step = HANDLE_REQUEST;

    return 0;
}

static void parse_dest_address(socks5_session_t *session, const uint8_t *data) {
    uint8_t len;

    switch (session->atyp) {
    case 0x01: // IPv4
        evutil_inet_ntop(AF_INET,
                         data,
                         session->daddr.host,
                         sizeof(session->daddr.host));
        session->daddr.port = ntohs(*(uint16_t *)(data + 4));
        break;
    case 0x03: // Domain Name
        len = *data++;
        memcpy(session->daddr.host, data, len);
        session->daddr.host[len] = '\0';
        session->daddr.port = ntohs(*(uint16_t *)(data + len));
        break;
    case 0x04: // IPv6
        evutil_inet_ntop(AF_INET6,
                         data,
                         session->daddr.host,
                         sizeof(session->daddr.host));
        session->daddr.port = ntohs(*(uint16_t *)(data + 16));
        break;
    default:
        assert(false);
        break;
    }
}

static void socks5_session_close_source(socks5_session_t *session) {
    assert(session->source != NULL);
    bufferevent_setcb(session->source, NULL, NULL, NULL, NULL);
    debug("free [bufferevent:%p]", session, session->source);
    bufferevent_free(session->source);
    session->source = NULL;
}

static void socks5_session_close_dest(socks5_session_t *session) {
    assert(session->dest != NULL);
    bufferevent_setcb(session->dest, NULL, NULL, NULL, NULL);
    debug("free [bufferevent:%p]", session->dest);
    bufferevent_free(session->dest);
    session->dest = NULL;
}

static void socks5_session_close(socks5_session_t *session) {
    assert(session->source != NULL && session->dest != NULL);

    socks5_session_close_source(session);
    socks5_session_close_dest(session);

    debug("remove [socks5_session:%p] from sessions", session);
    LIST_REMOVE(session, entries);

    debug("free [socks5_session:%p]", session);
    free(session);
}

static void close_on_finished_write_cb(struct bufferevent *bufev, void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;

    if (evbuffer_get_length(bufferevent_get_output(bufev)) == 0) {
        if (bufev == session->source) {
            socks5_session_close_source(session);
        } else {
            socks5_session_close_dest(session);
        }
    }

    if (session->source == NULL && session->dest == NULL) {
        debug("remove [socks5_session:%p] from sessions", session);
        LIST_REMOVE(session, entries);

        debug("free [socks5_session:%p]", session);
        free(session);
    }
}

static void socks5_session_close_source_on_sented(socks5_session_t *session) {
    if (session->source == NULL)
        return;

    if (evbuffer_get_length(bufferevent_get_output(session->source)) == 0) {
        socks5_session_close_source(session);
        if (session->source == NULL && session->dest == NULL) {
            debug("remove [socks5_session:%p] from sessions", session);
            LIST_REMOVE(session, entries);

            debug("free [socks5_session:%p]", session);
            free(session);
        }
        return;
    }

    bufferevent_set_timeouts(session->source, NULL, NULL);
    bufferevent_setcb(session->source,
                      NULL,
                      close_on_finished_write_cb,
                      event_cb,
                      session);
}

static void socks5_session_close_dest_on_sented(socks5_session_t *session) {
    if (session->dest == NULL) {
        return;
    }

    if (evbuffer_get_length(bufferevent_get_output(session->dest)) == 0) {
        socks5_session_close_dest(session);
        if (session->source == NULL && session->dest == NULL) {
            debug("remove [socks5_session:%p] from sessions", session);
            LIST_REMOVE(session, entries);

            debug("free [socks5_session:%p]", session);
            free(session);
        }
        return;
    }

    bufferevent_set_timeouts(session->dest, NULL, NULL);
    bufferevent_setcb(session->dest,
                      NULL,
                      close_on_finished_write_cb,
                      event_cb,
                      session);
}

static void event_cb(struct bufferevent *bufev, short what, void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;

    assert(what & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT));

    debug("[socks5_session:%p] [error:%d eof:%d timeout:%d]",
          session,
          !!(what & BEV_EVENT_ERROR),
          !!(what & BEV_EVENT_EOF),
          !!(what & BEV_EVENT_TIMEOUT));

    if (what & BEV_EVENT_ERROR) {
        debug(evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (bufev == session->source) {
        debug("[socks5_session:%p] recv from source", session);
        socks5_session_close_source(session);
        socks5_session_close_dest_on_sented(session);
        return;
    }

    debug("[socks5_session:%p] recv from dest", session);
    socks5_session_close_dest(session);
    socks5_session_close_source_on_sented(session);
}

/* data forward */
static void copy_cb(struct bufferevent *bufev, void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;
    struct evbuffer *input;
    struct evbuffer *output;
    struct timeval tv;

    tv.tv_sec = SOCKS5_SESSION_TIMEOUT;
    tv.tv_usec = 0;

    if (bufev == session->source) {
        debug("[socks5_session:%p] copy data from [%s:%d] to "
              "[%s:%d]",
              session,
              session->saddr.host,
              session->saddr.port,
              session->daddr.host,
              session->daddr.port);
        bufferevent_set_timeouts(session->dest, &tv, NULL);
        input = bufferevent_get_input(session->source);
        output = bufferevent_get_output(session->dest);
    } else {
        debug("[socks5_session:%p] copy data from [%s:%d] to "
              "[%s:%d]",
              session,
              session->daddr.host,
              session->daddr.port,
              session->saddr.host,
              session->saddr.port);
        bufferevent_set_timeouts(session->source, &tv, NULL);
        input = bufferevent_get_input(session->dest);
        output = bufferevent_get_output(session->source);
    }

    if (evbuffer_add_buffer(output, input) != 0) {
        debug("evbuffer_add_buffer failed");
        socks5_session_close(session);
    }
}

static void dest_event_cb(struct bufferevent *bufev, short what, void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;
    struct timeval tv;
    uint8_t rep;
    int err;

    assert(what & (BEV_EVENT_CONNECTED | BEV_EVENT_ERROR));
    assert(bufev == session->dest);
    (void)bufev;

    if (what & BEV_EVENT_CONNECTED) {
        debug("[socks5_session:%p] connect to [%s:%d] success",
              session,
              session->daddr.host,
              session->daddr.port);

        tv.tv_sec = SOCKS5_SESSION_TIMEOUT;
        tv.tv_usec = 0;

        bufferevent_set_timeouts(session->source, &tv, NULL);
        bufferevent_setcb(session->source, copy_cb, NULL, event_cb, session);

        bufferevent_set_timeouts(session->dest, &tv, NULL);
        bufferevent_setcb(session->dest, copy_cb, NULL, event_cb, session);

        if (bufferevent_enable(session->dest, EV_READ) != 0) {
            debug("bufferevent_enable failed");
            if (socks5_reply(session, 0x01) != 0) {
                debug("socks5_reply failed");
                socks5_session_close(session);
                return;
            }
            socks5_session_close_dest(session);
            socks5_session_close_source_on_sented(session);
            return;
        }

        if (socks5_reply(session, 0x00) != 0) { // Success
            socks5_session_close(session);
            return;
        }
        return;
    }

    assert(what & BEV_EVENT_ERROR);

    debug("[socks5_session:%p] connect to [%s:%d] failed",
          session,
          session->daddr.host,
          session->daddr.port);

    rep = 0x00;

    if (session->atyp == 0x03) {
        err = bufferevent_socket_get_dns_error(session->dest);
        if (err != 0) {
            debug("bufferevent_socket_get_dns_error failed "
                  "error (%s)",
                  evutil_gai_strerror(err));
            rep = 0x01;
        }
    }

    if (rep == 0x00) {
        err = EVUTIL_SOCKET_ERROR();
        debug("[socks5_session:%p] connect failed, error (%s)",
              evutil_socket_error_to_string(err));
        switch (err) {
        case ENETUNREACH:
            rep = 0x03;
            break;
        case EHOSTUNREACH:
            rep = 0x04;
            break;
        case ECONNREFUSED:
            rep = 0x05;
            break;
        default:
            rep = 0x01;
            break;
        }
    }

    if (socks5_reply(session, rep) != 0) {
        debug("socks5_reply failed");
        socks5_session_close(session);
        return;
    }

    socks5_session_close_dest(session);
    socks5_session_close_source_on_sented(session);
}

static void wait_dest_connect_event_cb(struct bufferevent *bufev,
                                       short what,
                                       void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;

    assert(what & (BEV_EVENT_ERROR | BEV_EVENT_EOF | BEV_EVENT_TIMEOUT));
    assert(bufev == session->source);

    (void)bufev;
    (void)what;

    debug("[socks5_session:%p] [error:%d eof:%d timeout:%d]",
          session,
          !!(what & BEV_EVENT_ERROR),
          !!(what & BEV_EVENT_EOF),
          !!(what & BEV_EVENT_TIMEOUT));
    socks5_session_close(session);
}

/* connect to target */
static int socks5_connect(socks5_session_t *session) {
    struct sockaddr_storage ss;
    struct bufferevent *dest;
    struct event_base *base = session->server->event_base;
    struct evdns_base *evdns_base = session->server->evdns_base;
    char str[512];
    int ss_len;
    int ret;

    snprintf(str,
             sizeof(str),
             "%s:%d",
             session->daddr.host,
             session->daddr.port);
    debug("[socks5_session:%p] connect to [%s] ...", session, str);

    dest = bufferevent_socket_new(base,
                                  -1,
                                  BEV_OPT_CLOSE_ON_FREE |
                                      BEV_OPT_DEFER_CALLBACKS);
    if (dest == NULL) {
        debug("bufferevent_socket_new failed");
        if (socks5_reply(session, 0x01) != 0) {
            debug("socks5_reply failed");
        }
        return -1;
    }
    debug("new [bufferevent:%p]", dest);

    if (session->atyp == 0x03) { // Domain name
        ret = bufferevent_socket_connect_hostname(dest,
                                                  evdns_base,
                                                  AF_UNSPEC,
                                                  session->daddr.host,
                                                  session->daddr.port);
    } else {
        ss_len = sizeof(ss);
        ret = evutil_parse_sockaddr_port(str, (struct sockaddr *)&ss, &ss_len);
        assert(ret == 0);
        ret = bufferevent_socket_connect(dest, (struct sockaddr *)&ss, ss_len);
    }

    if (ret != 0) {
        debug("[socks5_session:%p] connect failed", session);
        debug("free [bufferevent:%p]", dest);
        bufferevent_free(dest);
        if (socks5_reply(session, 0x01) != 0) {
            debug("socks5_reply failed");
        }
        return -1;
    }

    bufferevent_set_timeouts(session->source, NULL, NULL);
    bufferevent_setcb(session->source,
                      NULL,
                      NULL,
                      wait_dest_connect_event_cb,
                      session);
    bufferevent_setcb(dest, NULL, NULL, dest_event_cb, session);

    session->dest = dest;

    return 0;
}

static int handle_request(socks5_session_t *session) {
    struct evbuffer *input;
    unsigned char buf[264];
    size_t size;
    ev_ssize_t n;

    input = bufferevent_get_input(session->source);

    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    size = 5; // ver + cmd + rsv + atyp + dn_len
    n = evbuffer_copyout(input, buf, size);
    if (n < (ev_ssize_t)size) {
        assert(n != -1);
        return 0;
    }

    debug("[socks5_session:%p] request [ver:0x%02x cmd:0x%02x "
          "rsv:0x%02x atyp:0x%02x]",
          session,
          buf[0],
          buf[1],
          buf[2],
          buf[3]);

    if (buf[0] != 0x05) {
        debug("[socks5_session:%p] [ver:0x%02x] no supported", session, buf[0]);
        return -1;
    }

    if (buf[2] != 0x00) {
        debug("[ssocks5_ession:%p] fields marked rsv must be set "
              "to 0x00",
              session);
        return -1;
    }

    session->cmd = buf[1];
    session->atyp = buf[3];

    switch (session->atyp) {
    case 0x01:
        size += 5;
        break;
    case 0x03:
        size += buf[4] + 2;
        break;
    case 0x04:
        size += 18;
        break;
    default:
        debug("[socks5_session:%p] address type not supported "
              "[atyp:0x%02x]",
              session,
              session->atyp);
        return socks5_reply(session, 0x08);
    }

    n = evbuffer_copyout(input, buf, size);
    if (n < (ev_ssize_t)size) {
        assert(n != -1);
        return 0;
    }

    evbuffer_drain(input, size);
    parse_dest_address(session, buf + 4);

    switch (session->cmd) {
    case 0x01: // CONNECT
        return socks5_connect(session);
    case 0x02: // BIND
    case 0x03: // UDP ASSOCIATE
    default:
        debug("[socks5_session:%p] [command:0x%02x] not supported",
              session,
              buf[1]);
        if (socks5_reply(session, 0x07) != 0) {
            debug("socks5_reply failed");
        }
        return -1;
    }
}

static void read_cb(struct bufferevent *bufev, void *ptr) {
    socks5_session_t *session = (socks5_session_t *)ptr;
    int ret = 0;

    (void)bufev;

    switch (session->step) {
    case NEGOTIATE_AUTH_METHOD:
        ret = negotiate_auth_method(session);
        break;
    case AUTHENTICATION:
        ret = authentication(session);
        break;
    case HANDLE_REQUEST:
        ret = handle_request(session);
        break;
    default:
        assert(false);
        break;
    }

    if (ret == 0) {
        return;
    }

    debug("[socks5_session:%p] error processing proxy request", session);
    assert(session->dest == NULL);

    bufferevent_set_timeouts(session->source, NULL, NULL);
    bufferevent_setcb(session->source,
                      NULL,
                      close_on_finished_write_cb,
                      event_cb,
                      session);
}

static void source_event_cb(struct bufferevent *bufev, short what, void *ctx) {
    socks5_session_t *session = (socks5_session_t *)ctx;

    assert(what & (BEV_EVENT_TIMEOUT | BEV_EVENT_ERROR | BEV_EVENT_EOF));
    assert(session->source == bufev);
    assert(session->dest == NULL);
    (void)bufev;
    (void)what;

    if (what & BEV_EVENT_TIMEOUT) {
        debug("[bufferevent:%p] timeout", session->source);
    }

    if (what & BEV_EVENT_ERROR) {
        debug("[bufferevent:%p] error (%s)",
              session->source,
              evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
    }

    if (what & BEV_EVENT_EOF) {
        debug("[bufferevent:%p] remote closed", session->source);
    }

    bufferevent_setcb(session->source, NULL, NULL, NULL, NULL);
    debug("free [bufferevent:%p]", session->source);
    bufferevent_free(session->source);

    debug("remove [socks5_session:%p] from sessions", session);
    LIST_REMOVE(session, entries);

    debug("free [socks5_session:%p]", session);
    free(session);
}

static void accept_cb(struct evconnlistener *listener,
                      evutil_socket_t sock,
                      struct sockaddr *sa,
                      int len,
                      void *ptr) {
    struct sockaddr_in6 *sin6;
    struct sockaddr_in *sin;
    socks5_session_t *session;
    socks5_server_t *server;
    struct event_base *base;
    struct bufferevent *source;
    struct timeval tv;

    (void)listener;
    (void)len;

    session = malloc(sizeof(socks5_session_t));
    if (session == NULL) {
        debug("malloc failed");
        evutil_closesocket(sock);
        return;
    }
    debug("new [socks5_session:%p]", session);

    memset(session, 0, sizeof(socks5_session_t));

    switch (sa->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *)sa;
        evutil_inet_ntop(AF_INET,
                         &sin->sin_addr,
                         session->saddr.host,
                         sizeof(session->saddr.host));
        session->saddr.port = ntohs(sin->sin_port);
        break;
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *)sa;
        evutil_inet_ntop(AF_INET,
                         &sin6->sin6_addr,
                         session->saddr.host,
                         sizeof(session->saddr.host));
        session->saddr.port = ntohs(sin6->sin6_port);
        break;
    default:
        assert(false);
        break;
    }

    debug("[socks5_session:%p] recv from [%s:%d]",
          session,
          session->saddr.host,
          session->saddr.port);

    server = (socks5_server_t *)ptr;
    base = server->event_base;

    source = bufferevent_socket_new(base,
                                    sock,
                                    BEV_OPT_CLOSE_ON_FREE |
                                        BEV_OPT_DEFER_CALLBACKS);
    if (source == NULL) {
        debug("bufferevent_socket_new failed");
        goto error_new_bufferevent;
    }
    debug("new [bufferevent:%p]", source);

    bufferevent_setcb(source, read_cb, NULL, source_event_cb, session);

    tv.tv_sec = SOCKS5_SESSION_TIMEOUT;
    tv.tv_usec = 0;

    bufferevent_set_timeouts(source, &tv, NULL);

    if (bufferevent_enable(source, EV_READ) != 0) {
        debug("bufferevent_enable failed");
        goto error_enable_read;
    }

    session->server = server;
    session->source = source;
    session->step = NEGOTIATE_AUTH_METHOD;

    debug("add [socks5_session:%p] to sessions", session);
    LIST_INSERT_HEAD(&server->sessions, session, entries);

    return;

error_enable_read:
    debug("free [bufferevent:%p]", source);
    bufferevent_free(source);
error_new_bufferevent:
    debug("free [socks5_session:%p]", session);
    free(session);
}

static void accept_error_cb(struct evconnlistener *listener, void *ptr) {
    socks5_server_t *server = (socks5_server_t *)ptr;
    socks5_session_t *session;
    socks5_session_t *tvar;

    (void)listener;

    debug("got an error (%s) on the listener. shutting down",
          evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));

    debug("free [evconnlistener:%p]", listener);
    evconnlistener_free(listener);

    LIST_FOREACH_SAFE (session, &server->sessions, entries, tvar) {
        debug("remove [socks5_session:%p] from sessions", session);
        LIST_REMOVE(session, entries);

        if (session->source != NULL) {
            socks5_session_close_source(session);
        }

        if (session->dest != NULL) {
            socks5_session_close_dest(session);
        }

        debug("free [socks5_session:%p]", session);
        free(session);
    }

    debug("[event_base:%p] loopexit", server, server->event_base);
    event_base_loopexit(server->event_base, NULL);
}

int socks5_server_init(socks5_server_t *server,
                       const char *address,
                       const char *user,
                       const char *pass,
                       const char *nameserver) {
    struct evconnlistener *listener;
    struct event_base *event_base;
    struct evdns_base *evdns_base;
    struct sockaddr_storage ss;
    int flag;
    int slen;

    slen = (int)sizeof(ss);
    if (evutil_parse_sockaddr_port(address, (struct sockaddr *)&ss, &slen) !=
        0) {
        debug("evutil_parse_sockaddr_port failed");
        return -1;
    }

    assert(strlen(address) < sizeof(server->address));
    memcpy(server->address, address, strlen(address) + 1);

    assert(user != NULL && pass != NULL);

    server->ulen = strlen(user);
    assert(server->ulen < sizeof(server->user));
    memcpy(server->user, user, server->ulen);

    server->plen = strlen(pass);
    assert(server->plen < sizeof(server->pass));
    memcpy(server->pass, pass, server->plen);

    LIST_INIT(&server->sessions);

    event_base = event_base_new();
    if (event_base == NULL) {
        debug("event_base_new failed");
        return -1;
    }
    debug("new [event_base:%p]", event_base);

    flag = (nameserver == NULL) ? 0 : 1;

    evdns_base = evdns_base_new(event_base, flag);
    if (evdns_base == NULL) {
        debug("evdns_base_new failed");
        goto error_new_evdns_base;
    }
    debug("new [evdns_base:%p]", evdns_base);

    if (!flag && evdns_base_nameserver_ip_add(evdns_base, nameserver) != 0) {
        debug("evdns_base_nameserver_ip_add failed");
        goto error_evdns_add_nameserver;
    }

    listener = evconnlistener_new_bind(
        event_base,
        accept_cb,
        server,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_REUSEABLE,
        -1,
        (struct sockaddr *)&ss,
        slen);
    if (listener == NULL) {
        debug("evconnlistener_new_bind failed");
        goto error_new_listener;
    }
    debug("new [evconnlistener:%p]", listener);

    evconnlistener_set_error_cb(listener, accept_error_cb);

    server->event_base = event_base;
    server->evdns_base = evdns_base;
    server->listener = listener;

    return 0;

error_new_listener:
    debug("free [evdns_base:%p]", evdns_base);
    evdns_base_free(evdns_base, 0);
error_evdns_add_nameserver:
error_new_evdns_base:
    debug("free [event_base:%p]", event_base);
    event_base_free(event_base);
    return -1;
}

void socks5_server_free(socks5_server_t *server) {
    socks5_session_t *session, *tvar;

    LIST_FOREACH_SAFE (session, &server->sessions, entries, tvar) {
        debug("remove [socks5_session:%p] from sessions", session);
        LIST_REMOVE(session, entries);

        if (session->source != NULL) {
            socks5_session_close_source(session);
        }

        if (session->dest != NULL) {
            socks5_session_close_dest(session);
        }

        debug("free [socks5_session:%p]", session);
        free(session);
    }

    debug("free [evconnlistener:%p]", server->listener);
    evconnlistener_free(server->listener);

    debug("free [evdns_base:%p]", server->evdns_base);
    evdns_base_free(server->evdns_base, 0);

    debug("free [event_base:%p]", server->event_base);
    event_base_free(server->event_base);
}

int socks5_server_run(socks5_server_t *server) {
    debug("socks5 server started, listen (%s) [user:%.*s "
          "pass:%.*s]",
          server->address,
          server->ulen,
          server->user,
          server->plen,
          server->pass);
    if (event_base_dispatch(server->event_base) == -1) {
        debug("event_base_dispatch failed");
        return -1;
    }
    return 0;
}
