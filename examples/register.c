/* register.c
 * strophe XMPP client library -- In-band registration (XEP-0077)
 *
 * Copyright (C) 2016 Dmitry Podgorny <pasis.ua@gmail.com>
 *
 *  This software is provided AS-IS with no warranty, either express
 *  or implied.
 *
 *  This program is dual licensed under the MIT and GPLv3 licenses.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <strophe.h>

typedef struct {
    xmpp_ctx_t *ctx;
    const char *jid;
    const char *pass;
    const char *email;
} xmpp_reg_t;

#define FEATURES_TIMEOUT 5000 /* 5 seconds */
#define XMPP_NS_REGISTER "jabber:iq:register"

static int iq_reg_cb(xmpp_conn_t * const conn,
                     xmpp_stanza_t * const stanza,
                     void * const userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;

    (void)reg;
    fprintf(stderr, "DEBUG: iq_reg_cb\n");
    xmpp_disconnect(conn);

    return 0; /* XXX */
}

static int _handle_features(xmpp_conn_t * const conn,
                            xmpp_stanza_t * const stanza,
                            void * const userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;
    xmpp_ctx_t *ctx = reg->ctx;
    xmpp_stanza_t *child;
    xmpp_stanza_t *iq;
    char *domain;
    char *node;

    child = xmpp_stanza_get_child_by_name(stanza, "register");
    if (child && strcmp(xmpp_stanza_get_ns(child), XMPP_NS_REGISTER) == 0) {
        fprintf(stderr, "DEBUG: server doesn't support in-band registration\n");
        xmpp_disconnect(conn);
        return 0;
    }

    fprintf(stderr, "DEBUG: server supports in-band registration\n");
    domain = xmpp_jid_domain(ctx, reg->jid);
    node = xmpp_jid_node(ctx, reg->jid);
    iq = xmpp_iq_new(ctx, "get", "reg1");
    xmpp_stanza_set_to(iq, domain);
    child = xmpp_stanza_new(ctx);
    xmpp_stanza_set_name(child, "query");
    xmpp_stanza_set_ns(child, XMPP_NS_REGISTER);
    xmpp_stanza_add_child(iq, child);

    xmpp_handler_add(conn, iq_reg_cb, XMPP_NS_REGISTER, "iq", NULL, reg);
    xmpp_send(conn, iq);

    xmpp_free(ctx, node);
    xmpp_free(ctx, domain);
    xmpp_stanza_release(child);
    xmpp_stanza_release(iq);

    return 0;
}

static int _handle_error(xmpp_conn_t * const conn,
                         xmpp_stanza_t * const stanza,
                         void * const userdata)
{
    fprintf(stderr, "DEBUG: received stream error\n");
    xmpp_disconnect(conn);

    return 0;
}

static int _handle_missing_features(xmpp_conn_t * const conn,
                                    void * const userdata)
{
    fprintf(stderr, "DEBUG: timeout\n");
    xmpp_disconnect(conn);

    return 0;
}

static void conn_handler(xmpp_conn_t * const conn,
                         const xmpp_conn_event_t status,
                         const int error,
                         xmpp_stream_error_t * const stream_error,
                         void * const userdata)
{
    xmpp_reg_t *reg = (xmpp_reg_t *)userdata;
    int secured;

    if (status == XMPP_CONN_CONNECT) {
        fprintf(stderr, "DEBUG: connected\n");
        secured = xmpp_conn_is_secured(conn);
        fprintf(stderr, "DEBUG: connection is %s.\n",
                secured ? "secured" : "NOT secured");

        /* setup handler for stream:error */
        xmpp_handler_add(conn, _handle_error, XMPP_NS_STREAMS,
                         "error", NULL, NULL);

        /* setup handlers for incoming <stream:features> */
        xmpp_handler_add(conn, _handle_features, XMPP_NS_STREAMS,
                         "features", NULL, reg);
        xmpp_timed_handler_add(conn, _handle_missing_features,
                               FEATURES_TIMEOUT, NULL);
    }
    else {
        fprintf(stderr, "DEBUG: disconnected\n");
        xmpp_stop(reg->ctx);
    }
}

xmpp_reg_t *xmpp_reg_new(void)
{
    xmpp_reg_t *reg;

    reg = malloc(sizeof(*reg));
    if (reg != NULL) {
        memset(reg, 0, sizeof(*reg));
    }
    return reg;
}

void xmpp_reg_release(xmpp_reg_t *reg)
{
    free(reg);
}

int main(int argc, char **argv)
{
    xmpp_ctx_t *ctx;
    xmpp_conn_t *conn;
    xmpp_log_t *log;
    xmpp_reg_t *reg;
    const char *jid;
    const char *pass;
    const char *email;
    const char *host = NULL;
    long flags = 0;
    int i;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--disable-tls") == 0)
            flags |= XMPP_CONN_FLAG_DISABLE_TLS;
        else if (strcmp(argv[i], "--mandatory-tls") == 0)
            flags |= XMPP_CONN_FLAG_MANDATORY_TLS;
        else if (strcmp(argv[i], "--legacy-ssl") == 0)
            flags |= XMPP_CONN_FLAG_LEGACY_SSL;
        else
            break;
    }
    if ((argc - i) < 3 || (argc - i) > 4) {
        fprintf(stderr, "Usage: register [options] <jid> <pass> <email> [<host>]\n\n"
                        "Options:\n"
                        "  --disable-tls        Disable TLS.\n"
                        "  --mandatory-tls      Deny plaintext connection.\n"
                        "  --legacy-ssl         Use old style SSL.\n\n"
                        "Note: --disable-tls conflicts with --mandatory-tls or "
                              "--legacy-ssl\n");
        return 1;
    }

    jid = argv[i];
    pass = argv[i + 1];
    email = argv[i + 2];
    if (i + 3 < argc)
        host = argv[i + 3];

    /*
     * Note, this example doesn't handle errors. Applications should check
     * return values of non-void functions.
     */

    xmpp_initialize();
    log = xmpp_get_default_logger(XMPP_LEVEL_DEBUG);
    ctx = xmpp_ctx_new(NULL, log);
    conn = xmpp_conn_new(ctx);
    xmpp_conn_set_flags(conn, flags);
    xmpp_conn_set_jid(conn, jid);

    /* private data */
    reg = xmpp_reg_new();
    reg->ctx = ctx;
    reg->jid = jid;
    reg->pass = pass;
    reg->email = email;

    xmpp_connect_raw(conn, host, 0, conn_handler, reg);
    xmpp_run(ctx);

    /* release private data */
    xmpp_reg_release(reg);

    xmpp_conn_release(conn);
    xmpp_ctx_free(ctx);
    xmpp_shutdown();

    return 0;
}
