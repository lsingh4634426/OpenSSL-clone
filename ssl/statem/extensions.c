/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl_locl.h"
#include "statem_locl.h"

static int tls_ext_final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al);
static int tls_ext_init_server_name(SSL *s, unsigned int context);
static int tls_ext_final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al);
#ifndef OPENSSL_NO_EC
static int tls_ext_final_ec_pt_formats(SSL *s, unsigned int context, int sent,
                                       int *al);
#endif
static int tls_ext_init_session_ticket(SSL *s, unsigned int context);
static int tls_ext_init_status_request(SSL *s, unsigned int context);
static int tls_ext_final_status_request(SSL *s, unsigned int context, int sent,
                                        int *al);
#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_ext_init_npn(SSL *s, unsigned int context);
#endif
static int tls_ext_init_alpn(SSL *s, unsigned int context);
static int tls_ext_final_alpn(SSL *s, unsigned int context, int sent, int *al);
static int tls_ext_init_sig_algs(SSL *s, unsigned int context);
#ifndef OPENSSL_NO_SRP
static int tls_ext_init_srp(SSL *s, unsigned int context);
#endif
static int tls_ext_init_etm(SSL *s, unsigned int context);
static int tls_ext_init_ems(SSL *s, unsigned int context);
static int tls_ext_final_ems(SSL *s, unsigned int context, int sent, int *al);
#ifndef OPENSSL_NO_SRTP
static int tls_ext_init_srtp(SSL *s, unsigned int context);
#endif

/* Structure to define a built-in extension */
typedef struct {
    /* The ID for the extension */
    unsigned int type;
    /*
     * Initialise extension before parsing. Always called for relevant contexts
     * even if extension not present
     */
    int (*init_ext)(SSL *s, unsigned int context);
    /* Parse extension received by server from client */
    int (*parse_client_ext)(SSL *s, PACKET *pkt, int *al);
    /* Parse extension received by client from server */
    int (*parse_server_ext)(SSL *s, PACKET *pkt, int *al);
    /* Construct extension sent by server */
    int (*construct_server_ext)(SSL *s, WPACKET *pkt, int *al);
    /* Construct extension sent by client */
    int (*construct_client_ext)(SSL *s, WPACKET *pkt, int *al);
    /*
     * Finalise extension after parsing. Always called where an extensions was
     * initialised even if the extension was not present. |sent| is set to 1 if
     * the extension was seen, or 0 otherwise.
     */
    int (*finalise_ext)(SSL *s, unsigned int context, int sent, int *al);
    unsigned int context;
} EXTENSION_DEFINITION;

/*
 * Definitions of all built-in extensions. NOTE: Changes in the number or order
 * of these extensions should be mirrored with equivalent changes to the indexes
 * defined in statem_locl.h.
 * Each extension has an initialiser, a client and
 * server side parser and a finaliser. The initialiser is called (if the
 * extension is relevant to the given context) even if we did not see the
 * extension in the message that we received. The parser functions are only
 * called if we see the extension in the message. The finalisers are always
 * called if the initialiser was called.
 * There are also server and client side constructor functions which are always
 * called during message construction if the extension is relevant for the
 * given context.
 * The initialisation, parsing, finalisation and construction functions are
 * always called in the order defined in this list. Some extensions may depend
 * on others having been processed first, so the order of this list is
 * significant.
 * The extension context is defined by a series of flags which specify which
 * messages the extension is relevant to. These flags also specify whether the
 * extension is relevant to a paricular protocol or protocol version.
 * 
 * TODO(TLS1.3): Make sure we have a test to check the consistency of these
 */
static const EXTENSION_DEFINITION ext_defs[] = {
    {
        TLSEXT_TYPE_renegotiate,
        NULL,
        tls_parse_client_renegotiate,
        tls_parse_server_renegotiate,
        tls_construct_server_renegotiate,
        tls_construct_client_renegotiate,
        tls_ext_final_renegotiate,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_SSL3_ALLOWED
        | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_server_name,
        tls_ext_init_server_name,
        tls_parse_client_server_name,
        tls_parse_server_server_name,
        tls_construct_server_server_name,
        tls_construct_client_server_name,
        tls_ext_final_server_name,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#ifndef OPENSSL_NO_SRP
    {
        TLSEXT_TYPE_srp,
        tls_ext_init_srp,
        tls_parse_client_srp,
        NULL,
        NULL,
        tls_construct_client_srp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
#ifndef OPENSSL_NO_EC
    {
        TLSEXT_TYPE_ec_point_formats,
        NULL,
        tls_parse_client_ec_pt_formats,
        tls_parse_server_ec_pt_formats,
        tls_construct_server_ec_pt_formats,
        tls_construct_client_ec_pt_formats,
        tls_ext_final_ec_pt_formats,
        EXT_CLIENT_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_groups,
        NULL,
        tls_parse_client_supported_groups,
        NULL,
        NULL /* TODO(TLS1.3): Need to add this */,
        tls_construct_client_supported_groups,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#endif
    {
        TLSEXT_TYPE_session_ticket,
        tls_ext_init_session_ticket,
        tls_parse_client_session_ticket,
        tls_parse_server_session_ticket,
        tls_construct_server_session_ticket,
        tls_construct_client_session_ticket,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_signature_algorithms,
        tls_ext_init_sig_algs,
        tls_parse_client_sig_algs,
        NULL,
        NULL,
        tls_construct_client_sig_algs,
        NULL,
        EXT_CLIENT_HELLO
    },
#ifndef OPENSSL_NO_OCSP
    {
        TLSEXT_TYPE_status_request,
        tls_ext_init_status_request,
        tls_parse_client_status_request,
        tls_parse_server_status_request,
        tls_construct_server_status_request,
        tls_construct_client_status_request,
        tls_ext_final_status_request,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE
    },
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
    {
        TLSEXT_TYPE_next_proto_neg,
        tls_ext_init_npn,
        tls_parse_client_npn,
        tls_parse_server_npn,
        tls_construct_server_next_proto_neg,
        tls_construct_client_npn,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#endif
    {
        /*
         * Must appear in this list after server_name so that finalisation
         * happens after server_name callbacks
         */
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        tls_ext_init_alpn,
        tls_parse_client_alpn,
        tls_parse_server_alpn,
        tls_construct_server_alpn,
        tls_construct_client_alpn,
        tls_ext_final_alpn,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS
    },
#ifndef OPENSSL_NO_SRTP
    {
        TLSEXT_TYPE_use_srtp,
        tls_ext_init_srtp,
        tls_parse_client_use_srtp,
        tls_parse_server_use_srtp,
        tls_construct_server_use_srtp,
        tls_construct_client_use_srtp,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_ENCRYPTED_EXTENSIONS | EXT_DTLS_ONLY
    },
#endif
    {
        TLSEXT_TYPE_encrypt_then_mac,
        tls_ext_init_etm,
        tls_parse_client_etm,
        tls_parse_server_etm,
        tls_construct_server_etm,
        tls_construct_client_etm,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
#ifndef OPENSSL_NO_CT
    {
        TLSEXT_TYPE_signed_certificate_timestamp,
        NULL,
        /*
         * No server side support for this, but can be provided by a custom
         * extension. This is an exception to the rule that custom extensions
         * cannot override built in ones.
         */
        NULL,
        tls_parse_server_sct,
        NULL,
        tls_construct_client_sct,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO
        | EXT_TLS1_3_CERTIFICATE
    },
#endif
    {
        TLSEXT_TYPE_extended_master_secret,
        tls_ext_init_ems,
        tls_parse_client_ems,
        tls_parse_server_ems,
        tls_construct_server_ems,
        tls_construct_client_ems,
        tls_ext_final_ems,
        EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        TLSEXT_TYPE_supported_versions,
        NULL,
        /* Processed inline as part of version selection */
        NULL,
        NULL,
        NULL,
        tls_construct_client_supported_versions,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS_IMPLEMENTATION_ONLY | EXT_TLS1_3_ONLY
    },
    {
        /*
         * Must be in this list after supported_groups. We need that to have
         * been parsed before we do this one.
         */
        TLSEXT_TYPE_key_share,
        NULL,
        tls_parse_client_key_share,
        tls_parse_server_key_share,
        tls_construct_server_key_share,
        tls_construct_client_key_share,
        NULL,
        EXT_CLIENT_HELLO | EXT_TLS1_3_SERVER_HELLO
        | EXT_TLS1_3_HELLO_RETRY_REQUEST | EXT_TLS_IMPLEMENTATION_ONLY
        | EXT_TLS1_3_ONLY
    },
    {
        /*
         * Special unsolicited ServerHello extension only used when
         * SSL_OP_CRYPTOPRO_TLSEXT_BUG is set
         */
        TLSEXT_TYPE_cryptopro_bug,
        NULL,
        NULL,
        NULL,
        tls_construct_server_cryptopro_bug,
        NULL,
        NULL,
        EXT_TLS1_2_SERVER_HELLO | EXT_TLS1_2_AND_BELOW_ONLY
    },
    {
        /* Last in the list because it must be added as the last extension */
        TLSEXT_TYPE_padding,
        NULL,
        /* We send this, but don't read it */
        NULL,
        NULL,
        NULL,
        tls_construct_client_padding,
        NULL,
        EXT_CLIENT_HELLO
    }
};

/*
 * Verify whether we are allowed to use the extension |type| in the current
 * |context|. Returns 1 to indicate the extension is allowed or unknown or 0 to
 * indicate the extension is not allowed. If returning 1 then |*found| is set to
 * 1 if we found a definition for the extension, and |*idx| is set to its index
 */
static int verify_extension(SSL *s, unsigned int context, unsigned int type,
                            custom_ext_methods *meths, int *found, size_t *idx)
{
    size_t i;
    size_t builtin_num = OSSL_NELEM(ext_defs);

    for (i = 0; i < builtin_num; i++) {
        if (type == ext_defs[i].type) {
            /* Check we're allowed to use this extension in this context */
            if ((context & ext_defs[i].context) == 0)
                return 0;

            if (SSL_IS_DTLS(s)) {
                if ((ext_defs[i].context & EXT_TLS_ONLY) != 0)
                    return 0;
            } else if ((ext_defs[i].context & EXT_DTLS_ONLY) != 0) {
                    return 0;
            }

            *found = 1;
            *idx = i;
            return 1;
        }
    }

    if ((context & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) == 0) {
        /*
         * Custom extensions only apply to <=TLS1.2. This extension is unknown
         * in this context - we allow it
         */
        *found = 0;
        return 1;
    }

    /* Check the custom extensions */
    if (meths != NULL) {
        for (i = builtin_num; i < builtin_num + meths->meths_count; i++) {
            if (meths->meths[i - builtin_num].ext_type == type) {
                *found = 1;
                *idx = i;
                return 1;
            }
        }
    }

    /* Unknown extension. We allow it */
    *found = 0;
    return 1;
}

/*
 * Check whether the context defined for an extension |extctx| means whether
 * the extension is relevant for the current context |thisctx| or not. Returns
 * 1 if the extension is relevant for this context, and 0 otherwise
 */
static int extension_is_relevant(SSL *s, unsigned int extctx,
                                 unsigned int thisctx)
{
    if ((SSL_IS_DTLS(s)
                && (extctx & EXT_TLS_IMPLEMENTATION_ONLY) != 0)
            || (s->version == SSL3_VERSION
                    && (extctx & EXT_SSL3_ALLOWED) == 0)
            || (SSL_IS_TLS13(s)
                && (extctx & EXT_TLS1_2_AND_BELOW_ONLY) != 0)
            || (!SSL_IS_TLS13(s) && (extctx & EXT_TLS1_3_ONLY) != 0))
        return 0;

    return 1;
}

/*
 * Gather a list of all the extensions from the data in |packet]. |context|
 * tells us which message this extension is for. The raw extension data is
 * stored in |*res|. In the event of an error the alert type to use is stored in
 * |*al|. We don't actually process the content of the extensions yet, except to
 * check their types. This function also runs the initialiser functions for all
 * known extensions (whether we have collected them or not).
 *
 * Per http://tools.ietf.org/html/rfc5246#section-7.4.1.4, there may not be
 * more than one extension of the same type in a ClientHello or ServerHello.
 * This function returns 1 if all extensions are unique and we have parsed their
 * types, and 0 if the extensions contain duplicates, could not be successfully
 * collected, or an internal error occurred. We only check duplicates for
 * extensions that we know about. We ignore others.
 */
int tls_collect_extensions(SSL *s, PACKET *packet, unsigned int context,
                           RAW_EXTENSION **res, int *al)
{
    PACKET extensions = *packet;
    size_t i = 0, idx;
    int found = 0;
    custom_ext_methods *exts = NULL;
    RAW_EXTENSION *raw_extensions = NULL;

    /*
     * Initialise server side custom extensions. Client side is done during
     * construction of extensions for the ClientHello.
     */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        exts = &s->cert->srv_ext;
        custom_ext_init(&s->cert->srv_ext);
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        exts = &s->cert->cli_ext;
    }

    raw_extensions = OPENSSL_zalloc((OSSL_NELEM(ext_defs)
                                     + (exts != NULL ? exts->meths_count : 0))
                                     * sizeof(RAW_EXTENSION));
    if (raw_extensions == NULL) {
        *al = SSL_AD_INTERNAL_ERROR;
        SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    while (PACKET_remaining(&extensions) > 0) {
        unsigned int type;
        PACKET extension;

        if (!PACKET_get_net_2(&extensions, &type) ||
            !PACKET_get_length_prefixed_2(&extensions, &extension)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *al = SSL_AD_DECODE_ERROR;
            goto err;
        }
        /*
         * Verify this extension is allowed. We only check duplicates for
         * extensions that we recognise.
         */
        if (!verify_extension(s, context, type, exts, &found, &idx)
                || (found == 1
                    && raw_extensions[idx].present == 1)) {
            SSLerr(SSL_F_TLS_COLLECT_EXTENSIONS, SSL_R_BAD_EXTENSION);
            *al = SSL_AD_ILLEGAL_PARAMETER;
            goto err;
        }
        if (found) {
            raw_extensions[idx].data = extension;
            raw_extensions[idx].present = 1;
            raw_extensions[idx].type = type;
        }
    }

    /*
     * Initialise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (i = 0; i < OSSL_NELEM(ext_defs); i++) {
        if(ext_defs[i].init_ext != NULL && (ext_defs[i].context & context) != 0
                && extension_is_relevant(s, ext_defs[i].context, context)
                && !ext_defs[i].init_ext(s, context)) {
            *al = SSL_AD_INTERNAL_ERROR;
            goto err;
        }
    }

    *res = raw_extensions;
    return 1;

 err:
    OPENSSL_free(raw_extensions);
    return 0;
}

/*
 * Runs the parser for a given extension with index |idx|. |exts| contains the
 * list of all parsed extensions previously collected by
 * tls_collect_extensions(). The parser is only run if it is applicable for the
 * given |context| and the parser has not already been run. Returns 1 on success
 * or 0 on failure. In the event of a failure |*al| is populated with a suitable
 * alert code. If an extension is not present this counted as success.
 */
int tls_parse_extension(SSL *s, unsigned int idx, int context,
                        RAW_EXTENSION *exts, int *al)
{
    RAW_EXTENSION *currext = &exts[idx];
    int (*parser)(SSL *s, PACKET *pkt, int *al) = NULL;

    /* Skip if the extension is not present */
    if (!currext->present)
        return 1;

    if (s->tlsext_debug_cb)
        s->tlsext_debug_cb(s, !s->server, currext->type,
                           PACKET_data(&currext->data),
                           PACKET_remaining(&currext->data),
                           s->tlsext_debug_arg);

    /* Skip if we've already parsed this extension */
    if (currext->parsed)
        return 1;

    currext->parsed = 1;

    if (idx < OSSL_NELEM(ext_defs)) {
        /* We are handling a built-in extension */
        const EXTENSION_DEFINITION *extdef = &ext_defs[idx];

        /* Check if extension is defined for our protocol. If not, skip */
        if (!extension_is_relevant(s, extdef->context, context))
            return 1;

        parser = s->server ? extdef->parse_client_ext : extdef->parse_server_ext;

        if (parser != NULL) {
            if (!parser(s, &currext->data, al))
                return 0;

            return 1;
        }

        /*
         * If the parser is NULL we fall through to the custom extension
         * processing
         */
    }

    /*
     * This is a custom extension. We only allow this if it is a non
     * resumed session on the server side.
     *
     * TODO(TLS1.3): We only allow old style <=TLS1.2 custom extensions.
     * We're going to need a new mechanism for TLS1.3 to specify which
     * messages to add the custom extensions to.
     */
    if ((!s->hit || !s->server)
            && (context
                & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) != 0
            && custom_ext_parse(s, s->server, currext->type,
                                PACKET_data(&currext->data),
                                PACKET_remaining(&currext->data),
                                al) <= 0)
        return 0;

    return 1;
}

/*
 * Parse all remaining extensions that have not yet been parsed. Also calls the
 * finalisation for all extensions at the end, whether we collected them or not.
 * Returns 1 for success or 0 for failure. On failure, |*al| is populated with a
 * suitable alert code.
 */
int tls_parse_all_extensions(SSL *s, int context, RAW_EXTENSION *exts, int *al)
{
    size_t loop, numexts = OSSL_NELEM(ext_defs);

    /* Calculate the number of extensions in the extensions list */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        numexts += s->cert->srv_ext.meths_count;
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        numexts += s->cert->cli_ext.meths_count;
    }

    /* Parse each extension in turn */
    for (loop = 0; loop < numexts; loop++) {
        if (!tls_parse_extension(s, loop, context, exts, al))
            return 0;
    }

    /*
     * Finalise all known extensions relevant to this context, whether we have
     * found them or not
     */
    for (loop = 0; loop < OSSL_NELEM(ext_defs); loop++) {
        if(ext_defs[loop].finalise_ext != NULL
                && (ext_defs[loop].context & context) != 0
                && !ext_defs[loop].finalise_ext(s, context, exts[loop].present,
                                                al))
            return 0;
    }

    return 1;
}

/*
 * Construct all the extensions relevant to the current |context| and write
 * them to |pkt|. Returns 1 on success or 0 on failure. If a failure occurs then
 * |al| is populated with a suitable alert code.
 */
int tls_construct_extensions(SSL *s, WPACKET *pkt, unsigned int context,
                             int *al)
{
    size_t loop;
    int addcustom = 0;
    int min_version, max_version = 0, reason, tmpal;

    /*
     * Normally if something goes wrong during construction it's an internal
     * error. We can always override this later.
     */
    tmpal = SSL_AD_INTERNAL_ERROR;

    if (!WPACKET_start_sub_packet_u16(pkt)
               /*
                * If extensions are of zero length then we don't even add the
                * extensions length bytes to a ClientHello/ServerHello in SSLv3
                */
            || ((context & (EXT_CLIENT_HELLO | EXT_TLS1_2_SERVER_HELLO)) != 0
               && s->version == SSL3_VERSION
               && !WPACKET_set_flags(pkt,
                                     WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH))) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if ((context & EXT_CLIENT_HELLO) != 0) {
        reason = ssl_get_client_min_max_version(s, &min_version, &max_version);
        if (reason != 0) {
            SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, reason);
            goto err;
        }
    }

    /* Add custom extensions first */
    if ((context & EXT_CLIENT_HELLO) != 0) {
        custom_ext_init(&s->cert->cli_ext);
        addcustom = 1;
    } else if ((context & EXT_TLS1_2_SERVER_HELLO) != 0) {
        /*
         * We already initialised the custom extensions during ClientHello
         * parsing.
         * 
         * TODO(TLS1.3): We're going to need a new custom extension mechanism
         * for TLS1.3, so that custom extensions can specify which of the
         * multiple message they wish to add themselves to.
         */
        addcustom = 1;
    }

    if (addcustom && !custom_ext_add(s, s->server, pkt, &tmpal)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    for (loop = 0; loop < OSSL_NELEM(ext_defs); loop++) {
        int (*construct)(SSL *s, WPACKET *pkt, int *al);

        /* Skip if not relevant for our context */
        if ((ext_defs[loop].context & context) == 0)
            continue;

        construct = s->server ? ext_defs[loop].construct_server_ext
                              : ext_defs[loop].construct_client_ext;

        /* Check if this extension is defined for our protocol. If not, skip */
        if ((SSL_IS_DTLS(s)
                    && (ext_defs[loop].context & EXT_TLS_IMPLEMENTATION_ONLY)
                       != 0)
                || (s->version == SSL3_VERSION
                        && (ext_defs[loop].context & EXT_SSL3_ALLOWED) == 0)
                || (SSL_IS_TLS13(s)
                    && (ext_defs[loop].context & EXT_TLS1_2_AND_BELOW_ONLY)
                       != 0)
                || (!SSL_IS_TLS13(s)
                    && (ext_defs[loop].context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) == 0)
                || ((ext_defs[loop].context & EXT_TLS1_3_ONLY) != 0
                    && (context & EXT_CLIENT_HELLO) != 0
                    && (SSL_IS_DTLS(s) || max_version < TLS1_3_VERSION))
                || construct == NULL)
            continue;

        if (!construct(s, pkt, &tmpal))
            goto err;
    }

    if (!WPACKET_close(pkt)) {
        SSLerr(SSL_F_TLS_CONSTRUCT_EXTENSIONS, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    return 1;

 err:
    *al = tmpal;
    return 0;
}

/*
 * Built in extension finalisation and initialisation functions. All initialise
 * or finalise the associated extension type for the given |context|. For
 * finalisers |sent| is set to 1 if we saw the extension during parsing, and 0
 * otherwise. These functions return 1 on success or 0 on failure. In the event
 * of a failure then |*al| is populated with a suitable error code.
 */

static int tls_ext_final_renegotiate(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    if (!s->server) {
        /*
         * Check if we can connect to a server that doesn't support safe
         * renegotiation
         */
        if (!(s->options & SSL_OP_LEGACY_SERVER_CONNECT)
                && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
                && !sent) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_EXT_FINAL_RENEGOTIATE,
                   SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
            return 0;
        }

        return 1;
    }

    /* Need RI if renegotiating */
    if (s->renegotiate
            && !(s->options & SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION)
            && !sent) {
        *al = SSL_AD_HANDSHAKE_FAILURE;
        SSLerr(SSL_F_TLS_EXT_FINAL_RENEGOTIATE,
               SSL_R_UNSAFE_LEGACY_RENEGOTIATION_DISABLED);
        return 0;
    }


    return 1;
}

static int tls_ext_init_server_name(SSL *s, unsigned int context)
{
    if (s->server)
        s->servername_done = 0;

    return 1;
}

static int tls_ext_final_server_name(SSL *s, unsigned int context, int sent,
                                     int *al)
{
    int ret = SSL_TLSEXT_ERR_NOACK;
    int altmp = SSL_AD_UNRECOGNIZED_NAME;

    if (s->ctx != NULL && s->ctx->tlsext_servername_callback != 0)
        ret = s->ctx->tlsext_servername_callback(s, &altmp,
                                                 s->ctx->tlsext_servername_arg);
    else if (s->initial_ctx != NULL
             && s->initial_ctx->tlsext_servername_callback != 0)
        ret = s->initial_ctx->tlsext_servername_callback(s, &altmp,
                                       s->initial_ctx->tlsext_servername_arg);

    switch (ret) {
    case SSL_TLSEXT_ERR_ALERT_FATAL:
        *al = altmp;
        return 0;

    case SSL_TLSEXT_ERR_ALERT_WARNING:
        *al = altmp;
        return 1;

    case SSL_TLSEXT_ERR_NOACK:
        s->servername_done = 0;
        return 1;

    default:
        return 1;
    }
}

#ifndef OPENSSL_NO_EC
static int tls_ext_final_ec_pt_formats(SSL *s, unsigned int context, int sent,
                                       int *al)
{
    unsigned long alg_k, alg_a;

    if (s->server)
        return 1;

    alg_k = s->s3->tmp.new_cipher->algorithm_mkey;
    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    /*
     * If we are client and using an elliptic curve cryptography cipher
     * suite, then if server returns an EC point formats lists extension it
     * must contain uncompressed.
     */
    if ((s->tlsext_ecpointformatlist != NULL)
        && (s->tlsext_ecpointformatlist_length > 0)
        && (s->session->tlsext_ecpointformatlist != NULL)
        && (s->session->tlsext_ecpointformatlist_length > 0)
        && ((alg_k & SSL_kECDHE) || (alg_a & SSL_aECDSA))) {
        /* we are using an ECC cipher */
        size_t i;
        unsigned char *list;
        int found_uncompressed = 0;
        list = s->session->tlsext_ecpointformatlist;
        for (i = 0; i < s->session->tlsext_ecpointformatlist_length; i++) {
            if (*(list++) == TLSEXT_ECPOINTFORMAT_uncompressed) {
                found_uncompressed = 1;
                break;
            }
        }
        if (!found_uncompressed) {
            SSLerr(SSL_F_TLS_EXT_FINAL_EC_PT_FORMATS,
                   SSL_R_TLS_INVALID_ECPOINTFORMAT_LIST);
            return 0;
        }
    }

    return 1;
}
#endif

static int tls_ext_init_session_ticket(SSL *s, unsigned int context)
{
    if (!s->server)
        s->tlsext_ticket_expected = 0;

    return 1;
}

static int tls_ext_init_status_request(SSL *s, unsigned int context)
{
    if (s->server)
        s->tlsext_status_type = -1;

    return 1;
}

static int tls_ext_final_status_request(SSL *s, unsigned int context, int sent,
                                        int *al)
{
    if (s->server)
        return 1;

    /*
     * Ensure we get sensible values passed to tlsext_status_cb in the event
     * that we don't receive a status message
     */
    OPENSSL_free(s->tlsext_ocsp_resp);
    s->tlsext_ocsp_resp = NULL;
    s->tlsext_ocsp_resplen = 0;

    return 1;
}

#ifndef OPENSSL_NO_NEXTPROTONEG
static int tls_ext_init_npn(SSL *s, unsigned int context)
{
    s->s3->next_proto_neg_seen = 0;

    return 1;
}
#endif

static int tls_ext_init_alpn(SSL *s, unsigned int context)
{
    OPENSSL_free(s->s3->alpn_selected);
    s->s3->alpn_selected = NULL;
    if (s->server) {
        s->s3->alpn_selected_len = 0;
        OPENSSL_free(s->s3->alpn_proposed);
        s->s3->alpn_proposed = NULL;
        s->s3->alpn_proposed_len = 0;
    }
    return 1;
}

static int tls_ext_final_alpn(SSL *s, unsigned int context, int sent, int *al)
{
    const unsigned char *selected = NULL;
    unsigned char selected_len = 0;

    if (!s->server)
        return 1;

    if (s->ctx->alpn_select_cb != NULL && s->s3->alpn_proposed != NULL) {
        int r = s->ctx->alpn_select_cb(s, &selected, &selected_len,
                                       s->s3->alpn_proposed,
                                       (unsigned int)s->s3->alpn_proposed_len,
                                       s->ctx->alpn_select_cb_arg);

        if (r == SSL_TLSEXT_ERR_OK) {
            OPENSSL_free(s->s3->alpn_selected);
            s->s3->alpn_selected = OPENSSL_memdup(selected, selected_len);
            if (s->s3->alpn_selected == NULL) {
                *al = SSL_AD_INTERNAL_ERROR;
                return 0;
            }
            s->s3->alpn_selected_len = selected_len;
#ifndef OPENSSL_NO_NEXTPROTONEG
            /* ALPN takes precedence over NPN. */
            s->s3->next_proto_neg_seen = 0;
#endif
        } else {
            *al = SSL_AD_NO_APPLICATION_PROTOCOL;
            return 0;
        }
    }

    return 1;
}

static int tls_ext_init_sig_algs(SSL *s, unsigned int context)
{
    /* Clear any signature algorithms extension received */
    OPENSSL_free(s->s3->tmp.peer_sigalgs);
    s->s3->tmp.peer_sigalgs = NULL;

    return 1;
}

#ifndef OPENSSL_NO_SRP
static int tls_ext_init_srp(SSL *s, unsigned int context)
{
    OPENSSL_free(s->srp_ctx.login);
    s->srp_ctx.login = NULL;

    return 1;
}
#endif

static int tls_ext_init_etm(SSL *s, unsigned int context)
{
    s->s3->flags &= ~TLS1_FLAGS_ENCRYPT_THEN_MAC;

    return 1;
}

static int tls_ext_init_ems(SSL *s, unsigned int context)
{
    if (!s->server)
        s->s3->flags &= ~TLS1_FLAGS_RECEIVED_EXTMS;

    return 1;
}

static int tls_ext_final_ems(SSL *s, unsigned int context, int sent, int *al)
{
    if (!s->server && s->hit) {
        /*
         * Check extended master secret extension is consistent with
         * original session.
         */
        if (!(s->s3->flags & TLS1_FLAGS_RECEIVED_EXTMS) !=
            !(s->session->flags & SSL_SESS_FLAG_EXTMS)) {
            *al = SSL_AD_HANDSHAKE_FAILURE;
            SSLerr(SSL_F_TLS_EXT_FINAL_EMS, SSL_R_INCONSISTENT_EXTMS);
            return 0;
        }
    }

    return 1;
}

#ifndef OPENSSL_NO_SRTP
static int tls_ext_init_srtp(SSL *s, unsigned int context)
{
    if (s->server)
        s->srtp_profile = NULL;

    return 1;
}
#endif
