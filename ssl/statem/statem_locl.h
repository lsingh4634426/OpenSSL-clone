/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*****************************************************************************
 *                                                                           *
 * The following definitions are PRIVATE to the state machine. They should   *
 * NOT be used outside of the state machine.                                 *
 *                                                                           *
 *****************************************************************************/

/* Max message length definitions */

/* The spec allows for a longer length than this, but we limit it */
#define HELLO_VERIFY_REQUEST_MAX_LENGTH 258
#define SERVER_HELLO_MAX_LENGTH         20000
#define HELLO_RETRY_REQUEST_MAX_LENGTH  20000
#define ENCRYPTED_EXTENSIONS_MAX_LENGTH 20000
#define SERVER_KEY_EXCH_MAX_LENGTH      102400
#define SERVER_HELLO_DONE_MAX_LENGTH    0
#define KEY_UPDATE_MAX_LENGTH           1
#define CCS_MAX_LENGTH                  1
/* Max should actually be 36 but we are generous */
#define FINISHED_MAX_LENGTH             64

/* The maximum number of incoming KeyUpdate messages we will accept */
#define MAX_KEY_UPDATE_MESSAGES     32

/* Extension context codes */
/* This extension is only allowed in TLS */
#define EXT_TLS_ONLY                        0x0001
/* This extension is only allowed in DTLS */
#define EXT_DTLS_ONLY                       0x0002
/* Some extensions may be allowed in DTLS but we don't implement them for it */
#define EXT_TLS_IMPLEMENTATION_ONLY         0x0004
/* Most extensions are not defined for SSLv3 but EXT_TYPE_renegotiate is */
#define EXT_SSL3_ALLOWED                    0x0008
/* Extension is only defined for TLS1.2 and above */
#define EXT_TLS1_2_AND_BELOW_ONLY           0x0010
/* Extension is only defined for TLS1.3 and above */
#define EXT_TLS1_3_ONLY                     0x0020
#define EXT_CLIENT_HELLO                    0x0040
/* Really means TLS1.2 or below */
#define EXT_TLS1_2_SERVER_HELLO             0x0080
#define EXT_TLS1_3_SERVER_HELLO             0x0100
#define EXT_TLS1_3_ENCRYPTED_EXTENSIONS     0x0200
#define EXT_TLS1_3_HELLO_RETRY_REQUEST      0x0400
#define EXT_TLS1_3_CERTIFICATE              0x0800
#define EXT_TLS1_3_NEW_SESSION_TICKET       0x1000

/* Message processing return codes */
typedef enum {
    /* Something bad happened */
    MSG_PROCESS_ERROR,
    /* We've finished reading - swap to writing */
    MSG_PROCESS_FINISHED_READING,
    /*
     * We've completed the main processing of this message but there is some
     * post processing to be done.
     */
    MSG_PROCESS_CONTINUE_PROCESSING,
    /* We've finished this message - read the next message */
    MSG_PROCESS_CONTINUE_READING
} MSG_PROCESS_RETURN;

/* Flush the write BIO */
int statem_flush(SSL *s);

typedef int (*confunc_f) (SSL *s, WPACKET *pkt);

int check_in_list(SSL *s, unsigned int group_id, const unsigned char *groups,
                  size_t num_groups, int checkallow);

/*
 * TLS/DTLS client state machine functions
 */
int ossl_statem_client_read_transition(SSL *s, int mt);
WRITE_TRAN ossl_statem_client_write_transition(SSL *s);
WORK_STATE ossl_statem_client_pre_work(SSL *s, WORK_STATE wst);
WORK_STATE ossl_statem_client_post_work(SSL *s, WORK_STATE wst);
int ossl_statem_client_construct_message(SSL *s, WPACKET *pkt,
                                         confunc_f *confunc, int *mt);
size_t ossl_statem_client_max_message_size(SSL *s);
MSG_PROCESS_RETURN ossl_statem_client_process_message(SSL *s, PACKET *pkt);
WORK_STATE ossl_statem_client_post_process_message(SSL *s, WORK_STATE wst);

/*
 * TLS/DTLS server state machine functions
 */
int ossl_statem_server_read_transition(SSL *s, int mt);
WRITE_TRAN ossl_statem_server_write_transition(SSL *s);
WORK_STATE ossl_statem_server_pre_work(SSL *s, WORK_STATE wst);
WORK_STATE ossl_statem_server_post_work(SSL *s, WORK_STATE wst);
int ossl_statem_server_construct_message(SSL *s, WPACKET *pkt,
                                         confunc_f *confunc,int *mt);
size_t ossl_statem_server_max_message_size(SSL *s);
MSG_PROCESS_RETURN ossl_statem_server_process_message(SSL *s, PACKET *pkt);
WORK_STATE ossl_statem_server_post_process_message(SSL *s, WORK_STATE wst);

/* Functions for getting new message data */
__owur int tls_get_message_header(SSL *s, int *mt);
__owur int tls_get_message_body(SSL *s, size_t *len);
__owur int dtls_get_message(SSL *s, int *mt, size_t *len);

/* Message construction and processing functions */
__owur int tls_process_initial_server_flight(SSL *s, int *al);
__owur MSG_PROCESS_RETURN tls_process_change_cipher_spec(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_finished(SSL *s, PACKET *pkt);
__owur int tls_construct_change_cipher_spec(SSL *s, WPACKET *pkt);
__owur int dtls_construct_change_cipher_spec(SSL *s, WPACKET *pkt);

__owur int tls_construct_finished(SSL *s, WPACKET *pkt);
__owur int tls_construct_key_update(SSL *s, WPACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_key_update(SSL *s, PACKET *pkt);
__owur WORK_STATE tls_finish_handshake(SSL *s, WORK_STATE wst, int clearbufs);
__owur WORK_STATE dtls_wait_for_dry(SSL *s);

/* some client-only functions */
__owur int tls_construct_client_hello(SSL *s, WPACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_server_hello(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_certificate_request(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_new_session_ticket(SSL *s, PACKET *pkt);
__owur int tls_process_cert_status_body(SSL *s, PACKET *pkt, int *al);
__owur MSG_PROCESS_RETURN tls_process_cert_status(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_server_done(SSL *s, PACKET *pkt);
__owur int tls_construct_cert_verify(SSL *s, WPACKET *pkt);
__owur WORK_STATE tls_prepare_client_certificate(SSL *s, WORK_STATE wst);
__owur int tls_construct_client_certificate(SSL *s, WPACKET *pkt);
__owur int ssl_do_client_cert_cb(SSL *s, X509 **px509, EVP_PKEY **ppkey);
__owur int tls_construct_client_key_exchange(SSL *s, WPACKET *pkt);
__owur int tls_client_key_exchange_post_work(SSL *s);
__owur int tls_construct_cert_status_body(SSL *s, WPACKET *pkt);
__owur int tls_construct_cert_status(SSL *s, WPACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_key_exchange(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_server_certificate(SSL *s, PACKET *pkt);
__owur int ssl3_check_cert_and_algorithm(SSL *s);
#ifndef OPENSSL_NO_NEXTPROTONEG
__owur int tls_construct_next_proto(SSL *s, WPACKET *pkt);
#endif
__owur MSG_PROCESS_RETURN tls_process_hello_req(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN dtls_process_hello_verify(SSL *s, PACKET *pkt);

/* some server-only functions */
__owur MSG_PROCESS_RETURN tls_process_client_hello(SSL *s, PACKET *pkt);
__owur WORK_STATE tls_post_process_client_hello(SSL *s, WORK_STATE wst);
__owur int tls_construct_server_hello(SSL *s, WPACKET *pkt);
__owur int dtls_construct_hello_verify_request(SSL *s, WPACKET *pkt);
__owur int tls_construct_server_certificate(SSL *s, WPACKET *pkt);
__owur int tls_construct_server_key_exchange(SSL *s, WPACKET *pkt);
__owur int tls_construct_certificate_request(SSL *s, WPACKET *pkt);
__owur int tls_construct_server_done(SSL *s, WPACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_client_certificate(SSL *s, PACKET *pkt);
__owur MSG_PROCESS_RETURN tls_process_client_key_exchange(SSL *s, PACKET *pkt);
__owur WORK_STATE tls_post_process_client_key_exchange(SSL *s, WORK_STATE wst);
__owur MSG_PROCESS_RETURN tls_process_cert_verify(SSL *s, PACKET *pkt);
#ifndef OPENSSL_NO_NEXTPROTONEG
__owur MSG_PROCESS_RETURN tls_process_next_proto(SSL *s, PACKET *pkt);
#endif
__owur int tls_construct_new_session_ticket(SSL *s, WPACKET *pkt);


/* Extension processing */

__owur int tls_collect_extensions(SSL *s, PACKET *packet, unsigned int context,
                                  RAW_EXTENSION **res, int *al);
__owur int tls_parse_extension(SSL *s, TLSEXT_INDEX idx, int context,
                               RAW_EXTENSION *exts,  X509 *x, size_t chainidx,
                               int *al);
__owur int tls_parse_all_extensions(SSL *s, int context, RAW_EXTENSION *exts,
                                    X509 *x, size_t chainidx, int *al);
__owur int tls_construct_extensions(SSL *s, WPACKET *pkt, unsigned int context,
                                    X509 *x, size_t chainidx, int *al);

__owur int tls_psk_do_binder(SSL *s, const EVP_MD *md,
                             const unsigned char *msgstart,
                             size_t binderoffset, const unsigned char *binderin,
                             unsigned char *binderout,
                             SSL_SESSION *sess, int sign);

/* Server Extension processing */
int tls_parse_ctos_renegotiate(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx, int *al);
int tls_parse_ctos_server_name(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRP
int tls_parse_ctos_srp(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_EC
int tls_parse_ctos_ec_pt_formats(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx, int *al);
int tls_parse_ctos_supported_groups(SSL *s, PACKET *pkt, unsigned int context,
                                    X509 *x, size_t chainidx, int *al);
#endif
int tls_parse_ctos_session_ticket(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx, int *al);
int tls_parse_ctos_sig_algs(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx, int *al);
#ifndef OPENSSL_NO_OCSP
int tls_parse_ctos_status_request(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_parse_ctos_npn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
#endif
int tls_parse_ctos_alpn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRTP
int tls_parse_ctos_use_srtp(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx, int *al);
#endif
int tls_parse_ctos_etm(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
int tls_parse_ctos_key_share(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                             size_t chainidx, int *al);
int tls_parse_ctos_ems(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
int tls_parse_ctos_psk_kex_modes(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx, int *al);
int tls_parse_ctos_psk(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);

int tls_construct_stoc_renegotiate(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx, int *al);
int tls_construct_stoc_server_name(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_EC
int tls_construct_stoc_ec_pt_formats(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx, int *al);
#endif
int tls_construct_stoc_session_ticket(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx, int *al);
#ifndef OPENSSL_NO_OCSP
int tls_construct_stoc_status_request(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_stoc_next_proto_neg(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx, int *al);
#endif
int tls_construct_stoc_alpn(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRTP
int tls_construct_stoc_use_srtp(SSL *s, WPACKET *pkt, unsigned int context,
                                X509 *x, size_t chainidx, int *al);
#endif
int tls_construct_stoc_etm(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
int tls_construct_stoc_ems(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
int tls_construct_stoc_key_share(SSL *s, WPACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx, int *al);
/*
 * Not in public headers as this is not an official extension. Only used when
 * SSL_OP_CRYPTOPRO_TLSEXT_BUG is set.
 */
#define TLSEXT_TYPE_cryptopro_bug      0xfde8
int tls_construct_stoc_cryptopro_bug(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx, int *al);
int tls_construct_stoc_psk(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);

/* Client Extension processing */
int tls_construct_ctos_renegotiate(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx, int *al);
int tls_construct_ctos_server_name(SSL *s, WPACKET *pkt, unsigned int context,
                                   X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRP
int tls_construct_ctos_srp(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_EC
int tls_construct_ctos_ec_pt_formats(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx, int *al);
int tls_construct_ctos_supported_groups(SSL *s, WPACKET *pkt,
                                        unsigned int context, X509 *x,
                                        size_t chainidx, int *al);
#endif
int tls_construct_ctos_session_ticket(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx, int *al);
int tls_construct_ctos_sig_algs(SSL *s, WPACKET *pkt, unsigned int context,
                                X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_OCSP
int tls_construct_ctos_status_request(SSL *s, WPACKET *pkt,
                                      unsigned int context, X509 *x,
                                      size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_construct_ctos_npn(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
#endif
int tls_construct_ctos_alpn(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRTP
int tls_construct_ctos_use_srtp(SSL *s, WPACKET *pkt, unsigned int context,
                                X509 *x, size_t chainidx, int *al);
#endif
int tls_construct_ctos_etm(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
#ifndef OPENSSL_NO_CT
int tls_construct_ctos_sct(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
#endif
int tls_construct_ctos_ems(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
int tls_construct_ctos_supported_versions(SSL *s, WPACKET *pkt,
                                          unsigned int context, X509 *x,
                                          size_t chainidx, int *al);
int tls_construct_ctos_key_share(SSL *s, WPACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx, int *al);
int tls_construct_ctos_psk_kex_modes(SSL *s, WPACKET *pkt, unsigned int context,
                                     X509 *x, size_t chainidx, int *al);
int tls_construct_ctos_padding(SSL *s, WPACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx, int *al);
int tls_construct_ctos_psk(SSL *s, WPACKET *pkt, unsigned int context, X509 *x,
                           size_t chainidx, int *al);
int tls_parse_stoc_renegotiate(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx, int *al);
int tls_parse_stoc_server_name(SSL *s, PACKET *pkt, unsigned int context,
                               X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_EC
int tls_parse_stoc_ec_pt_formats(SSL *s, PACKET *pkt, unsigned int context,
                                 X509 *x, size_t chainidx, int *al);
#endif
int tls_parse_stoc_session_ticket(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx, int *al);
#ifndef OPENSSL_NO_OCSP
int tls_parse_stoc_status_request(SSL *s, PACKET *pkt, unsigned int context,
                                  X509 *x, size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_CT
int tls_parse_stoc_sct(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
#endif
#ifndef OPENSSL_NO_NEXTPROTONEG
int tls_parse_stoc_npn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
#endif
int tls_parse_stoc_alpn(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                        size_t chainidx, int *al);
#ifndef OPENSSL_NO_SRTP
int tls_parse_stoc_use_srtp(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                            size_t chainidx, int *al);
#endif
int tls_parse_stoc_etm(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
int tls_parse_stoc_ems(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
int tls_parse_stoc_key_share(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                             size_t chainidx, int *al);
int tls_parse_stoc_psk(SSL *s, PACKET *pkt, unsigned int context, X509 *x,
                       size_t chainidx, int *al);
