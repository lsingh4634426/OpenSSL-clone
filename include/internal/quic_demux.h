/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_DEMUX_H
# define OSSL_QUIC_DEMUX_H

# include <openssl/ssl.h>
# include "internal/quic_types.h"
# include "internal/bio_addr.h"

/*
 * QUIC Demuxer
 * ============
 *
 * The QUIC connection demuxer is the entity responsible for receiving datagrams
 * from the network via a datagram BIO. It parses packet headers to determine
 * each packet's destination connection ID (DCID) and hands off processing of
 * the packet to the correct QUIC Record Layer (QRL)'s RX side.
 *
 * A QRL is instantiated per QUIC connection and contains the cryptographic
 * resources needed to decrypt QUIC packets for that connection. Received
 * datagrams are passed from the demuxer to the QRL via a callback registered
 * for a specific DCID by the QRL; thus the demuxer has no specific knowledge of
 * the QRL and is not coupled to it.
 *
 * A connection may have multiple connection IDs associated with it; a QRL
 * handles this simply by registering multiple connection IDs with the demuxer
 * via multiple register calls.
 *
 * URX Queue
 * ---------
 *
 * Since the demuxer must handle the initial reception of datagrams from the OS,
 * RX queue management for new, unprocessed datagrams is also handled by the
 * demuxer.
 *
 * The demuxer maintains a queue of Unprocessed RX Entries (URXEs), which store
 * unprocessed (i.e., encrypted, unvalidated) data received from the network.
 * The URXE queue is designed to allow multiple datagrams to be received in a
 * single call to BIO_recvmmsg, where supported.
 *
 * One URXE is used per received datagram. Each datagram may contain multiple
 * packets, however, this is not the demuxer's concern. QUIC prohibits different
 * packets in the same datagram from containing different DCIDs; the demuxer
 * only considers the DCID of the first packet in a datagram when deciding how
 * to route a received datagram, and it is the responsibility of the QRL to
 * enforce this rule. Packets other than the first packet in a datagram are not
 * examined by the demuxer, and the demuxer does not perform validation of
 * packet headers other than to the minimum extent necessary to extract the
 * DCID; further parsing and validation of packet headers is the responsibility
 * of the QRL.
 *
 * Rather than defining an opaque interface, the URXE structure internals
 * are exposed. Since the demuxer is only exposed to other parts of the QUIC
 * implementation internals, this poses no problem, and has a number of
 * advantages:
 *
 *   - Fields in the URXE can be allocated to support requirements in other
 *     components, like the QRL, which would otherwise have to allocate extra
 *     memory corresponding to each URXE.
 *
 *   - Other components, like the QRL, can keep the URXE in queues of its own
 *     when it is not being managed by the demuxer.
 *
 * URX Queue Structure
 * -------------------
 *
 * The URXE queue is maintained as a simple doubly-linked list. URXE entries are
 * moved between different lists in their lifecycle (for example, from a free
 * list to a pending list and vice versa). The buffer into which datagrams are
 * received immediately follows this URXE header structure and is part of the
 * same allocation.
 */

typedef struct quic_urxe_st QUIC_URXE;

/* Maximum number of packets we allow to exist in one datagram. */
#define QUIC_MAX_PKT_PER_URXE       (sizeof(uint64_t) * 8)

struct quic_urxe_st {
    QUIC_URXE *prev, *next;

    /*
     * The URXE data starts after this structure so we don't need a pointer.
     * data_len stores the current length (i.e., the length of the received
     * datagram) and alloc_len stores the allocation length. The URXE will be
     * reallocated if we need a larger allocation than is available, though this
     * should not be common as we will have a good idea of worst-case MTUs up
     * front.
     */
    size_t          data_len, alloc_len;

    /*
     * Bitfields per packet. processed indicates the packet has been processed
     * and must not be processed again, hpr_removed indicates header protection
     * has already been removed. Used by QRL only; not used by the demuxer.
     */
    uint64_t        processed, hpr_removed;

    /*
     * Address of peer we received the datagram from, and the local interface
     * address we received it on. If local address support is not enabled, local
     * is zeroed.
     */
    BIO_ADDR        peer, local;
};

/* Accessors for URXE buffer. */
static ossl_unused ossl_inline unsigned char *
ossl_quic_urxe_data(const QUIC_URXE *e)
{
    return (unsigned char *)&e[1];
}

static ossl_unused ossl_inline unsigned char *
ossl_quic_urxe_data_end(const QUIC_URXE *e)
{
    return ossl_quic_urxe_data(e) + e->data_len;
}

/* List structure tracking a queue of URXEs. */
typedef struct quic_urxe_list_st {
    QUIC_URXE *head, *tail;
} QUIC_URXE_LIST;

/*
 * List management helpers. These are used by the demuxer but can also be used
 * by users of the demuxer to manage URXEs.
 */
void ossl_quic_urxe_remove(QUIC_URXE_LIST *l, QUIC_URXE *e);
void ossl_quic_urxe_insert_head(QUIC_URXE_LIST *l, QUIC_URXE *e);
void ossl_quic_urxe_insert_tail(QUIC_URXE_LIST *l, QUIC_URXE *e);

/* Opaque type representing a demuxer. */
typedef struct quic_demux_st QUIC_DEMUX;

/*
 * Called when a datagram is received for a given connection ID.
 *
 * e is a URXE containing the datagram payload. It is permissible for the callee
 * to mutate this buffer; once the demuxer calls this callback, it will never
 * read the buffer again.
 *
 * The callee must arrange for ossl_quic_demux_release_urxe to be called on the URXE
 * at some point in the future (this need not be before the callback returns).
 *
 * At the time the callback is made, the URXE will not be in any queue,
 * therefore the callee can use the prev and next fields as it wishes.
 */
typedef void (ossl_quic_demux_cb_fn)(QUIC_URXE *e, void *arg);

/*
 * Creates a new demuxer. The given BIO is used to receive datagrams from the
 * network using BIO_recvmmsg. short_conn_id_len is the length of destination
 * connection IDs used in RX'd packets; it must have the same value for all
 * connections used on a socket. default_urxe_alloc_len is the buffer size to
 * receive datagrams into; it should be a value large enough to contain any
 * received datagram according to local MTUs, etc.
 */
QUIC_DEMUX *ossl_quic_demux_new(BIO *net_bio,
                                size_t short_conn_id_len,
                                size_t default_urxe_alloc_len);

/*
 * Destroy a demuxer. All URXEs must have been released back to the demuxer
 * before calling this. No-op if demux is NULL.
 */
void ossl_quic_demux_free(QUIC_DEMUX *demux);

/*
 * Register a datagram handler callback for a connection ID.
 *
 * ossl_quic_demux_pump will call the specified function if it receives a datagram
 * the first packet of which has the specified destination connection ID.
 *
 * It is assumed all packets in a datagram have the same destination connection
 * ID (as QUIC mandates this), but it is the user's responsibility to check for
 * this and reject subsequent packets in a datagram that violate this rule.
 *
 * dst_conn_id is a destination connection ID; it is copied and need not remain
 * valid after this function returns.
 *
 * cb_arg is passed to cb when it is called. For information on the callback,
 * see its typedef above.
 *
 * Only one handler can be set for a given connection ID. If a handler is
 * already set for the given connection ID, returns 0.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_quic_demux_register(QUIC_DEMUX *demux,
                             const QUIC_CONN_ID *dst_conn_id,
                             ossl_quic_demux_cb_fn *cb,
                             void *cb_arg);

/*
 * Unregisters any datagram handler callback set for the given connection ID.
 * Fails if no handler is registered for the given connection ID.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_quic_demux_unregister(QUIC_DEMUX *demux,
                               const QUIC_CONN_ID *dst_conn_id);

/*
 * Unregisters any datagram handler callback from all connection IDs it is used
 * for. cb and cb_arg must both match the values passed to
 * ossl_quic_demux_register.
 */
void ossl_quic_demux_unregister_by_cb(QUIC_DEMUX *demux,
                                      ossl_quic_demux_cb_fn *cb,
                                      void *cb_arg);

/*
 * Releases a URXE back to the demuxer. No reference must be made to the URXE or
 * its buffer after calling this function. The URXE must not be in any queue;
 * that is, its prev and next pointers must be NULL.
 */
void ossl_quic_demux_release_urxe(QUIC_DEMUX *demux,
                                  QUIC_URXE *e);

/*
 * Process any unprocessed RX'd datagrams, by calling registered callbacks by
 * connection ID, reading more datagrams from the BIO if necessary.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_quic_demux_pump(QUIC_DEMUX *demux);

/*
 * Artificially inject a packet into the demuxer for testing purposes. The
 * buffer must not exceed the URXE size being used by the demuxer.
 *
 * If peer or local are NULL, their respective fields are zeroed in the injected
 * URXE.
 *
 * Returns 1 on success or 0 on failure.
 */
int ossl_quic_demux_inject(QUIC_DEMUX *demux,
                           const unsigned char *buf,
                           size_t buf_len,
                           const BIO_ADDR *peer,
                           const BIO_ADDR *local);

#endif
