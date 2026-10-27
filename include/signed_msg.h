/*
 * signed_msg: authenticated messages with replay protection for a small
 * network of nodes (a CAN bus, a serial link, UDP). Each frame carries a
 * monotonic counter and a truncated HMAC-SHA256 tag over the whole header and
 * payload. A receiver accepts a frame only if the tag verifies and the counter
 * is strictly greater than the last one it accepted from that sender.
 *
 * Frame layout (all integers big-endian):
 *
 *   off  size  field
 *   0    1     version (SM_VERSION)
 *   1    1     sender id
 *   2    1     receiver id
 *   3    8     counter (starts at 1, never repeats)
 *   11   1     payload length n (0..SM_MAX_PAYLOAD)
 *   12   n     payload
 *   12+n 16    tag = HMAC-SHA256(key, bytes 0..12+n)[0..16]
 *
 * One sm_tx per (sender -> receiver) link on the sending node, one sm_rx per
 * (sender -> receiver) link on the receiving node, both with the same key.
 * Only plain structs, no allocation: the caller owns all memory.
 */
#ifndef SIGNED_MSG_H
#define SIGNED_MSG_H

#include <stddef.h>
#include <stdint.h>

#define SM_VERSION      0x01
#define SM_KEY_LEN      32
#define SM_TAG_LEN      16
#define SM_HEADER_LEN   12
#define SM_MAX_PAYLOAD  64
#define SM_OVERHEAD     (SM_HEADER_LEN + SM_TAG_LEN)
#define SM_MAX_FRAME    (SM_OVERHEAD + SM_MAX_PAYLOAD)

typedef enum {
    SM_OK = 0,
    SM_ERR_ARG,        /* NULL pointer or payload too long */
    SM_ERR_BUFFER,     /* output buffer too small */
    SM_ERR_FORMAT,     /* wrong version, wrong length, malformed frame */
    SM_ERR_ADDRESS,    /* frame is not from our peer or not addressed to us */
    SM_ERR_TAG,        /* tag does not verify: forged, tampered or wrong key */
    SM_ERR_REPLAY,     /* counter not newer than the last accepted one */
    SM_ERR_EXHAUSTED,  /* sender counter used up: rekey before sending more */
} sm_status;

typedef struct {
    uint8_t self_id;
    uint8_t peer_id;
    uint8_t key[SM_KEY_LEN];
    uint64_t next;     /* counter for the next frame; 0 means exhausted */
} sm_tx;

typedef struct {
    uint8_t self_id;
    uint8_t peer_id;
    uint8_t key[SM_KEY_LEN];
    uint64_t last;     /* highest counter accepted so far; 0 means none */
} sm_rx;

/* next_counter: the first counter to use, normally 1, or the value persisted
 * before a restart (see sm_tx_counter). 0 is treated as 1. */
void sm_tx_init(sm_tx *tx, uint8_t self_id, uint8_t peer_id,
                const uint8_t key[SM_KEY_LEN], uint64_t next_counter);

/* last_accepted: 0 for a fresh link, or the value persisted before a restart
 * (see sm_rx_counter). */
void sm_rx_init(sm_rx *rx, uint8_t self_id, uint8_t peer_id,
                const uint8_t key[SM_KEY_LEN], uint64_t last_accepted);

/* Builds a frame into out. The counter is consumed even if the frame is never
 * sent, so a counter value is never signed twice. */
sm_status sm_seal(sm_tx *tx, const uint8_t *payload, size_t len,
                  uint8_t *out, size_t cap, size_t *out_len);

/* Checks a frame and copies its payload to out. On any error rx is unchanged
 * and nothing is written to out. */
sm_status sm_open(sm_rx *rx, const uint8_t *frame, size_t len,
                  uint8_t *out, size_t cap, size_t *out_len);

/* Values to persist across restarts. Persist sm_tx_counter BEFORE sending the
 * frames that use it (e.g. reserve blocks of 1000), or a reboot reuses
 * counters and the receiver drops the frames as replays. */
uint64_t sm_tx_counter(const sm_tx *tx);
uint64_t sm_rx_counter(const sm_rx *rx);

/* Sender id of a frame, to pick the right sm_rx on a node with several peers.
 * Returns -1 if the frame is too short to have one. Not authenticated. */
int sm_frame_sender(const uint8_t *frame, size_t len);

/* Zeroes the key and state. */
void sm_tx_wipe(sm_tx *tx);
void sm_rx_wipe(sm_rx *rx);

const char *sm_strerror(sm_status s);

#endif
