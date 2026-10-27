#include "signed_msg.h"

#include <string.h>

#include "sha256.h"

static void put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

/* Compare without an early exit, so the time taken does not reveal how many
 * leading tag bytes an attacker got right. */
static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static void compute_tag(const uint8_t key[SM_KEY_LEN], const uint8_t *msg, size_t len,
                        uint8_t tag[SM_TAG_LEN])
{
    uint8_t full[SHA256_LEN];
    hmac_sha256(key, SM_KEY_LEN, msg, len, full);
    memcpy(tag, full, SM_TAG_LEN);
    memset(full, 0, sizeof full);
}

void sm_tx_init(sm_tx *tx, uint8_t self_id, uint8_t peer_id,
                const uint8_t key[SM_KEY_LEN], uint64_t next_counter)
{
    tx->self_id = self_id;
    tx->peer_id = peer_id;
    memcpy(tx->key, key, SM_KEY_LEN);
    tx->next = next_counter ? next_counter : 1;
}

void sm_rx_init(sm_rx *rx, uint8_t self_id, uint8_t peer_id,
                const uint8_t key[SM_KEY_LEN], uint64_t last_accepted)
{
    rx->self_id = self_id;
    rx->peer_id = peer_id;
    memcpy(rx->key, key, SM_KEY_LEN);
    rx->last = last_accepted;
}

sm_status sm_seal(sm_tx *tx, const uint8_t *payload, size_t len,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    if (!tx || !out || !out_len || (len > 0 && !payload) || len > SM_MAX_PAYLOAD)
        return SM_ERR_ARG;
    if (cap < SM_OVERHEAD + len)
        return SM_ERR_BUFFER;
    if (tx->next == 0)
        return SM_ERR_EXHAUSTED;

    uint64_t ctr = tx->next++;   /* wraps to 0 after UINT64_MAX: exhausted */

    out[0] = SM_VERSION;
    out[1] = tx->self_id;
    out[2] = tx->peer_id;
    put_u64(out + 3, ctr);
    out[11] = (uint8_t)len;
    if (len > 0)
        memcpy(out + SM_HEADER_LEN, payload, len);
    compute_tag(tx->key, out, SM_HEADER_LEN + len, out + SM_HEADER_LEN + len);
    *out_len = SM_OVERHEAD + len;
    return SM_OK;
}

sm_status sm_open(sm_rx *rx, const uint8_t *frame, size_t len,
                  uint8_t *out, size_t cap, size_t *out_len)
{
    if (!rx || !frame || !out_len || (cap > 0 && !out))
        return SM_ERR_ARG;

    /* 1. Shape: everything here is attacker-controlled, check before use. */
    if (len < SM_OVERHEAD || len > SM_MAX_FRAME)
        return SM_ERR_FORMAT;
    if (frame[0] != SM_VERSION)
        return SM_ERR_FORMAT;
    size_t n = frame[11];
    if (n > SM_MAX_PAYLOAD || len != SM_OVERHEAD + n)
        return SM_ERR_FORMAT;

    /* 2. Addressing. The ids are also covered by the tag, so a frame cannot be
     * relabelled; this check just gives a clearer error for misrouted frames
     * and refuses our own frames reflected back at us. */
    if (frame[1] != rx->peer_id || frame[2] != rx->self_id)
        return SM_ERR_ADDRESS;

    /* 3. Authenticity, before trusting the counter. Checking the counter first
     * would still be safe, but updating state from an unverified frame would
     * let a forger push `last` to UINT64_MAX and lock the sender out. */
    uint8_t tag[SM_TAG_LEN];
    compute_tag(rx->key, frame, SM_HEADER_LEN + n, tag);
    int ok = ct_equal(tag, frame + SM_HEADER_LEN + n, SM_TAG_LEN);
    memset(tag, 0, sizeof tag);
    if (!ok)
        return SM_ERR_TAG;

    /* 4. Freshness: strictly increasing. Replays and reordered frames both
     * fail here. Counter 0 is never issued, so it always fails too. */
    uint64_t ctr = get_u64(frame + 3);
    if (ctr <= rx->last)
        return SM_ERR_REPLAY;

    if (cap < n)
        return SM_ERR_BUFFER;

    /* 5. Commit only after every check passed. */
    if (n > 0)
        memcpy(out, frame + SM_HEADER_LEN, n);
    *out_len = n;
    rx->last = ctr;
    return SM_OK;
}

uint64_t sm_tx_counter(const sm_tx *tx) { return tx->next; }
uint64_t sm_rx_counter(const sm_rx *rx) { return rx->last; }

int sm_frame_sender(const uint8_t *frame, size_t len)
{
    return (frame && len >= 2) ? frame[1] : -1;
}

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}

void sm_tx_wipe(sm_tx *tx) { wipe(tx, sizeof *tx); }
void sm_rx_wipe(sm_rx *rx) { wipe(rx, sizeof *rx); }

const char *sm_strerror(sm_status s)
{
    switch (s) {
    case SM_OK:            return "ok";
    case SM_ERR_ARG:       return "bad argument";
    case SM_ERR_BUFFER:    return "buffer too small";
    case SM_ERR_FORMAT:    return "malformed frame";
    case SM_ERR_ADDRESS:   return "wrong sender or receiver";
    case SM_ERR_TAG:       return "authentication failed";
    case SM_ERR_REPLAY:    return "replayed or reordered frame";
    case SM_ERR_EXHAUSTED: return "counter exhausted, rekey";
    }
    return "unknown";
}
