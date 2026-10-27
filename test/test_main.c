/* Tests for sha256.c and signed_msg.c. Plain C, no framework: each CHECK
 * prints the failing line and the run exits non-zero if any failed. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha256.h"
#include "signed_msg.h"

static int failures, checks;

#define CHECK(cond)                                                       \
    do {                                                                  \
        checks++;                                                         \
        if (!(cond)) {                                                    \
            failures++;                                                   \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                 \
    } while (0)

#define CHECK_ST(expr, want)                                              \
    do {                                                                  \
        sm_status got_ = (expr);                                          \
        checks++;                                                         \
        if (got_ != (want)) {                                             \
            failures++;                                                   \
            printf("  FAIL %s:%d: %s = %s, want %s\n", __FILE__, __LINE__, \
                   #expr, sm_strerror(got_), sm_strerror(want));          \
        }                                                                 \
    } while (0)

static void hex(const uint8_t *b, size_t n, char *out)
{
    for (size_t i = 0; i < n; i++)
        sprintf(out + 2 * i, "%02x", b[i]);
}

static int digest_is(const uint8_t d[SHA256_LEN], const char *want)
{
    char got[2 * SHA256_LEN + 1];
    hex(d, SHA256_LEN, got);
    if (strcmp(got, want) != 0) {
        printf("  got  %s\n  want %s\n", got, want);
        return 0;
    }
    return 1;
}

/* ---- SHA-256: FIPS 180-2 examples ---- */
static void test_sha256(void)
{
    uint8_t d[SHA256_LEN];

    sha256("", 0, d);
    CHECK(digest_is(d, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    sha256("abc", 3, d);
    CHECK(digest_is(d, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    const char *m = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    sha256(m, strlen(m), d);
    CHECK(digest_is(d, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"));

    /* One million 'a', fed in uneven pieces to exercise buffering. */
    uint8_t a[1000];
    memset(a, 'a', sizeof a);
    sha256_ctx c;
    sha256_init(&c);
    size_t left = 1000000, step = 1;
    while (left > 0) {
        size_t n = step < left ? step : left;
        if (n > sizeof a)
            n = sizeof a;
        sha256_update(&c, a, n);
        left -= n;
        step = step * 7 % 997 + 1;
    }
    sha256_final(&c, d);
    CHECK(digest_is(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));
}

/* ---- HMAC-SHA256: RFC 4231 test cases 1-4, 6, 7 ---- */
static void test_hmac(void)
{
    uint8_t d[SHA256_LEN], key[131], data[50];

    memset(key, 0x0b, 20);
    hmac_sha256(key, 20, "Hi There", 8, d);
    CHECK(digest_is(d, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));

    hmac_sha256("Jefe", 4, "what do ya want for nothing?", 28, d);
    CHECK(digest_is(d, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));

    memset(key, 0xaa, 20);
    memset(data, 0xdd, 50);
    hmac_sha256(key, 20, data, 50, d);
    CHECK(digest_is(d, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"));

    for (int i = 0; i < 25; i++)
        key[i] = (uint8_t)(i + 1);
    memset(data, 0xcd, 50);
    hmac_sha256(key, 25, data, 50, d);
    CHECK(digest_is(d, "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"));

    memset(key, 0xaa, 131);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    hmac_sha256(key, 131, m6, strlen(m6), d);
    CHECK(digest_is(d, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));

    const char *m7 = "This is a test using a larger than block-size key and a larger "
                     "than block-size data. The key needs to be hashed before being "
                     "used by the HMAC algorithm.";
    hmac_sha256(key, 131, m7, strlen(m7), d);
    CHECK(digest_is(d, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"));
}

/* ---- signed_msg ---- */

enum { ALARM = 0x01, DOOR = 0x10, PIR = 0x11 };

static const uint8_t KEY[SM_KEY_LEN] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
};
static const uint8_t OTHER_KEY[SM_KEY_LEN] = {1};

/* The door sensor reports to the alarm unit. */
static void link(sm_tx *tx, sm_rx *rx)
{
    sm_tx_init(tx, DOOR, ALARM, KEY, 1);
    sm_rx_init(rx, ALARM, DOOR, KEY, 0);
}

static void seal(sm_tx *tx, const char *msg, uint8_t *f, size_t *n)
{
    CHECK_ST(sm_seal(tx, (const uint8_t *)msg, strlen(msg), f, SM_MAX_FRAME, n), SM_OK);
}

static void test_roundtrip(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    for (int i = 0; i < 5; i++) {
        seal(&tx, "door open", f, &n);
        CHECK(n == SM_OVERHEAD + 9);
        CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
        CHECK(m == 9 && memcmp(out, "door open", 9) == 0);
    }
    CHECK(sm_rx_counter(&rx) == 5);
    CHECK(sm_tx_counter(&tx) == 6);

    /* Empty and maximum-size payloads. */
    CHECK_ST(sm_seal(&tx, NULL, 0, f, sizeof f, &n), SM_OK);
    CHECK_ST(sm_open(&rx, f, n, NULL, 0, &m), SM_OK);
    CHECK(m == 0);
    uint8_t big[SM_MAX_PAYLOAD];
    memset(big, 0x5a, sizeof big);
    CHECK_ST(sm_seal(&tx, big, sizeof big, f, sizeof f, &n), SM_OK);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
    CHECK(m == SM_MAX_PAYLOAD && memcmp(out, big, m) == 0);
}

static void test_replay_refused(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "disarm", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
    /* An attacker who recorded the "disarm" frame sends it again, now and
     * after more traffic. */
    for (int i = 0; i < 3; i++)
        CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_REPLAY);
    uint8_t f2[SM_MAX_FRAME]; size_t n2;
    seal(&tx, "heartbeat", f2, &n2);
    CHECK_ST(sm_open(&rx, f2, n2, out, sizeof out, &m), SM_OK);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_REPLAY);
}

static void test_reorder_refused(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f1[SM_MAX_FRAME], f2[SM_MAX_FRAME], f3[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n1, n2, n3, m;

    seal(&tx, "arm", f1, &n1);
    seal(&tx, "disarm", f2, &n2);
    seal(&tx, "arm", f3, &n3);
    /* An attacker delays "disarm" (f2) and delivers it after f3. */
    CHECK_ST(sm_open(&rx, f1, n1, out, sizeof out, &m), SM_OK);
    CHECK_ST(sm_open(&rx, f3, n3, out, sizeof out, &m), SM_OK);
    CHECK_ST(sm_open(&rx, f2, n2, out, sizeof out, &m), SM_ERR_REPLAY);
    CHECK(sm_rx_counter(&rx) == 3);
}

static void test_dropped_frames_ok(void)
{
    /* Lost frames are not an attack: a gap in the counter is accepted. */
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    for (int i = 0; i < 10; i++)
        seal(&tx, "lost", f, &n);
    seal(&tx, "arrives", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
    CHECK(sm_rx_counter(&rx) == 11);
}

static void test_tamper_every_bit(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], t[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;
    int refused = 0, total = 0;

    seal(&tx, "door closed", f, &n);
    /* Flip each bit of the frame in turn: header, counter, length, payload,
     * tag. Every variant must be refused and leave the receiver untouched,
     * and the out buffer unwritten. */
    for (size_t i = 0; i < n; i++) {
        for (int b = 0; b < 8; b++) {
            memcpy(t, f, n);
            t[i] ^= (uint8_t)(1u << b);
            memset(out, 0xee, sizeof out);
            sm_status s = sm_open(&rx, t, n, out, sizeof out, &m);
            total++;
            if (s != SM_OK)
                refused++;
            else
                printf("  FAIL accepted with byte %zu bit %d flipped\n", i, b);
            CHECK(sm_rx_counter(&rx) == 0);
            CHECK(out[0] == 0xee);
        }
    }
    CHECK(refused == total);
    CHECK(total == (int)n * 8);
    /* The untouched frame still works afterwards. */
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
}

static void test_tamper_payload_with_fixed_length(void)
{
    /* Same length, different content: only the tag can catch this. */
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "arm", f, &n);
    memcpy(f + SM_HEADER_LEN, "off", 3);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_TAG);
}

static void test_forged_counter_does_not_lock_out(void)
{
    /* A forger sends frames with counter UINT64_MAX and a garbage tag. If the
     * receiver stored the counter before checking the tag, every real frame
     * afterwards would be refused as a replay. */
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "x", f, &n);
    memset(f + 3, 0xff, 8);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_TAG);
    CHECK(sm_rx_counter(&rx) == 0);
    seal(&tx, "real", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
}

static void test_wrong_key(void)
{
    sm_tx tx; sm_rx rx;
    sm_tx_init(&tx, DOOR, ALARM, OTHER_KEY, 1);
    sm_rx_init(&rx, ALARM, DOOR, KEY, 0);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "disarm", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_TAG);
}

static void test_addressing(void)
{
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    /* Reflection: with one key per pair in both directions, the alarm's own
     * frame sent back to it must not be accepted as coming from the door. */
    sm_tx alarm_tx; sm_rx alarm_rx;
    sm_tx_init(&alarm_tx, ALARM, DOOR, KEY, 1);
    sm_rx_init(&alarm_rx, ALARM, DOOR, KEY, 0);
    seal(&alarm_tx, "siren on", f, &n);
    CHECK_ST(sm_open(&alarm_rx, f, n, out, sizeof out, &m), SM_ERR_ADDRESS);

    /* A frame from another node (sharing the key by mistake) is refused. */
    sm_tx pir_tx; sm_rx rx;
    sm_tx_init(&pir_tx, PIR, ALARM, KEY, 1);
    sm_rx_init(&rx, ALARM, DOOR, KEY, 0);
    seal(&pir_tx, "motion", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_ADDRESS);

    /* Relabelling the sender id is caught by the tag. */
    f[1] = DOOR;
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_ERR_TAG);

    CHECK(sm_frame_sender(f, n) == DOOR);
    CHECK(sm_frame_sender(f, 1) == -1);
}

static void test_independent_senders(void)
{
    /* Each link has its own counter: the PIR's counter 1 is fine after the
     * door's counter 5. */
    sm_tx door, pir; sm_rx from_door, from_pir;
    sm_tx_init(&door, DOOR, ALARM, KEY, 1);
    sm_tx_init(&pir, PIR, ALARM, OTHER_KEY, 1);
    sm_rx_init(&from_door, ALARM, DOOR, KEY, 0);
    sm_rx_init(&from_pir, ALARM, PIR, OTHER_KEY, 0);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    for (int i = 0; i < 5; i++) {
        seal(&door, "d", f, &n);
        CHECK_ST(sm_open(&from_door, f, n, out, sizeof out, &m), SM_OK);
    }
    seal(&pir, "p", f, &n);
    CHECK_ST(sm_open(&from_pir, f, n, out, sizeof out, &m), SM_OK);
    CHECK(sm_rx_counter(&from_door) == 5 && sm_rx_counter(&from_pir) == 1);
}

static void test_malformed(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME + 8], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "hello", f, &n);
    /* Every truncation, and one extra byte. */
    for (size_t len = 0; len < n; len++)
        CHECK(sm_open(&rx, f, len, out, sizeof out, &m) != SM_OK);
    f[n] = 0;
    CHECK_ST(sm_open(&rx, f, n + 1, out, sizeof out, &m), SM_ERR_FORMAT);
    /* Length field larger than the maximum, with a frame that long. */
    uint8_t g[SM_MAX_FRAME + 8];
    memcpy(g, f, n);
    g[11] = SM_MAX_PAYLOAD + 1;
    CHECK_ST(sm_open(&rx, g, SM_OVERHEAD + SM_MAX_PAYLOAD + 1, out, sizeof out, &m), SM_ERR_FORMAT);
    /* Wrong version. */
    memcpy(g, f, n);
    g[0] = 0x02;
    CHECK_ST(sm_open(&rx, g, n, out, sizeof out, &m), SM_ERR_FORMAT);
    CHECK_ST(sm_open(&rx, NULL, n, out, sizeof out, &m), SM_ERR_ARG);
    CHECK(sm_rx_counter(&rx) == 0);

    /* Output buffer too small: refused without consuming the counter, so the
     * same frame can be opened again with a big enough buffer. */
    CHECK_ST(sm_open(&rx, f, n, out, 2, &m), SM_ERR_BUFFER);
    CHECK(sm_rx_counter(&rx) == 0);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
}

static void test_seal_args(void)
{
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t f[SM_MAX_FRAME], p[SM_MAX_PAYLOAD + 1] = {0};
    size_t n;

    CHECK_ST(sm_seal(&tx, p, sizeof p, f, sizeof f, &n), SM_ERR_ARG);
    CHECK_ST(sm_seal(&tx, p, 4, f, SM_OVERHEAD + 3, &n), SM_ERR_BUFFER);
    CHECK_ST(sm_seal(&tx, NULL, 4, f, sizeof f, &n), SM_ERR_ARG);
    CHECK(sm_tx_counter(&tx) == 1);   /* failed seals do not burn counters */
}

static void test_restart_with_persisted_counters(void)
{
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;
    sm_tx tx; sm_rx rx; link(&tx, &rx);
    uint8_t old[SM_MAX_FRAME]; size_t old_n;

    seal(&tx, "before reboot", old, &old_n);
    CHECK_ST(sm_open(&rx, old, old_n, out, sizeof out, &m), SM_OK);

    /* Receiver reboots and restores its counter: the old frame stays dead. */
    uint64_t saved_rx = sm_rx_counter(&rx), saved_tx = sm_tx_counter(&tx);
    sm_rx_wipe(&rx);
    sm_tx_wipe(&tx);
    sm_rx_init(&rx, ALARM, DOOR, KEY, saved_rx);
    sm_tx_init(&tx, DOOR, ALARM, KEY, saved_tx);
    CHECK_ST(sm_open(&rx, old, old_n, out, sizeof out, &m), SM_ERR_REPLAY);
    seal(&tx, "after reboot", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);

    /* The documented failure mode: a receiver that forgets its counter
     * accepts the old frame again. This is why the counter must persist. */
    sm_rx fresh;
    sm_rx_init(&fresh, ALARM, DOOR, KEY, 0);
    CHECK_ST(sm_open(&fresh, old, old_n, out, sizeof out, &m), SM_OK);
}

static void test_counter_exhaustion(void)
{
    sm_tx tx; sm_rx rx;
    sm_tx_init(&tx, DOOR, ALARM, KEY, UINT64_MAX);
    sm_rx_init(&rx, ALARM, DOOR, KEY, UINT64_MAX - 1);
    uint8_t f[SM_MAX_FRAME], out[SM_MAX_PAYLOAD];
    size_t n, m;

    seal(&tx, "last", f, &n);
    CHECK_ST(sm_open(&rx, f, n, out, sizeof out, &m), SM_OK);
    /* The counter would wrap to 0 here; the sender must refuse instead. */
    CHECK_ST(sm_seal(&tx, (const uint8_t *)"x", 1, f, sizeof f, &n), SM_ERR_EXHAUSTED);
    CHECK_ST(sm_seal(&tx, (const uint8_t *)"x", 1, f, sizeof f, &n), SM_ERR_EXHAUSTED);
}

int main(void)
{
    struct { const char *name; void (*fn)(void); } tests[] = {
        {"sha256 FIPS vectors", test_sha256},
        {"hmac-sha256 RFC 4231 vectors", test_hmac},
        {"round trip", test_roundtrip},
        {"replayed frame refused", test_replay_refused},
        {"reordered frame refused", test_reorder_refused},
        {"dropped frames tolerated", test_dropped_frames_ok},
        {"every single-bit tamper refused", test_tamper_every_bit},
        {"same-length payload swap refused", test_tamper_payload_with_fixed_length},
        {"forged high counter does not lock out", test_forged_counter_does_not_lock_out},
        {"wrong key refused", test_wrong_key},
        {"reflection and misaddressing refused", test_addressing},
        {"independent per-sender counters", test_independent_senders},
        {"malformed frames refused", test_malformed},
        {"seal argument checks", test_seal_args},
        {"restart with persisted counters", test_restart_with_persisted_counters},
        {"counter exhaustion", test_counter_exhaustion},
    };
    size_t count = sizeof tests / sizeof tests[0];

    for (size_t i = 0; i < count; i++) {
        int before = failures;
        tests[i].fn();
        printf("%s  %s\n", failures == before ? "ok  " : "FAIL", tests[i].name);
    }
    printf("\n%zu tests, %d checks, %d failed\n", count, checks, failures);
    return failures ? 1 : 0;
}
