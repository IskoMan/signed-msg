# signed-msg

A small C library that signs messages between nodes on a shared bus (CAN,
RS-485, a serial link, UDP) so a receiver can tell that a frame came from the
node it claims, was not changed, and is not an old frame played back. HMAC-SHA256
over the frame plus a monotonic counter. C99, no dependencies, no allocation,
about 300 lines of library code.

The idea comes from a university embedded-systems project: a home alarm on
STM32 microcontrollers where door and motion sensors report to a central unit
over CAN. Anyone who can touch the bus wires can record the "disarm" frame and
send it again later. This repo is a clean, standalone rewrite of that
protection with tests; no code from the course hand-in is reused.

## Build and test

```
make test    # unit tests
make asan    # same tests under AddressSanitizer + UndefinedBehaviorSanitizer
make         # build/libsigned_msg.a
```

## Frame

```
version(1) | sender(1) | receiver(1) | counter(8) | len(1) | payload(len) | tag(16)
tag = first 16 bytes of HMAC-SHA256(key, everything before the tag)
```

Overhead is 28 bytes, payload up to 64. That does not fit a classic 8-byte CAN
frame: use CAN FD, or segment with ISO-TP. Automotive AUTOSAR SecOC solves the
same problem in fewer bytes by sending truncated counters and MACs; this
library keeps them whole to stay simple to check.

## What it defends against, and how

| Threat | Control | Test |
|---|---|---|
| Replay: an attacker records a frame and sends it again | The receiver keeps the highest counter it accepted per sender and refuses anything not strictly greater | `replayed frame refused` |
| Reordering: an attacker holds back a frame and delivers it after a newer one | Same strict check; an old counter is refused even if it was never seen | `reordered frame refused` |
| Tampering with any field | The tag covers version, both ids, counter, length and payload; every single-bit flip of a frame is tried and refused | `every single-bit tamper refused` |
| Forging without the key | HMAC-SHA256, 128-bit tag, compared in constant time | `wrong key refused` |
| Locking a sender out by forging a huge counter | The counter is stored only after the tag verifies | `forged high counter does not lock out` |
| Reflection: a node's own frame sent back to it | Receiver id is inside the tag; a frame must be from our peer and to us | `reflection and misaddressing refused` |
| Relabelling who sent it | Sender id is inside the tag | `reflection and misaddressing refused` |
| Malformed frames (short, long, bad length byte) | Length and version checked before any field is used; sanitizer run in `make asan` | `malformed frames refused` |
| Counter wrap after 2^64 frames | The sender refuses to sign instead of wrapping to an old value | `counter exhaustion` |

Lost frames are fine: a gap in the counter is accepted.

`make test` also passes for the SHA-256 (FIPS 180-2) and HMAC (RFC 4231) test
vectors. Each check above was confirmed to matter by breaking it on purpose
(`<` instead of `<=`, tag check removed, address check removed, tag over the
payload only, 8-byte tag compare, length check removed, exhaustion check
removed, state saved before the tag check): every one makes the tests fail.

## What it does not do

- **No secrecy.** Payloads are readable on the bus. Signing is not encryption.
- **No key distribution.** Keys are given to `sm_tx_init`/`sm_rx_init`. Use one
  key per sender/receiver pair; a key shared by the whole bus lets any node
  that has it impersonate any other.
- **Counters must survive a reboot.** A receiver that restarts at 0 accepts old
  frames again (shown in `restart with persisted counters`). A sender that
  restarts at an old value gets its frames dropped. Persist with
  `sm_tx_counter`/`sm_rx_counter`; reserve sender counters in blocks so flash
  is not written on every frame.
- **No freshness in time.** A frame held back and delivered later is accepted
  if nothing newer arrived in between. If "disarm" must be recent, add a
  challenge from the receiver or a timestamp with a trusted clock.
- **No protection against flooding or jamming.** Anyone on the bus can drown it
  out; CAN arbitration makes that easy.
- **Not hardened against physical side channels** (power, EM) on the
  microcontroller. Only the tag compare is constant-time.
- **No out-of-order window.** Strict ordering fits a single bus, which delivers
  in order. A network that reorders (UDP over the internet) would need a
  sliding window like IPsec's.

## Layout

```
include/signed_msg.h   API and frame format
include/sha256.h       SHA-256 and HMAC-SHA256
src/                   implementation
test/test_main.c       all tests, plain C
```
