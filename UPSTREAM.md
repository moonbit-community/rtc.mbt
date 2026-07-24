# Upstream alignment ledger

This port's upstream compatibility target is intentionally pinned. Changes
after the snapshot below do not enter the compatibility target until this
ledger is updated.

## Baseline

| Item | Value |
| --- | --- |
| Repository | `webrtc-rs/rtc` |
| Commit | `a10cd2c18f7c4e646e83f6f00b792ef38ac3cdb2` |
| Upstream version | `0.20.0-rc.4` |
| Upstream license | `MIT OR Apache-2.0` |
| Crypto ABI | OpenSSL 3.x, `libcrypto.so.3` |
| Reproducible crypto build | Ubuntu OpenSSL `3.0.2-0ubuntu1.25` from snapshot `20260702T000000Z` |
| Initial platform | Linux x86_64 native |

The upstream copyright notice is retained in `LICENSE-MIT`; Apache-2.0 terms
are retained in `LICENSE-APACHE`.

## Package alignment

`implemented` means the pinned capability surface exists with deterministic
MoonBit tests. `interop-verified` additionally means it participates in the
fixed external Rust, Chromium, or coturn gates.

| MoonBit package | Upstream crate or root area | Status | Evidence |
| --- | --- | --- | --- |
| `sdp` | `rtc-sdp`, root JSEP | implemented | strict document/media codecs, inheritance, offer/answer/pranswer/rollback/glare, RTP/RTX/RID/simulcast/SSRC attributes |
| `stun` | `rtc-stun` | implemented | framing, typed attributes, XOR addresses, integrity/fingerprint, transaction deadlines, malformed input |
| `turn` | `rtc-turn` | implemented | allocation authentication, refresh, permission/channel binding, relay framing, UDP/TCP/TLS server legs |
| `mdns` | `rtc-mdns` | implemented | DNS codec, QueryOnly and QueryAndGather, retry/timeout, local registration and answers |
| `ice` | `rtc-ice`, root integration | implemented | host/srflx/prflx/relay, UDP and active/passive TCP, checks, nomination, role conflict, trickle, restart |
| `dtls` | `rtc-dtls` | implemented | DTLS 1.2, EMS, ECDSA/RSA/PSK, all eleven pinned suites, flights, fragmentation, replay, exporter, fingerprint validation |
| `srtp` | `rtc-srtp` | interop-verified | AES-CM 80/32 and AES-GCM 128/256 RTP/RTCP protection, rollover, replay and tamper rejection |
| `sctp` | `rtc-sctp` | interop-verified | cookies, simultaneous open, DATA fragmentation/reassembly, SACK/retransmit, FORWARD-TSN, reset, shutdown, buffers |
| `datachannel` | `rtc-datachannel` | interop-verified | DCEP, reliable/partial, ordered/unordered, negotiated/multi-channel, parity remap, close/reset and thresholds |
| `rtp` | `rtc-rtp` | interop-verified | packet/header extensions and pinned codec packetizers/depacketizers |
| `rtcp` | `rtc-rtcp` | implemented | SR/RR/SDES/BYE/APP, NACK/PLI/FIR/TWCC/REMB/XR, compound validation and unknown packets |
| `interceptor` | `rtc-interceptor` | implemented | pipeline context, reports, NACK, TWCC, RTX and feedback routing |
| `media` | `rtc-media`, root media API | interop-verified | tracks/senders/receivers/transceivers, audio PCM/RTP, sample builder, H26x, Ogg, IVF, transforms |
| root `rtc` | PeerConnection/JSEP/stats/settings | interop-verified | Sans-I/O routing, TURN/mDNS/ICE/DTLS/SRTP/SCTP composition, renegotiation, simulcast/SVC and detailed stats |
| `runtime/async` | MoonBit runtime adapter | implemented | bounded queues, real UDP and ICE TCP, TURN TCP/TLS, timers, cancellation, scoped lifecycle and output backpressure |

## External interoperability

`scripts/test-rust-interop` uses the independently compiled Rust `webrtc`
0.14.0 peer fixed by `interop/rust-peer/Cargo.lock` and Rust 1.90.0. It runs
six rows:

- MoonBit offerer → Rust answerer, reliable ordered;
- Rust offerer → MoonBit answerer, reliable ordered;
- MoonBit offerer → Rust answerer, partial/unordered;
- Rust offerer → MoonBit answerer, partial/unordered;
- MoonBit offerer → Rust answerer, Opus audio and VP8 video;
- Rust offerer → MoonBit answerer, Opus audio and VP8 video.

Every row exchanges UTF-8 text and a fragmented binary payload and performs
channel close. The media rows additionally require both audio and video RTP
to arrive over the negotiated SRTP transport. This gate also covers
peer-selected DTLS GCM explicit nonces and SCTP simultaneous active open.

`scripts/test-chromium-interop` fixes Playwright `1.61.1`, Chromium revision
`1228` (`149.0.7827.55`), and runs the equivalent six-row matrix. The
MoonBit-sending media row requires Chromium inbound-RTP statistics for both
audio and video; the Chromium-sending row uses live WebAudio and canvas
tracks and requires MoonBit to receive both RTP streams. The matrix also
covers response-source peer-reflexive ICE nomination when Chromium's wildcard
socket answers a loopback check from an address different from its SDP host
candidate.

The pinned Sans-I/O root crate itself uses an unstable Rust API under the
available stable toolchain, so it remains an unmodified source oracle rather
than the executable peer.

`scripts/test-coturn-interop` starts coturn `4.14.0-r0` from the pinned Linux
x86_64 OCI digest, gathers two relay-only candidates against the real server,
and carries text plus a fragmented binary DataChannel payload through the
relay. The CI artifact retains the raw coturn log.

## Acceptance inventory

`scripts/audit-upstream.mjs` verifies:

- 1,174 valid Rust tests (`1,072 #[test]` and `102 #[tokio::test]`);
- two commented TODO tests;
- 87 fuzz targets;
- 32 root integration-test files;
- four crate-level integration-test files.

`docs/upstream-coverage.json` contains all 1,299 ledger entries with source
locations, semantic target areas, status, and MoonBit evidence. A semantic
conformance mapping is not described as a mechanical test translation, and
deterministic malformed-input regressions are not described as continuous
fuzzing.

## Release artifacts

The repository contains:

- locked Rust interoperability dependencies;
- locked Playwright dependencies and an exact Chromium revision;
- an exact coturn version/platform OCI digest;
- an exact Ubuntu platform OCI digest, archive snapshot, and complete OpenSSL
  package version, with archived runtime build identity;
- a native ASan runner that instruments generated test entry points and C
  stubs while disabling the bundled allocator;
- seven native release benchmarks and a self-testing interleaved regression
  gate;
- a five-warmup, twenty-sample raw benchmark baseline tied to clean commit
  `29f4ff26dcb507715a0bfdacd58a0a3b48f3c776`;
- generated `.mbti` files for public-interface review.
