# rtc.mbt

`rtc.mbt` is an experimental, native MoonBit implementation of a Sans-I/O
WebRTC stack. Its compatibility target is the fixed `webrtc-rs/rtc` snapshot
recorded in [`UPSTREAM.md`](UPSTREAM.md).

The first supported platform is Linux x86_64 with the native backend and
OpenSSL 3.x `libcrypto.so.3`. CI additionally verifies the exact OpenSSL
`3.0.2-0ubuntu1.25` Ubuntu build in a digest- and archive-snapshot-pinned
environment documented in
[`docs/ci-crypto-environment.md`](docs/ci-crypto-environment.md).

## What is implemented

The stack includes:

- SDP/JSEP offer, answer, provisional answer, rollback, glare handling,
  perfect negotiation, BUNDLE, trickle ICE, ICE restart, RTP media sections,
  RTX, RID, simulcast, and SSRC groups;
- STUN, mDNS query/gather, host/srflx/prflx/relay ICE, TURN over UDP/TCP/TLS,
  and active/passive ICE TCP;
- DTLS 1.2 with ECDSA, RSA, and PSK authentication across the eleven pinned
  cipher suites, EMS, replay protection, certificate fingerprints, and
  `use_srtp`;
- SRTP/SRTCP for AES-CM and AEAD profiles;
- SCTP association setup, fragmentation, SACK/retransmission, partial
  reliability, unordered delivery, stream reset, flow control, and DCEP
  DataChannels;
- RTP/RTCP codecs, packetizers/depacketizers, NACK, TWCC, RTX, reports,
  interceptors, encoded transforms, tracks/transceivers, simulcast controls,
  media helpers, and detailed statistics.

The fixed Rust `webrtc` 0.14.0 peer and Playwright Chromium
`149.0.7827.55` exchange reliable and partial/unordered DataChannels plus
Opus audio and VP8 video RTP over SRTP with MoonBit in both offerer and
answerer roles. A Linux x86_64 coturn `4.14.0-r0` image is pinned by digest
and carries a relay-only MoonBit DataChannel in CI.

## Sans-I/O boundary

The core never opens sockets or reads system time. Applications inject
`IoEvent`, `InboundDatagram`, `RtcMessage`, and explicit monotonic timestamps,
then drain:

- `poll_io_action` for UDP and TCP/TLS connect/listen/read/write/close work;
- `poll_message` and `poll_event` for application output;
- `poll_timeout` for the next protocol deadline.

The clock mapping is explicit and deterministic:

```moonbit check
///|
test "inject a deterministic clock sample" {
  let monotonic = Instant::from_milliseconds(42L)
  let wall = WallTime::from_unix_nanoseconds(1700000000000000000L)
  let sample = ClockSample::new(monotonic~, wall~)
  assert_eq(sample.monotonic().as_milliseconds(), 42L)
  assert_eq(sample.wall().as_unix_nanoseconds(), 1700000000000000000L)
}
```

`runtime/async` is the official bounded-queue adapter. It manages UDP sockets,
TCP listeners and streams, TURN TLS legs, timers, cancellation, and output
backpressure while preserving the same core contract. Its bounded priority
lane keeps protocol control traffic, timers, flushing, and cancellation live
when application output is temporarily full.

Run the complete in-memory example:

```sh
moon run --target native examples/sans_io_datachannel
```

The schema-free WebSocket signaling relay is in
[`examples/websocket_signaling`](examples/websocket_signaling). Signaling,
media capture, codecs, rendering, and device integration intentionally remain
application concerns.

## Development and acceptance

The upstream audit expects `--upstream` to point to a `webrtc-rs/rtc`
checkout at the commit recorded in [`UPSTREAM.md`](UPSTREAM.md).

```sh
moon fmt --check
moon check --target native --warn-list +73
moon test --target native
scripts/test-rust-interop
scripts/test-chromium-interop
scripts/test-coturn-interop
scripts/audit-upstream.mjs \
  --upstream /path/to/webrtc-rs-rtc \
  --write-ledger docs/upstream-coverage.json
moon bench --release --target native --no-parallelize
moon info
```

The ASan entry point is `scripts/run-asan.mjs`. The performance gate is
`scripts/bench-gate.mjs`. Its committed
[`benchmarks/baseline.json`](benchmarks/baseline.json) binds the fixed
workloads and 20 raw samples to clean commit
`29f4ff26dcb507715a0bfdacd58a0a3b48f3c776`. See
[`benchmarks/README.md`](benchmarks/README.md).

The generated per-item upstream inventory is
[`docs/upstream-coverage.json`](docs/upstream-coverage.json). Public interfaces
are reviewed through every `pkg.generated.mbti`; DTLS record ciphers, PRF/key
schedule helpers, crypto providers, parsers, and replay state remain internal.

The project is dual-licensed under MIT or Apache-2.0. It remains pre-1.0 while
the reviewed public API is intentionally experimental.
