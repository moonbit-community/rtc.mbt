# Architecture

The package graph follows protocol ownership:

```text
rtc facade
├── sdp
├── ice ── stun, turn, mdns
├── dtls ── internal/crypto, internal/replay
├── sctp ── internal/codec, internal/crypto
├── datachannel ── sctp
├── rtp, rtcp ── internal/codec
├── srtp ── rtp, rtcp, internal/crypto, internal/replay
├── interceptor ── rtp, rtcp
├── media ── rtp, rtcp
└── transport

runtime/async ── rtc facade, transport, moonbitlang/async
```

`transport` owns the concrete cross-package types: monotonic and wall-clock
time, addresses, transport context, UDP datagrams, stream/listener IDs, and
the complete Sans-I/O `IoEvent`/`IoAction` boundary. The root facade re-exports
the types applications normally need.

Internal packages own checked byte readers/writers, replay-window state, and
the dynamically loaded OpenSSL provider. OpenSSL handles, secrets, record
ciphers, DTLS PRF/key schedule helpers, and parser state are not application
API.

## Receive and send paths

TURN server-leg framing and mDNS resolution happen before peer packet
classification:

```text
UDP/TCP/TLS input
  ├── TURN response / Data Indication / ChannelData ──┐
  ├── mDNS query or answer                            │
  └── direct peer packet                              │
                                                     ▼
  RFC 7983 demux
  ├── STUN ── ICE checks and nomination
  ├── DTLS ── SCTP ── DCEP/DataChannel
  └── SRTP/SRTCP ── interceptors ── tracks/messages
```

Sending applies the inverse wrapping. Direct and relay paths remain distinct:
TURN allocations own authentication, refresh, permissions, channel bindings,
and stream framing, while ICE owns candidate pairs and selected peer paths.

The root aggregates the earliest deadline from TURN, mDNS, ICE, DTLS, SCTP,
RTCP, and media feedback. Every state machine consumes an explicit `Instant`.
Certificate validity and RTCP NTP timestamps derive from the injected
`ClockSample`; the core never reads an operating-system clock.

## Async driver

`Driver::create` transfers a `PeerConnection` into one driver and returns a
cloneable `PeerHandle` plus single-consumer event and message streams.
`Driver::run` binds configured UDP host candidates and executes TCP/TLS
connect/listen/accept/read/write actions emitted by the core.

Command, control-input, event, and message queues are bounded. When an output
queue is full, the driver retains a bounded pending item and pauses application
commands plus directly classified RTP ingress. A priority control lane keeps
STUN/TURN, DTLS/SCTP-bearing datagrams, RTCP, and ordered TCP/TLS stream input
moving; deadlines are checked before queued input, and outbound flushing plus
the independent close path also remain live. A coalescing wakeup queue avoids
lossy queue races while allowing a consumer read to resume paused ingress. If
capacity remains unavailable for 30 seconds, the driver terminates with
`BackpressureExceeded`. Task-group cleanup closes all queues, sockets, streams,
and listeners and wakes blocked operations.

Accepted stream IDs use the high half of the 64-bit identifier space; outbound
core-created streams use the low half. This prevents collisions without
letting the runtime driver assign protocol state.

## Public surface

Protocol packages expose their wire types and state-machine endpoints. The
root facade exposes JSEP, DataChannel/media operations, detailed statistics,
advanced settings, and the canonical Sans-I/O polling methods. The async
package only adds runtime ownership; signaling remains an application
protocol. Public-surface changes are reviewed by regenerating every
`pkg.generated.mbti`.
