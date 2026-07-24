# coturn interoperability fixture

The image in `image.txt` is coturn `4.14.0-r0` for Linux x86_64. The digest is
the immutable platform-manifest digest, not a mutable tag.

`scripts/test-coturn-interop` starts it on the host network with an isolated
test realm, a small relay-port range, and loopback peers enabled. The MoonBit
fixture performs authenticated allocations for two relay-only
`PeerConnection`s, then exercises TURN permission/channel binding, ICE, DTLS,
SCTP, text and fragmented binary DataChannel traffic, and stream reset.

Loopback peers are enabled only for this local acceptance fixture. Do not copy
that option into a production TURN deployment.
