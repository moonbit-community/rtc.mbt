# Examples

- `sans_io_datachannel` negotiates two `PeerConnection` instances and moves
  every datagram through an in-memory loop. It is the smallest complete example
  of the core Sans-I/O contract.
- `websocket_signaling` is a deliberately schema-free signaling relay. It
  broadcasts UTF-8 text frames between connected peers; applications can send
  JSON containing offers, answers, and trickled ICE candidates. Signaling is
  intentionally outside the RTC core.

Build either example with:

```sh
moon build --target native examples/sans_io_datachannel
moon build --target native examples/websocket_signaling
```

Run the relay with:

```sh
moon run --target native examples/websocket_signaling
```

The relay does not authenticate clients or persist messages. It is suitable for
local examples, not production deployment.
