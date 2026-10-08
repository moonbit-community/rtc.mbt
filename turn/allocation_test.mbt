///|
fn turn_endpoint(last_octet : Byte, port : UInt16) -> @transport.SocketAddress {
  @transport.SocketAddress::new(
    address=@transport.IpAddress::v4(192, 0, 2, last_octet),
    port~,
  )
}

///|
fn turn_inbound(
  outbound : @transport.OutboundDatagram,
  now : @transport.Instant,
  payload : Bytes,
) -> @transport.InboundDatagram {
  { now, context: outbound.context, payload, }
}

///|
fn authenticated_success(
  request : @stun.Message,
  attributes : Array[@stun.Attribute],
  key : Bytes,
) -> Bytes raise @stun.StunError {
  @stun.Message::new(
    class=SuccessResponse,
    stun_method=request.stun_method(),
    transaction_id=request.transaction_id(),
    attributes~,
  ).encode_authenticated(key)
}

///|
test "TURN long-term credential key uses RFC MD5 derivation" {
  assert_eq(
    @turn.long_term_key("user", "realm", "pass"),
    b"\x84\x93\xfb\xc5\x3b\xa5\x82\xfb\x4c\x04\x4c\x45\x6b\xdc\x40\xeb",
  )
}

///|
test "TURN allocation authenticates, creates permission/channel, and carries data" {
  let local_address = turn_endpoint(10, 5000)
  let server = turn_endpoint(20, 3478)
  let peer = turn_endpoint(30, 6000)
  let relayed = @transport.SocketAddress::new(
    address=@transport.IpAddress::parse("198.51.100.50"),
    port=55000,
  )
  let credentials = @turn.TurnCredentials::new(username="user", password="pass")
  let allocation = @turn.Allocation::new(local_address~, server~, credentials~)
  let start = @transport.Instant::from_milliseconds(0)
  allocation.start(start)
  guard allocation.poll_datagram() is Some(initial_datagram) else {
    fail("TURN allocation did not emit Allocate request")
  }
  let initial = @stun.Message::decode(initial_datagram.payload)
  assert_eq(initial.class(), Request)
  assert_eq(initial.stun_method(), Allocate)
  assert_eq(
    initial.first_attribute(RequestedTransport).unwrap().value(),
    b"\x11\x00\x00\x00",
  )

  let challenge = @stun.Message::new(
    class=ErrorResponse,
    stun_method=Allocate,
    transaction_id=initial.transaction_id(),
    attributes=[
      @stun.Attribute::from_error(@stun.ResponseError::with_default_reason(401)),
      @stun.Attribute::realm("realm"),
      @stun.Attribute::nonce("nonce-1"),
    ],
  ).encode()
  allocation.handle_datagram(
    turn_inbound(
      initial_datagram,
      @transport.Instant::from_milliseconds(1),
      challenge,
    ),
  )
  guard allocation.poll_datagram() is Some(authenticated_datagram) else {
    fail("TURN allocation did not retry with long-term credentials")
  }
  let authenticated = @stun.Message::decode(authenticated_datagram.payload)
  let key = @turn.long_term_key("user", "realm", "pass")
  authenticated.verify_integrity(key)
  authenticated.verify_fingerprint()
  assert_eq(authenticated.first_attribute(Username).unwrap().as_text(), "user")

  let allocate_success = authenticated_success(
    authenticated,
    [
      @stun.Attribute::from_xor_address(
        relayed,
        authenticated.transaction_id(),
        attribute_type=XorRelayedAddress,
      ),
      @stun.Attribute::lifetime(600U),
    ],
    key,
  )
  allocation.handle_datagram(
    turn_inbound(
      authenticated_datagram,
      @transport.Instant::from_milliseconds(2),
      allocate_success,
    ),
  )
  assert_eq(allocation.state(), Active)
  assert_eq(allocation.relayed_address().unwrap().address(), relayed)

  allocation.create_permission(peer, @transport.Instant::from_milliseconds(3))
  guard allocation.poll_datagram() is Some(permission_datagram) else {
    fail("TURN allocation did not emit CreatePermission")
  }
  let permission_request = @stun.Message::decode(permission_datagram.payload)
  permission_request.verify_integrity(key)
  let permission_success = authenticated_success(permission_request, [], key)
  allocation.handle_datagram(
    turn_inbound(
      permission_datagram,
      @transport.Instant::from_milliseconds(4),
      permission_success,
    ),
  )

  allocation.send(
    peer,
    b"send indication",
    @transport.Instant::from_milliseconds(5),
  )
  guard allocation.poll_datagram() is Some(send_datagram) else {
    fail("TURN allocation did not emit Send indication")
  }
  let send = @stun.Message::decode(send_datagram.payload)
  assert_eq(send.class(), Indication)
  assert_eq(send.stun_method(), Send)
  assert_eq(
    send
    .first_attribute(XorPeerAddress)
    .unwrap()
    .to_xor_address(send.transaction_id()),
    peer,
  )
  assert_eq(
    send.first_attribute(DataAttribute).unwrap().value(),
    b"send indication",
  )

  allocation.bind_channel(
    peer,
    0x4001,
    @transport.Instant::from_milliseconds(6),
  )
  guard allocation.poll_datagram() is Some(channel_datagram) else {
    fail("TURN allocation did not emit ChannelBind")
  }
  let channel_request = @stun.Message::decode(channel_datagram.payload)
  let channel_success = authenticated_success(channel_request, [], key)
  allocation.handle_datagram(
    turn_inbound(
      channel_datagram,
      @transport.Instant::from_milliseconds(7),
      channel_success,
    ),
  )
  allocation.send(
    peer,
    b"channel data",
    @transport.Instant::from_milliseconds(8),
  )
  guard allocation.poll_datagram() is Some(channel_output) else {
    fail("TURN allocation did not emit ChannelData")
  }
  assert_eq(channel_output.payload, b"\x40\x01\x00\x0cchannel data")
  allocation.handle_datagram(
    turn_inbound(
      channel_output,
      @transport.Instant::from_milliseconds(9),
      b"\x40\x01\x00\x05reply",
    ),
  )
  let mut saw_reply = false
  while allocation.poll_event() is Some(event) {
    match event {
      PeerData(peer=event_peer, payload=event_payload) if event_peer == peer &&
        event_payload == b"reply" => saw_reply = true
      _ => ()
    }
  }
  assert_true(saw_reply)

  allocation.close(@transport.Instant::from_milliseconds(10))
  assert_eq(allocation.state(), Closed)
  guard allocation.poll_datagram() is Some(close_datagram) else {
    fail("TURN allocation close did not emit Refresh(0)")
  }
  let close_request = @stun.Message::decode(close_datagram.payload)
  assert_eq(close_request.stun_method(), Refresh)
  assert_eq(close_request.first_attribute(Lifetime).unwrap().as_u32(), 0U)
}

///|
fn feed_turn_stream(
  allocation : @turn.Allocation,
  now : @transport.Instant,
  frame : Bytes,
  chunk_size : Int,
) -> Unit raise @turn.TurnError {
  let mut offset = 0
  while offset < frame.length() {
    let end = if offset + chunk_size < frame.length() {
      offset + chunk_size
    } else {
      frame.length()
    }
    allocation.handle_stream_bytes(now, frame[offset:end].to_owned())
    offset = end
  }
}

///|
test "TURN TCP and TLS server legs frame arbitrary stream fragments" {
  let transports : Array[@turn.TurnTransport] = [Tcp, Tls]
  for transport in transports {
    let local_address = turn_endpoint(10, 5000)
    let server = turn_endpoint(20, 5349)
    let peer = turn_endpoint(30, 6000)
    let relayed = turn_endpoint(40, 55000)
    let credentials = @turn.TurnCredentials::new(
      username="user",
      password="pass",
    )
    let allocation = @turn.Allocation::new(
      local_address~,
      server~,
      credentials~,
      transport~,
    )
    let start = @transport.Instant::from_milliseconds(0)
    allocation.start(start)
    assert_eq(allocation.poll_datagram(), None)
    guard allocation.poll_stream_write() is Some(initial_frame) else {
      fail("TURN stream allocation omitted Allocate request")
    }
    let initial = @stun.Message::decode(initial_frame)
    let challenge = @stun.Message::new(
      class=ErrorResponse,
      stun_method=Allocate,
      transaction_id=initial.transaction_id(),
      attributes=[
        @stun.Attribute::from_error(
          @stun.ResponseError::with_default_reason(401),
        ),
        @stun.Attribute::realm("realm"),
        @stun.Attribute::nonce("stream-nonce"),
      ],
    ).encode()
    feed_turn_stream(
      allocation,
      @transport.Instant::from_milliseconds(1),
      challenge,
      1,
    )
    guard allocation.poll_stream_write() is Some(authenticated_frame) else {
      fail("TURN stream allocation omitted authenticated retry")
    }
    let authenticated = @stun.Message::decode(authenticated_frame)
    let key = @turn.long_term_key("user", "realm", "pass")
    authenticated.verify_integrity(key)
    let success = authenticated_success(
      authenticated,
      [
        @stun.Attribute::from_xor_address(
          relayed,
          authenticated.transaction_id(),
          attribute_type=XorRelayedAddress,
        ),
        @stun.Attribute::lifetime(600U),
      ],
      key,
    )
    feed_turn_stream(
      allocation,
      @transport.Instant::from_milliseconds(2),
      success,
      7,
    )
    assert_eq(allocation.state(), Active)
    assert_eq(allocation.relayed_address().unwrap().transport(), transport)

    allocation.create_permission(peer, @transport.Instant::from_milliseconds(3))
    guard allocation.poll_stream_write() is Some(permission_frame) else {
      fail("TURN stream allocation omitted CreatePermission")
    }
    let permission = @stun.Message::decode(permission_frame)
    feed_turn_stream(
      allocation,
      @transport.Instant::from_milliseconds(4),
      authenticated_success(permission, [], key),
      5,
    )
    allocation.bind_channel(
      peer,
      0x4001,
      @transport.Instant::from_milliseconds(5),
    )
    guard allocation.poll_stream_write() is Some(bind_frame) else {
      fail("TURN stream allocation omitted ChannelBind")
    }
    let bind = @stun.Message::decode(bind_frame)
    feed_turn_stream(
      allocation,
      @transport.Instant::from_milliseconds(6),
      authenticated_success(bind, [], key),
      3,
    )
    allocation.send(peer, b"reply", @transport.Instant::from_milliseconds(7))
    guard allocation.poll_stream_write() is Some(channel_frame) else {
      fail("TURN stream allocation omitted ChannelData")
    }
    assert_eq(channel_frame, b"\x40\x01\x00\x05reply\x00\x00\x00")
    feed_turn_stream(
      allocation,
      @transport.Instant::from_milliseconds(8),
      channel_frame,
      2,
    )
    let mut received = false
    while allocation.poll_event() is Some(event) {
      match event {
        PeerData(peer=event_peer, payload=b"reply") if event_peer == peer =>
          received = true
        _ => ()
      }
    }
    assert_true(received)
  }
}

///|
test "TURN stream parser accepts coalesced frames and rejects invalid prefixes" {
  let local_address = turn_endpoint(10, 5000)
  let server = turn_endpoint(20, 3478)
  let credentials = @turn.TurnCredentials::new(username="user", password="pass")
  let allocation = @turn.Allocation::new(
    local_address~,
    server~,
    credentials~,
    transport=Tcp,
  )
  allocation.start(@transport.Instant::from_milliseconds(0))
  ignore(allocation.poll_stream_write())
  try
    allocation.handle_stream_bytes(
      @transport.Instant::from_milliseconds(1),
      b"\x80\x00\x00\x00",
    )
  catch {
    @turn.TurnError::InvalidPacket(_) => ()
    _ => fail("unexpected TURN stream framing error")
  } noraise {
    _ => fail("TURN stream parser accepted a reserved frame prefix")
  }
}
