///|
fn swap_datagram(
  datagram : @rtc.OutboundDatagram,
  now : @rtc.Instant,
) -> @rtc.InboundDatagram {
  {
    now,
    context: {
      local_address: datagram.context.peer,
      peer: datagram.context.local_address,
      ecn: datagram.context.ecn,
      protocol: datagram.context.protocol,
    },
    payload: datagram.payload,
  }
}

///|
fn[T] test_stun(
  operation : () -> T raise @stun.StunError,
) -> T raise @rtc.RtcError {
  operation() catch {
    error => raise Stun(error)
  }
}

///|
fn gather_test_relay(
  peer : @rtc.PeerConnection,
  relayed_address : @rtc.SocketAddress,
  now : @rtc.Instant,
) -> Unit raise @rtc.RtcError {
  ignore(peer.create_offer(now))
  guard peer.poll_datagram() is Some(initial_datagram) else {
    raise InvalidState("test TURN server did not receive Allocate")
  }
  let initial = test_stun(() => @stun.Message::decode(initial_datagram.payload))
  let challenge = test_stun(() => {
    @stun.Message::new(
      class=ErrorResponse,
      stun_method=Allocate,
      transaction_id=initial.transaction_id(),
      attributes=[
        @stun.Attribute::from_error(
          @stun.ResponseError::with_default_reason(401),
        ),
        @stun.Attribute::realm("relay.test"),
        @stun.Attribute::nonce("relay-nonce"),
      ],
    ).encode()
  })
  peer.handle_datagram({
    now,
    context: initial_datagram.context,
    payload: challenge,
  })
  guard peer.poll_datagram() is Some(authenticated_datagram) else {
    raise InvalidState(
      "test TURN server did not receive authenticated Allocate",
    )
  }
  let authenticated = test_stun(() => {
    @stun.Message::decode(authenticated_datagram.payload)
  })
  let key = @turn.long_term_key("relay-user", "relay.test", "relay-pass")
  test_stun(() => authenticated.verify_integrity(key))
  let success = test_stun(() => {
    @stun.Message::new(
      class=SuccessResponse,
      stun_method=Allocate,
      transaction_id=authenticated.transaction_id(),
      attributes=[
        @stun.Attribute::from_xor_address(
          relayed_address,
          authenticated.transaction_id(),
          attribute_type=XorRelayedAddress,
        ),
        @stun.Attribute::lifetime(600U),
      ],
    ).encode_authenticated(key)
  })
  peer.handle_datagram({
    now,
    context: authenticated_datagram.context,
    payload: success,
  })
}

///|
fn gather_test_stream_relay(
  url : String,
  expected_tls : Bool,
  expected_server_port : UInt16,
) -> Unit raise @rtc.RtcError {
  let host_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=52000,
  )
  let server_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::v4(192, 0, 2, 200),
    port=expected_server_port,
  )
  let relayed_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::v4(198, 51, 100, 200),
    port=55000,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0) catch {
      _ => raise InvalidState("invalid TURN stream test time")
    },
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let host_candidate = @ice.IceCandidate::host(
    foundation="turn-stream-host",
    host_address,
  ) catch {
    error => raise Ice(error)
  }
  let peer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[
        @rtc.IceServer::new(
          urls=[url],
          username="relay-user",
          credential="relay-pass",
        ),
      ],
      host_candidates=[host_candidate],
    ),
    sample,
  )
  ignore(peer.create_offer(sample.monotonic()))
  guard peer.poll_io_action() is Some(connect_action) else {
    raise InvalidState("TURN stream allocation omitted its connect action")
  }
  let connection = match connect_action {
    ConnectTcp(connection~, local_address~, peer=server) => {
      if expected_tls || server != server_address {
        raise InvalidState("TURN stream used the wrong TCP connect action")
      }
      guard local_address is Some(bound_address) && bound_address.port() == 0 else {
        raise InvalidState("TURN TCP connect did not use an ephemeral port")
      }
      connection
    }
    ConnectTls(connection~, local_address~, peer=server, server_name=None) => {
      if !expected_tls || server != server_address {
        raise InvalidState("TURN stream used the wrong TLS connect action")
      }
      guard local_address is Some(bound_address) && bound_address.port() == 0 else {
        raise InvalidState("TURN TLS connect did not use an ephemeral port")
      }
      connection
    }
    _ => raise InvalidState("TURN stream used the wrong connect action")
  }
  let connected_context : @rtc.TransportContext = {
    local_address: @rtc.SocketAddress::new(
      address=host_address.address(),
      port=53000,
    ),
    peer: server_address,
    ecn: None,
    protocol: Tcp,
  }
  peer.handle_io_event(
    StreamConnected(
      now=sample.monotonic(),
      connection~,
      context=connected_context,
    ),
  )
  guard peer.poll_io_action()
    is Some(WriteStream(connection=write_connection, bytes=initial_frame)) &&
    write_connection == connection else {
    raise InvalidState("TURN stream omitted its Allocate request")
  }
  let initial = test_stun(() => @stun.Message::decode(initial_frame))
  let challenge = test_stun(() => {
    @stun.Message::new(
      class=ErrorResponse,
      stun_method=Allocate,
      transaction_id=initial.transaction_id(),
      attributes=[
        @stun.Attribute::from_error(
          @stun.ResponseError::with_default_reason(401),
        ),
        @stun.Attribute::realm("relay.test"),
        @stun.Attribute::nonce("relay-stream-nonce"),
      ],
    ).encode()
  })
  deliver_stream_chunks(peer, connection, challenge, sample.monotonic())
  guard peer.poll_io_action()
    is Some(WriteStream(connection=retry_connection, bytes=retry_frame)) &&
    retry_connection == connection else {
    raise InvalidState("TURN stream omitted its authenticated Allocate")
  }
  let retry = test_stun(() => @stun.Message::decode(retry_frame))
  let key = @turn.long_term_key("relay-user", "relay.test", "relay-pass")
  test_stun(() => retry.verify_integrity(key))
  let success = test_stun(() => {
    @stun.Message::new(
      class=SuccessResponse,
      stun_method=Allocate,
      transaction_id=retry.transaction_id(),
      attributes=[
        @stun.Attribute::from_xor_address(
          relayed_address,
          retry.transaction_id(),
          attribute_type=XorRelayedAddress,
        ),
        @stun.Attribute::lifetime(600U),
      ],
    ).encode_authenticated(key)
  })
  deliver_stream_chunks(peer, connection, success, sample.monotonic())
  let mut saw_relay = false
  while peer.poll_event() is Some(event) {
    match event {
      IceCandidateDiscovered(candidate) =>
        if candidate.candidate_type() == Relay &&
          candidate.socket_address() == Some(relayed_address) {
          saw_relay = true
        }
      _ => ()
    }
  }
  if !saw_relay {
    raise InvalidState("TURN stream allocation omitted its relay candidate")
  }
}

///|
test "PeerConnection gathers TURN relay over TCP and TLS stream legs" {
  gather_test_stream_relay("turn:192.0.2.200?transport=tcp", false, 3478)
  gather_test_stream_relay("turns:192.0.2.200", true, 5349)
}

///|
fn serve_test_turn_datagram(
  source : @rtc.PeerConnection,
  destination : @rtc.PeerConnection,
  datagram : @rtc.OutboundDatagram,
  source_relay : @rtc.SocketAddress,
  destination_relay : @rtc.SocketAddress,
  destination_local : @rtc.SocketAddress,
  server : @rtc.SocketAddress,
  now : @rtc.Instant,
) -> Unit raise @rtc.RtcError {
  if datagram.context.peer != server {
    raise InvalidState("relay-only peer emitted a direct datagram")
  }
  let message = test_stun(() => @stun.Message::decode(datagram.payload))
  let key = @turn.long_term_key("relay-user", "relay.test", "relay-pass")
  match (message.class(), message.stun_method()) {
    (Request, CreatePermission) => {
      test_stun(() => message.verify_integrity(key))
      let response = test_stun(() => {
        @stun.Message::new(
          class=SuccessResponse,
          stun_method=CreatePermission,
          transaction_id=message.transaction_id(),
          attributes=[],
        ).encode_authenticated(key)
      })
      source.handle_datagram({
        now,
        context: datagram.context,
        payload: response,
      })
    }
    (Indication, Send) => {
      guard message.first_attribute(XorPeerAddress) is Some(peer_attribute) &&
        message.first_attribute(DataAttribute) is Some(data_attribute) else {
        raise InvalidState("test TURN Send indication is incomplete")
      }
      let addressed_peer = test_stun(() => {
        peer_attribute.to_xor_address(message.transaction_id())
      })
      if addressed_peer != destination_relay {
        raise InvalidState(
          "test TURN Send indication targeted an unknown relay",
        )
      }
      let transaction_id = test_stun(() => @stun.TransactionId::random())
      let indication = test_stun(() => {
        @stun.Message::new(
          class=Indication,
          stun_method=Data,
          transaction_id~,
          attributes=[
            @stun.Attribute::from_xor_address(
              source_relay,
              transaction_id,
              attribute_type=XorPeerAddress,
            ),
            @stun.Attribute::new(
              attribute_type=DataAttribute,
              value=data_attribute.value(),
            ),
          ],
        ).encode()
      })
      destination.handle_datagram({
        now,
        context: {
          local_address: destination_local,
          peer: server,
          ecn: None,
          protocol: Udp,
        },
        payload: indication,
      })
    }
    _ => raise InvalidState("test TURN server received an unexpected packet")
  }
}

///|
fn pump_relayed_peers(
  offerer : @rtc.PeerConnection,
  answerer : @rtc.PeerConnection,
  offerer_relay : @rtc.SocketAddress,
  answerer_relay : @rtc.SocketAddress,
  offerer_local : @rtc.SocketAddress,
  answerer_local : @rtc.SocketAddress,
  server : @rtc.SocketAddress,
  now : @rtc.Instant,
) -> Bool raise @rtc.RtcError {
  for round = 0; round < 32768; round = round + 1 {
    let mut progressed = false
    match offerer.poll_datagram() {
      Some(datagram) => {
        serve_test_turn_datagram(
          offerer, answerer, datagram, offerer_relay, answerer_relay, answerer_local,
          server, now,
        )
        progressed = true
      }
      None => ()
    }
    match answerer.poll_datagram() {
      Some(datagram) => {
        serve_test_turn_datagram(
          answerer, offerer, datagram, answerer_relay, offerer_relay, offerer_local,
          server, now,
        )
        progressed = true
      }
      None => ()
    }
    if !progressed {
      return true
    }
  }
  false
}

///|
fn pump_peers(
  offerer : @rtc.PeerConnection,
  answerer : @rtc.PeerConnection,
  now : @rtc.Instant,
) -> Bool raise @rtc.RtcError {
  for round = 0; round < 16384; round = round + 1 {
    let mut progressed = false
    match offerer.poll_datagram() {
      Some(datagram) => {
        answerer.handle_datagram(swap_datagram(datagram, now))
        progressed = true
      }
      None => ()
    }
    match answerer.poll_datagram() {
      Some(datagram) => {
        offerer.handle_datagram(swap_datagram(datagram, now))
        progressed = true
      }
      None => ()
    }
    if !progressed {
      return true
    }
  }
  false
}

///|
struct TcpTestNetwork {
  mut listener : @rtc.ListenerId?
  mut client_connection : @rtc.ConnectionId?
  server_connection : @rtc.ConnectionId
  client_address : @rtc.SocketAddress
  server_address : @rtc.SocketAddress
}

///|
fn deliver_stream_chunks(
  destination : @rtc.PeerConnection,
  connection : @rtc.ConnectionId,
  bytes : Bytes,
  now : @rtc.Instant,
) -> Unit raise @rtc.RtcError {
  let split = if bytes.length() > 1 { bytes.length() / 2 } else { 1 }
  destination.handle_io_event(
    StreamBytes(now~, connection~, bytes=bytes[0:split].to_owned()),
  )
  if split < bytes.length() {
    destination.handle_io_event(
      StreamBytes(now~, connection~, bytes=bytes[split:].to_owned()),
    )
  }
}

///|
fn pump_tcp_peers(
  client : @rtc.PeerConnection,
  server : @rtc.PeerConnection,
  network : TcpTestNetwork,
  now : @rtc.Instant,
) -> Bool raise @rtc.RtcError {
  for round = 0; round < 32768; round = round + 1 {
    let mut progressed = false
    match server.poll_io_action() {
      Some(ListenTcp(listener~, local_address~)) => {
        if local_address != network.server_address {
          raise InvalidState("ICE TCP listener used the wrong address")
        }
        network.listener = Some(listener)
        progressed = true
      }
      Some(WriteStream(connection~, bytes~)) => {
        guard network.client_connection is Some(client_connection) &&
          connection == network.server_connection else {
          raise InvalidState("unknown server ICE TCP stream")
        }
        deliver_stream_chunks(client, client_connection, bytes, now)
        progressed = true
      }
      Some(SendDatagram(_)) =>
        raise InvalidState("ICE TCP server emitted a UDP datagram")
      Some(_) =>
        raise InvalidState("ICE TCP server emitted an unexpected I/O action")
      None => ()
    }
    match client.poll_io_action() {
      Some(ConnectTcp(connection~, local_address=_, peer~)) => {
        if peer != network.server_address ||
          network.client_connection is Some(_) {
          raise InvalidState("unexpected ICE TCP connect action")
        }
        guard network.listener is Some(listener) else {
          raise InvalidState("ICE TCP connect preceded the passive listener")
        }
        network.client_connection = Some(connection)
        let client_context : @rtc.TransportContext = {
          local_address: network.client_address,
          peer: network.server_address,
          ecn: None,
          protocol: Tcp,
        }
        let server_context : @rtc.TransportContext = {
          local_address: network.server_address,
          peer: network.client_address,
          ecn: None,
          protocol: Tcp,
        }
        client.handle_io_event(
          StreamConnected(now~, connection~, context=client_context),
        )
        server.handle_io_event(
          StreamAccepted(
            now~,
            listener~,
            connection=network.server_connection,
            context=server_context,
          ),
        )
        progressed = true
      }
      Some(WriteStream(connection~, bytes~)) => {
        guard network.client_connection == Some(connection) else {
          raise InvalidState("unknown client ICE TCP stream")
        }
        deliver_stream_chunks(server, network.server_connection, bytes, now)
        progressed = true
      }
      Some(SendDatagram(_)) =>
        raise InvalidState("ICE TCP client emitted a UDP datagram")
      Some(_) =>
        raise InvalidState("ICE TCP client emitted an unexpected I/O action")
      None => ()
    }
    if !progressed {
      return true
    }
  }
  false
}

///|
fn saw_channel_open(
  peer : @rtc.PeerConnection,
  stream : @sctp.StreamId,
) -> Bool {
  let mut found = false
  while peer.poll_event() is Some(event) {
    match event {
      DataChannelOpened(channel) if channel.id() == stream => found = true
      _ => ()
    }
  }
  found
}

///|
fn saw_channel_closed(
  peer : @rtc.PeerConnection,
  stream : @sctp.StreamId,
) -> Bool {
  let mut found = false
  while peer.poll_event() is Some(event) {
    match event {
      DataChannelClosed(value) if value == stream => found = true
      _ => ()
    }
  }
  found
}

///|
fn saw_buffered_amount_low(
  peer : @rtc.PeerConnection,
  stream : @sctp.StreamId,
) -> Bool {
  let mut found = false
  while peer.poll_event() is Some(event) {
    match event {
      BufferedAmountLow(value) if value == stream => found = true
      _ => ()
    }
  }
  found
}

///|
fn without_sdp_candidates(
  description : @rtc.SessionDescription,
) -> @rtc.SessionDescription {
  let sdp = description
    .sdp()
    .split("\r\n")
    .filter(line => !line.has_prefix("a=candidate:"))
    .map(line => line.to_owned())
    .to_array()
    .join("\r\n")
  @rtc.SessionDescription::new(sdp_type=description.sdp_type(), sdp~)
}

///|
test "two PeerConnections negotiate host ICE, DTLS, SCTP, and DataChannel" {
  let offerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=50000,
  )
  let answerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=50001,
  )
  let offerer_candidate = @ice.IceCandidate::host(
    foundation="offerer",
    offerer_address,
  )
  let answerer_candidate = @ice.IceCandidate::host(
    foundation="answerer",
    answerer_address,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[offerer_candidate]),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[answerer_candidate]),
    sample,
  )
  let channel = offerer.create_data_channel(
    @rtc.DataChannelConfig::new(label="chat", protocol="moonbit"),
    sample.monotonic(),
  )
  assert_eq(channel.id(), StreamId(1))
  offerer.set_data_channel_buffered_amount_low_threshold(channel.id(), 1000UL)
  assert_eq(
    offerer.data_channel_buffered_amount_low_threshold(channel.id()),
    1000UL,
  )

  let offer = offerer.create_offer(sample.monotonic())
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())

  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  assert_true(saw_channel_open(offerer, channel.id()))
  assert_true(saw_channel_open(answerer, channel.id()))

  offerer.handle_message(
    DataChannel(
      channel_id=channel.id(),
      message=Text("hello through the complete stack 🌙"),
    ),
    sample.monotonic(),
  )
  offerer.handle_message(
    DataChannel(
      channel_id=channel.id(),
      message=Binary(Bytes::make(2500, 0xa5)),
    ),
    sample.monotonic(),
  )
  assert_true(offerer.data_channel_buffered_amount(channel.id()) > 0UL)
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.data_channel_buffered_amount(channel.id()), 0UL)
  assert_true(saw_buffered_amount_low(offerer, channel.id()))
  assert_eq(
    answerer.poll_message(),
    Some(
      DataChannel(
        channel_id=channel.id(),
        message=Text("hello through the complete stack 🌙"),
      ),
    ),
  )
  assert_eq(
    answerer.poll_message(),
    Some(
      DataChannel(
        channel_id=channel.id(),
        message=Binary(Bytes::make(2500, 0xa5)),
      ),
    ),
  )

  let initial_ice_credentials = offer.datachannel_parameters().ice_credentials()
  offerer.restart_ice(sample.monotonic())
  let restart_offer = offerer.create_offer(sample.monotonic())
  assert_true(
    restart_offer.datachannel_parameters().ice_credentials() !=
    initial_ice_credentials,
  )
  offerer.set_local_description(restart_offer, sample.monotonic())
  answerer.set_remote_description(restart_offer, sample.monotonic())
  let restart_answer = answerer.create_answer(sample.monotonic())
  answerer.set_local_description(restart_answer, sample.monotonic())
  offerer.set_remote_description(restart_answer, sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  offerer.handle_message(
    DataChannel(channel_id=channel.id(), message=Text("after ICE restart")),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(
    answerer.poll_message(),
    Some(
      DataChannel(channel_id=channel.id(), message=Text("after ICE restart")),
    ),
  )

  offerer.close_data_channel(channel.id(), sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_true(saw_channel_closed(offerer, channel.id()))
  assert_true(saw_channel_closed(answerer, channel.id()))
  let offerer_stats = offerer.stats(sample.monotonic())
  let answerer_stats = answerer.stats(sample.monotonic())
  assert_true(offerer_stats.packets_sent > 0UL)
  assert_true(answerer_stats.packets_received > 0UL)
  assert_eq(offerer_stats.data_channels_opened, 1U)
  assert_eq(answerer_stats.data_channels_closed, 1U)
}

///|
test "PeerConnection settings drive PSK DTLS and the answering role" {
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let settings = @rtc.Settings::new(
    dtls_psk=b"peer-connection-shared-secret",
    dtls_psk_identity=b"rtc.mbt",
    answering_dtls_role=Server,
    sctp_max_payload_size=700,
    sctp_send_buffer_size=131072UL,
    sctp_receive_buffer_size=131072U,
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      host_candidates=[
        @ice.IceCandidate::host(
          foundation="psk-offerer",
          @rtc.SocketAddress::new(
            address=@rtc.IpAddress::loopback_v4(),
            port=50500,
          ),
        ),
      ],
      settings~,
    ),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      host_candidates=[
        @ice.IceCandidate::host(
          foundation="psk-answerer",
          @rtc.SocketAddress::new(
            address=@rtc.IpAddress::loopback_v4(),
            port=50501,
          ),
        ),
      ],
      settings~,
    ),
    sample,
  )
  let channel = offerer.create_data_channel(
    @rtc.DataChannelConfig::new(label="psk-settings"),
    sample.monotonic(),
  )
  let offer = offerer.create_offer(sample.monotonic())
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  assert_true(answer.sdp().contains("a=setup:passive"))
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  offerer.handle_message(
    DataChannel(
      channel_id=channel.id(),
      message=Text("configured PSK transport"),
    ),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(
    answerer.poll_message(),
    Some(
      DataChannel(
        channel_id=channel.id(),
        message=Text("configured PSK transport"),
      ),
    ),
  )
}

///|
test "PeerConnection settings drive ICE disconnected and failed states" {
  let start = @rtc.Instant::from_milliseconds(0)
  let sample = @rtc.ClockSample::new(
    monotonic=start,
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      host_candidates=[
        @ice.IceCandidate::host(
          foundation="liveness-offerer",
          @rtc.SocketAddress::new(
            address=@rtc.IpAddress::loopback_v4(),
            port=50600,
          ),
        ),
      ],
      settings=@rtc.Settings::new(
        ice_disconnected_timeout=@rtc.Duration::milliseconds(10),
        ice_failed_timeout=@rtc.Duration::milliseconds(20),
        ice_keepalive_interval=@rtc.Duration::milliseconds(5),
      ),
    ),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      @ice.IceCandidate::host(
        foundation="liveness-answerer",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=50601,
        ),
      ),
    ]),
    sample,
  )
  let channel = offerer.create_data_channel(
    @rtc.DataChannelConfig::new(label="liveness"),
    start,
  )
  let offer = offerer.create_offer(start)
  offerer.set_local_description(offer, start)
  answerer.set_remote_description(offer, start)
  let answer = answerer.create_answer(start)
  answerer.set_local_description(answer, start)
  offerer.set_remote_description(answer, start)
  assert_true(pump_peers(offerer, answerer, start))
  assert_eq(offerer.connection_state(), Connected)
  assert_true(saw_channel_open(offerer, channel.id()))
  assert_eq(offerer.poll_timeout(), Some(@rtc.Instant::from_milliseconds(5)))

  offerer.handle_timeout(@rtc.Instant::from_milliseconds(10))
  assert_eq(offerer.connection_state(), Disconnected)
  offerer.handle_timeout(@rtc.Instant::from_milliseconds(29))
  assert_eq(offerer.connection_state(), Disconnected)
  offerer.handle_timeout(@rtc.Instant::from_milliseconds(30))
  assert_eq(offerer.connection_state(), Failed)
}

///|
test "PeerConnection carries DataChannel over active/passive ICE TCP" {
  let advertised_client_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=0,
  )
  let connected_client_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=51000,
  )
  let server_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=51001,
  )
  let client_candidate = @ice.IceCandidate::tcp_host(
    foundation="tcp-active",
    advertised_client_address,
    tcp_type=Active,
  )
  let server_candidate = @ice.IceCandidate::tcp_host(
    foundation="tcp-passive",
    server_address,
    tcp_type=Passive,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let client = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[client_candidate]),
    sample,
  )
  let server = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[server_candidate]),
    sample,
  )
  let channel = client.create_data_channel(
    @rtc.DataChannelConfig::new(label="ice-tcp"),
    sample.monotonic(),
  )
  let offer = client.create_offer(sample.monotonic())
  assert_true(offer.sdp().contains(" tcp "))
  assert_true(offer.sdp().contains("tcptype active"))
  client.set_local_description(offer, sample.monotonic())
  server.set_remote_description(offer, sample.monotonic())
  let answer = server.create_answer(sample.monotonic())
  assert_true(answer.sdp().contains("tcptype passive"))
  server.set_local_description(answer, sample.monotonic())
  client.set_remote_description(answer, sample.monotonic())
  let network : TcpTestNetwork = {
    listener: None,
    client_connection: None,
    server_connection: ConnectionId(9000UL),
    client_address: connected_client_address,
    server_address,
  }
  assert_true(pump_tcp_peers(client, server, network, sample.monotonic()))
  assert_eq(client.connection_state(), Connected)
  assert_eq(server.connection_state(), Connected)
  assert_true(saw_channel_open(client, channel.id()))
  assert_true(saw_channel_open(server, channel.id()))
  client.handle_message(
    DataChannel(channel_id=channel.id(), message=Text("framed over ICE TCP")),
    sample.monotonic(),
  )
  assert_true(pump_tcp_peers(client, server, network, sample.monotonic()))
  assert_eq(
    server.poll_message(),
    Some(
      DataChannel(channel_id=channel.id(), message=Text("framed over ICE TCP")),
    ),
  )
  guard network.client_connection is Some(client_connection) else {
    fail("ICE TCP client connection identifier was not recorded")
  }
  client.handle_io_event(
    StreamWritable(now=sample.monotonic(), connection=client_connection),
  )
  server.handle_io_event(
    StreamWritable(now=sample.monotonic(), connection=network.server_connection),
  )
  client.handle_io_event(
    StreamEof(now=sample.monotonic(), connection=client_connection),
  )
  assert_eq(client.connection_state(), Disconnected)
  assert_eq(client.poll_io_action(), Some(CloseStream(client_connection)))
  client.handle_io_event(
    StreamClosed(now=sample.monotonic(), connection=client_connection),
  )
  server.handle_io_event(
    StreamError(
      now=sample.monotonic(),
      connection=network.server_connection,
      reason="test stream failure",
    ),
  )
  assert_eq(server.connection_state(), Disconnected)
  assert_eq(
    server.poll_io_action(),
    Some(CloseStream(network.server_connection)),
  )
  server.handle_io_event(
    StreamClosed(now=sample.monotonic(), connection=network.server_connection),
  )
}

///|
test "two PeerConnections negotiate and carry encrypted RTP and RTCP" {
  let offerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=50500,
  )
  let answerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=50501,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let encoded_transforms = @media.EncodedTransformPipeline::new()
  encoded_transforms.add(
    @media.EncodedTransform::new(name="xor-frame", handler=(_context, payload) => {
      let transformed : Array[Byte] = []
      for byte in payload {
        transformed.push(byte ^ 0x5a)
      }
      Bytes::from_array(transformed)
    }),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      host_candidates=[
        @ice.IceCandidate::host(foundation="offerer-media", offerer_address),
      ],
      encoded_transform_pipeline=encoded_transforms,
    ),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      host_candidates=[
        @ice.IceCandidate::host(foundation="answerer-media", answerer_address),
      ],
      encoded_transform_pipeline=encoded_transforms,
    ),
    sample,
  )
  let codec = @media.CodecCapability::new(
    mime_type="audio/opus",
    clock_rate=48000U,
    channels=2,
    fmtp="minptime=10;useinbandfec=1",
    rtcp_feedback=["transport-cc"],
  )
  let track = @rtc.MediaTrack::new(
    id="audio-track",
    stream_id="media-stream",
    kind=Audio,
    codec~,
  )
  ignore(offerer.add_track(track, sample.monotonic()))
  let video_codec = @media.CodecCapability::new(
    mime_type="video/vp8",
    clock_rate=90000U,
    rtcp_feedback=["nack", "nack pli", "transport-cc"],
  )
  let video_track = @rtc.MediaTrack::new(
    id="video-track",
    stream_id="media-stream",
    kind=Video,
    codec=video_codec,
  )
  let video_transceiver = offerer.add_track(video_track, sample.monotonic())
  offerer.set_sender_encodings(
    "video-track",
    [
      @media.RtpEncodingParameters::new(
        ssrc=0x11000001U,
        rtx_ssrc=0x21000001U,
        rid="high",
        max_bitrate=2500000UL,
        scalability_mode="L1T3",
      ),
      @media.RtpEncodingParameters::new(
        ssrc=0x11000002U,
        rtx_ssrc=0x21000002U,
        rid="medium",
        max_bitrate=1000000UL,
        scale_resolution_down_by=2.0,
        scalability_mode="L1T3",
      ),
      @media.RtpEncodingParameters::new(
        ssrc=0x11000003U,
        rtx_ssrc=0x21000003U,
        rid="low",
        active=false,
        max_bitrate=300000UL,
        scale_resolution_down_by=4.0,
        scalability_mode="L1T3",
      ),
    ],
    sample.monotonic(),
  )
  let offer = offerer.create_offer(sample.monotonic())
  assert_true(offer.sdp().contains("m=audio 9 UDP/TLS/RTP/SAVPF 111"))
  assert_true(offer.sdp().contains("a=rtpmap:97 rtx/90000"))
  assert_true(offer.sdp().contains("a=ssrc-group:FID"))
  assert_true(offer.sdp().contains("a=simulcast:send high;medium;~low"))
  assert_true(
    offer.sdp().contains("a=ssrc-group:SIM 285212673 285212674 285212675"),
  )
  assert_true(
    offer
    .sdp()
    .contains(
      "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
  )
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  assert_true(answer.sdp().contains("a=recvonly"))
  assert_true(
    answer
    .sdp()
    .contains(
      "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    ),
  )
  assert_true(answer.sdp().contains("a=simulcast:recv high;medium;~low"))
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  let mut saw_audio_track = false
  let mut saw_video_track = false
  while answerer.poll_event() is Some(event) {
    match event {
      TrackOpened(remote_track) if remote_track.id() == "audio-track" =>
        saw_audio_track = true
      TrackOpened(remote_track) if remote_track.id() == "video-track" =>
        saw_video_track = true
      _ => ()
    }
  }
  assert_true(saw_audio_track)
  assert_true(saw_video_track)

  guard offerer.local_track_ssrc("audio-track") is Some(ssrc) &&
    offerer.local_track_payload_type("audio-track") is Some(payload_type) else {
    fail("local RTP track did not receive transport parameters")
  }
  let packet = @rtp.Packet::new(
    marker=true,
    payload_type~,
    sequence_number=1,
    timestamp=960U,
    ssrc~,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=17).marshal(),
      ),
    ],
    payload=b"encoded opus frame",
  )
  offerer.handle_message(
    Rtp(track_id="audio-track", packet~),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(answerer.poll_message(), Some(Rtp(track_id="audio-track", packet~)))

  let pli = @rtcp.PictureLossIndicationPacket::new(
    sender_ssrc=0x55667788U,
    media_ssrc=ssrc,
  ).to_packet()
  answerer.handle_message(Rtcp(pli), sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.poll_message(), Some(Rtcp(pli)))

  guard offerer.local_track_ssrc("video-track") is Some(video_ssrc) &&
    offerer.local_track_payload_type("video-track") is Some(video_payload_type) else {
    fail("video track did not receive transport parameters")
  }
  assert_eq(
    video_transceiver.sender().track().map(value => value.id()),
    Some("video-track"),
  )
  let video_encodings = video_transceiver
    .sender()
    .parameters()
    .unwrap()
    .encodings()
  assert_eq(video_encodings.length(), 3)
  assert_eq(video_encodings[0].ssrc, Some(video_ssrc))
  assert_eq(video_encodings[0].payload_type, Some(video_payload_type))
  let video_packet_before = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=41,
    timestamp=6000U,
    ssrc=video_ssrc,
    payload=b"encoded VP8 frame 41",
  )
  offerer.handle_message(
    Rtp(track_id="video-track", packet=video_packet_before),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  let received_video_packet_before = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=41,
    timestamp=6000U,
    ssrc=video_ssrc,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=18).marshal(),
      ),
    ],
    payload=b"encoded VP8 frame 41",
  )
  assert_eq(
    answerer.poll_message(),
    Some(Rtp(track_id="video-track", packet=received_video_packet_before)),
  )

  let negotiated_video_encodings = offerer.local_track_encodings("video-track")
  assert_eq(negotiated_video_encodings.length(), 3)
  assert_true(negotiated_video_encodings[0].active)
  assert_true(negotiated_video_encodings[1].active)
  assert_false(negotiated_video_encodings[2].active)
  let medium_packet = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=1,
    timestamp=6000U,
    ssrc=0x11000002U,
    payload=b"encoded VP8 medium layer",
  )
  offerer.handle_message(
    Rtp(track_id="video-track", packet=medium_packet),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  let received_medium_packet = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=1,
    timestamp=6000U,
    ssrc=0x11000002U,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=19).marshal(),
      ),
    ],
    payload=b"encoded VP8 medium layer",
  )
  assert_eq(
    answerer.poll_message(),
    Some(Rtp(track_id="video-track", packet=received_medium_packet)),
  )
  let mut paused_rejected = false
  let paused_packet = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=1,
    timestamp=6000U,
    ssrc=0x11000003U,
    payload=b"paused layer",
  )
  offerer.handle_message(
    Rtp(track_id="video-track", packet=paused_packet),
    sample.monotonic(),
  ) catch {
    InvalidState(_) => paused_rejected = true
    _ => fail("unexpected paused simulcast encoding error")
  }
  assert_true(paused_rejected)

  let video_packet = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=42,
    timestamp=9000U,
    ssrc=video_ssrc,
    payload=b"encoded VP8 frame",
  )
  offerer.handle_message(
    Rtp(track_id="video-track", packet=video_packet),
    sample.monotonic(),
  )
  guard offerer.poll_datagram() is Some(dropped_media) else {
    fail("video RTP did not produce an SRTP datagram")
  }
  assert_true(
    dropped_media.payload[0] >= 128 && dropped_media.payload[0] <= 191,
  )
  assert_eq(
    ((dropped_media.payload[2].to_uint() << 8) |
    dropped_media.payload[3].to_uint()).to_uint16(),
    42,
  )

  let video_packet_after = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=43,
    timestamp=12000U,
    ssrc=video_ssrc,
    payload=b"encoded VP8 frame 43",
  )
  offerer.handle_message(
    Rtp(track_id="video-track", packet=video_packet_after),
    sample.monotonic(),
  )
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  let received_video_packet_after = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=43,
    timestamp=12000U,
    ssrc=video_ssrc,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=21).marshal(),
      ),
    ],
    payload=b"encoded VP8 frame 43",
  )
  assert_eq(
    answerer.poll_message(),
    Some(Rtp(track_id="video-track", packet=received_video_packet_after)),
  )
  let recovered_video_packet = @rtp.Packet::new(
    marker=true,
    payload_type=video_payload_type,
    sequence_number=42,
    timestamp=9000U,
    ssrc=video_ssrc,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=22).marshal(),
      ),
    ],
    payload=b"encoded VP8 frame",
  )
  assert_eq(
    answerer.poll_message(),
    Some(Rtp(track_id="video-track", packet=recovered_video_packet)),
  )

  let report_time = @rtc.Instant::from_milliseconds(1000)
  offerer.handle_timeout(report_time)
  answerer.handle_timeout(report_time)
  assert_true(pump_peers(offerer, answerer, report_time))
  let mut saw_sender_report = false
  while answerer.poll_message() is Some(message) {
    match message {
      Rtcp(SenderReport(_)) => saw_sender_report = true
      _ => ()
    }
  }
  let mut saw_receiver_report = false
  let mut saw_transport_feedback = false
  while offerer.poll_message() is Some(message) {
    match message {
      Rtcp(ReceiverReport(_)) => saw_receiver_report = true
      Rtcp(TransportFeedback(_)) => saw_transport_feedback = true
      _ => ()
    }
  }
  assert_true(saw_sender_report)
  assert_true(saw_receiver_report)
  assert_true(saw_transport_feedback)
  let offerer_detailed_stats = offerer.detailed_stats(report_time)
  let answerer_detailed_stats = answerer.detailed_stats(report_time)
  assert_eq(offerer_detailed_stats.outbound_rtp.length(), 4)
  assert_eq(answerer_detailed_stats.inbound_rtp.length(), 4)
  assert_true(
    offerer_detailed_stats.outbound_rtp.any(stream => {
      stream.rid == Some("medium") && stream.packets == 1UL
    }),
  )
  assert_true(
    offerer_detailed_stats.outbound_rtp.any(stream => {
      stream.rid == Some("low") && !stream.active && stream.packets == 0UL
    }),
  )
  assert_true(
    answerer_detailed_stats.inbound_rtp.any(stream => {
      stream.rid == Some("high") && stream.packets_lost == 0UL
    }),
  )
  assert_true(
    offerer_detailed_stats.transport.selected_candidate_pair_id is Some(_),
  )
  assert_true(
    answerer_detailed_stats.candidate_pairs.any(pair => pair.selected),
  )

  offerer.remove_track("video-track", report_time)
  assert_true(video_transceiver.sender().track() is None)
  let remove_offer = offerer.create_offer(report_time)
  offerer.set_local_description(remove_offer, report_time)
  answerer.set_remote_description(remove_offer, report_time)
  let remove_answer = answerer.create_answer(report_time)
  answerer.set_local_description(remove_answer, report_time)
  offerer.set_remote_description(remove_answer, report_time)
  assert_eq(offerer.signaling_state(), Stable)
  assert_eq(answerer.signaling_state(), Stable)
  let mut saw_video_closed = false
  while answerer.poll_event() is Some(event) {
    match event {
      TrackClosed("video-track") => saw_video_closed = true
      _ => ()
    }
  }
  assert_true(saw_video_closed)
  assert_false(
    answerer
    .transceivers()
    .any(transceiver => {
      transceiver
      .receiver()
      .track()
      .map(track => track.id() == "video-track")
      .unwrap_or(false)
    }),
  )

  let replacement_track = @rtc.MediaTrack::new(
    id="replacement-video-track",
    stream_id="replacement-media-stream",
    kind=Video,
    codec=video_codec,
  )
  ignore(offerer.add_track(replacement_track, report_time))
  let replacement_offer = offerer.create_offer(report_time)
  offerer.set_local_description(replacement_offer, report_time)
  answerer.set_remote_description(replacement_offer, report_time)
  let replacement_answer = answerer.create_answer(report_time)
  answerer.set_local_description(replacement_answer, report_time)
  offerer.set_remote_description(replacement_answer, report_time)
  let mut saw_replacement_opened = false
  while answerer.poll_event() is Some(event) {
    match event {
      TrackOpened(remote_track) if remote_track.id() ==
        "replacement-video-track" => saw_replacement_opened = true
      _ => ()
    }
  }
  assert_true(saw_replacement_opened)

  guard offerer.local_track_ssrc("replacement-video-track")
    is Some(replacement_ssrc) &&
    offerer.local_track_payload_type("replacement-video-track")
    is Some(replacement_payload_type) else {
    fail("replacement video track did not receive transport parameters")
  }
  let replacement_packet = @rtp.Packet::new(
    marker=true,
    payload_type=replacement_payload_type,
    sequence_number=1,
    timestamp=3000U,
    ssrc=replacement_ssrc,
    payload=b"replacement VP8 frame",
  )
  offerer.handle_message(
    Rtp(track_id="replacement-video-track", packet=replacement_packet),
    report_time,
  )
  assert_true(pump_peers(offerer, answerer, report_time))
  let received_replacement_packet = @rtp.Packet::new(
    marker=true,
    payload_type=replacement_payload_type,
    sequence_number=1,
    timestamp=3000U,
    ssrc=replacement_ssrc,
    extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=23).marshal(),
      ),
    ],
    payload=b"replacement VP8 frame",
  )
  assert_eq(
    answerer.poll_message(),
    Some(
      Rtp(
        track_id="replacement-video-track",
        packet=received_replacement_packet,
      ),
    ),
  )
}

///|
test "PeerConnection accepts a remote candidate trickled after signaling" {
  let offerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=51000,
  )
  let answerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=51001,
  )
  let offerer_candidate = @ice.IceCandidate::host(
    foundation="offerer-trickle",
    offerer_address,
  )
  let answerer_candidate = @ice.IceCandidate::host(
    foundation="answerer-trickle",
    answerer_address,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[offerer_candidate]),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[answerer_candidate]),
    sample,
  )
  ignore(
    offerer.create_data_channel(
      @rtc.DataChannelConfig::new(label="trickle"),
      sample.monotonic(),
    ),
  )
  let offer = offerer.create_offer(sample.monotonic())
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  let answer_without_candidates = without_sdp_candidates(answer)
  answerer.set_local_description(answer_without_candidates, sample.monotonic())
  offerer.set_remote_description(answer_without_candidates, sample.monotonic())
  offerer.add_ice_candidate(answerer_candidate, sample.monotonic())
  offerer.handle_timeout(sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
}

///|
test "provisional answers commit with a final answer" {
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      @ice.IceCandidate::host(
        foundation="pranswer-offerer",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=51500,
        ),
      ),
    ]),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      @ice.IceCandidate::host(
        foundation="pranswer-answerer",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=51501,
        ),
      ),
    ]),
    sample,
  )
  let offer = offerer.create_offer(sample.monotonic())
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let provisional = answerer.create_pranswer(sample.monotonic())
  assert_eq(provisional.sdp_type(), Pranswer)
  answerer.set_local_description(provisional, sample.monotonic())
  offerer.set_remote_description(provisional, sample.monotonic())
  assert_eq(answerer.signaling_state(), HaveLocalPranswer)
  assert_eq(offerer.signaling_state(), HaveRemotePranswer)
  let answer = answerer.create_answer(sample.monotonic())
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())
  assert_eq(answerer.signaling_state(), Stable)
  assert_eq(offerer.signaling_state(), Stable)
}

///|
test "remote rollback removes tracks and transceivers created by its offer" {
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(@rtc.Configuration::new(), sample)
  let answerer = @rtc.PeerConnection::new(@rtc.Configuration::new(), sample)
  let codec = @media.CodecCapability::new(
    mime_type="video/vp8",
    clock_rate=90000U,
  )
  ignore(
    offerer.add_track(
      @rtc.MediaTrack::new(
        id="rollback-track",
        stream_id="rollback-stream",
        kind=Video,
        codec~,
      ),
      sample.monotonic(),
    ),
  )
  let offer = offerer.create_offer(sample.monotonic())
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  assert_eq(answerer.signaling_state(), HaveRemoteOffer)
  assert_eq(answerer.transceivers().length(), 1)
  answerer.rollback(sample.monotonic())
  assert_eq(answerer.signaling_state(), Stable)
  assert_eq(answerer.transceivers().length(), 0)
  let mut opened = false
  let mut closed = false
  while answerer.poll_event() is Some(event) {
    match event {
      TrackOpened(track) if track.id() == "rollback-track" => opened = true
      TrackClosed("rollback-track") => closed = true
      _ => ()
    }
  }
  assert_true(opened)
  assert_true(closed)
}

///|
test "polite perfect negotiation resolves offer glare" {
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let left = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      @ice.IceCandidate::host(
        foundation="glare-left",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=51600,
        ),
      ),
    ]),
    sample,
  )
  let right = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      @ice.IceCandidate::host(
        foundation="glare-right",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=51601,
        ),
      ),
    ]),
    sample,
  )
  let left_offer = left.create_offer(sample.monotonic())
  let right_offer = right.create_offer(sample.monotonic())
  left.set_local_description(left_offer, sample.monotonic())
  right.set_local_description(right_offer, sample.monotonic())
  let mut collision_rejected = false
  left.set_remote_description_perfect(right_offer, Impolite, sample.monotonic()) catch {
    InvalidState(_) => collision_rejected = true
    _ => fail("unexpected perfect-negotiation error")
  }
  assert_true(collision_rejected)
  assert_eq(left.signaling_state(), HaveLocalOffer)
  right.set_remote_description_perfect(left_offer, Polite, sample.monotonic())
  assert_eq(right.signaling_state(), HaveRemoteOffer)
  let answer = right.create_answer(sample.monotonic())
  right.set_local_description(answer, sample.monotonic())
  left.set_remote_description(answer, sample.monotonic())
  assert_eq(right.signaling_state(), Stable)
  assert_eq(left.signaling_state(), Stable)
}

///|
test "QueryAndGather hides host addresses and resolves them through mDNS" {
  let offerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=52000,
  )
  let answerer_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=52001,
  )
  let offerer_candidate = @ice.IceCandidate::host(
    foundation="offerer-mdns",
    offerer_address,
  )
  let answerer_candidate = @ice.IceCandidate::host(
    foundation="answerer-mdns",
    answerer_address,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(mdns_mode=QueryAndGather, host_candidates=[
      offerer_candidate,
    ]),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(mdns_mode=QueryAndGather, host_candidates=[
      answerer_candidate,
    ]),
    sample,
  )
  let channel = offerer.create_data_channel(
    @rtc.DataChannelConfig::new(label="private-host"),
    sample.monotonic(),
  )
  let offer = offerer.create_offer(sample.monotonic())
  guard offer.datachannel_parameters().candidates() is [encoded_offer_candidate] else {
    fail("mDNS offer did not contain exactly one candidate")
  }
  let advertised_offer_candidate = @ice.IceCandidate::parse(
    encoded_offer_candidate,
  )
  assert_true(advertised_offer_candidate.address() is MdnsName(_))
  assert_false(offer.sdp().contains("127.0.0.1"))
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  assert_false(answer.sdp().contains("127.0.0.1"))
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())
  assert_true(pump_peers(offerer, answerer, sample.monotonic()))
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  assert_true(saw_channel_open(offerer, channel.id()))
  assert_true(saw_channel_open(answerer, channel.id()))
}

///|
test "PeerConnection gathers and trickles a server-reflexive candidate" {
  let local_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.10"),
    port=53000,
  )
  let server_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.200"),
    port=3478,
  )
  let mapped_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("198.51.100.10"),
    port=62000,
  )
  let local_candidate = @ice.IceCandidate::host(
    foundation="host-srflx",
    local_address,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let peer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[@rtc.IceServer::new(urls=["stun:192.0.2.200:3478"])],
      host_candidates=[local_candidate],
    ),
    sample,
  )
  let initial_offer = peer.create_offer(sample.monotonic())
  assert_eq(initial_offer.datachannel_parameters().candidates().length(), 1)
  guard peer.poll_datagram() is Some(binding_datagram) else {
    fail("PeerConnection did not emit a STUN gathering request")
  }
  assert_eq(binding_datagram.context.peer, server_address)
  let binding = @stun.Message::decode(binding_datagram.payload)
  let response = @stun.Message::new(
    class=SuccessResponse,
    stun_method=Binding,
    transaction_id=binding.transaction_id(),
    attributes=[
      @stun.Attribute::from_xor_address(
        mapped_address,
        binding.transaction_id(),
      ),
    ],
  ).encode()
  peer.handle_datagram({
    now: @transport.Instant::from_milliseconds(1),
    context: binding_datagram.context,
    payload: response,
  })
  let mut discovered_srflx : @rtc.IceCandidate? = None
  let mut gathering_complete = false
  while peer.poll_event() is Some(event) {
    match event {
      IceCandidateDiscovered(candidate) if candidate.candidate_type() ==
        ServerReflexive => discovered_srflx = Some(candidate)
      IceGatheringStateChanged(Complete) => gathering_complete = true
      _ => ()
    }
  }
  guard discovered_srflx is Some(candidate) else {
    fail("PeerConnection did not trickle the srflx candidate")
  }
  assert_eq(candidate.socket_address(), Some(mapped_address))
  assert_true(gathering_complete)
  let completed_offer = peer.create_offer(
    @transport.Instant::from_milliseconds(2),
  )
  assert_eq(completed_offer.datachannel_parameters().candidates().length(), 2)
}

///|
test "relay policy gathers a TURN candidate without exposing the host" {
  let local_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.60"),
    port=54000,
  )
  let server_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.210"),
    port=3478,
  )
  let relayed_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("198.51.100.60"),
    port=56000,
  )
  let host_candidate = @ice.IceCandidate::host(
    foundation="relay-base",
    local_address,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let peer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[
        @rtc.IceServer::new(
          urls=["turn:192.0.2.210:3478?transport=udp"],
          username="turn-user",
          credential="turn-pass",
        ),
      ],
      ice_transport_policy=Relay,
      host_candidates=[host_candidate],
    ),
    sample,
  )
  let initial_offer = peer.create_offer(sample.monotonic())
  assert_true(initial_offer.datachannel_parameters().candidates().is_empty())
  guard peer.poll_datagram() is Some(initial_allocate_datagram) else {
    fail("relay gathering did not emit TURN Allocate")
  }
  assert_eq(initial_allocate_datagram.context.peer, server_address)
  let initial_allocate = @stun.Message::decode(
    initial_allocate_datagram.payload,
  )
  let challenge = @stun.Message::new(
    class=ErrorResponse,
    stun_method=Allocate,
    transaction_id=initial_allocate.transaction_id(),
    attributes=[
      @stun.Attribute::from_error(@stun.ResponseError::with_default_reason(401)),
      @stun.Attribute::realm("rtc.test"),
      @stun.Attribute::nonce("turn-nonce"),
    ],
  ).encode()
  peer.handle_datagram({
    now: @transport.Instant::from_milliseconds(1),
    context: initial_allocate_datagram.context,
    payload: challenge,
  })
  guard peer.poll_datagram() is Some(authenticated_allocate_datagram) else {
    fail("relay gathering did not authenticate TURN Allocate")
  }
  let authenticated_allocate = @stun.Message::decode(
    authenticated_allocate_datagram.payload,
  )
  let key = @turn.long_term_key("turn-user", "rtc.test", "turn-pass")
  authenticated_allocate.verify_integrity(key)
  let success = @stun.Message::new(
    class=SuccessResponse,
    stun_method=Allocate,
    transaction_id=authenticated_allocate.transaction_id(),
    attributes=[
      @stun.Attribute::from_xor_address(
        relayed_address,
        authenticated_allocate.transaction_id(),
        attribute_type=XorRelayedAddress,
      ),
      @stun.Attribute::lifetime(600U),
    ],
  ).encode_authenticated(key)
  peer.handle_datagram({
    now: @transport.Instant::from_milliseconds(2),
    context: authenticated_allocate_datagram.context,
    payload: success,
  })
  let mut relay_candidate : @rtc.IceCandidate? = None
  while peer.poll_event() is Some(event) {
    match event {
      IceCandidateDiscovered(candidate) if candidate.candidate_type() == Relay =>
        relay_candidate = Some(candidate)
      _ => ()
    }
  }
  guard relay_candidate is Some(candidate) else {
    fail("relay gathering did not publish a relay candidate")
  }
  assert_eq(candidate.socket_address(), Some(relayed_address))
  let completed_offer = peer.create_offer(
    @transport.Instant::from_milliseconds(3),
  )
  guard completed_offer.datachannel_parameters().candidates()
    is [encoded_candidate] else {
    fail("relay-only SDP did not contain exactly one candidate")
  }
  assert_eq(@ice.IceCandidate::parse(encoded_candidate).candidate_type(), Relay)
  assert_false(completed_offer.sdp().contains("192.0.2.60"))
}

///|
test "two relay-only PeerConnections carry a DataChannel through TURN" {
  let offerer_local = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.70"),
    port=57000,
  )
  let answerer_local = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.71"),
    port=57001,
  )
  let server = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("192.0.2.220"),
    port=3478,
  )
  let offerer_relay = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("198.51.100.70"),
    port=58000,
  )
  let answerer_relay = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse("198.51.100.71"),
    port=58001,
  )
  let sample = @rtc.ClockSample::new(
    monotonic=@rtc.Instant::from_milliseconds(0),
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let server_config = @rtc.IceServer::new(
    urls=["turn:192.0.2.220:3478?transport=udp"],
    username="relay-user",
    credential="relay-pass",
  )
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[server_config],
      ice_transport_policy=Relay,
      host_candidates=[
        @ice.IceCandidate::host(foundation="offerer-relay-base", offerer_local),
      ],
    ),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[server_config],
      ice_transport_policy=Relay,
      host_candidates=[
        @ice.IceCandidate::host(
          foundation="answerer-relay-base",
          answerer_local,
        ),
      ],
    ),
    sample,
  )
  gather_test_relay(offerer, offerer_relay, sample.monotonic())
  gather_test_relay(answerer, answerer_relay, sample.monotonic())
  let channel = offerer.create_data_channel(
    @rtc.DataChannelConfig::new(label="relayed"),
    sample.monotonic(),
  )
  let offer = offerer.create_offer(sample.monotonic())
  assert_false(offer.sdp().contains("192.0.2.70"))
  offerer.set_local_description(offer, sample.monotonic())
  answerer.set_remote_description(offer, sample.monotonic())
  let answer = answerer.create_answer(sample.monotonic())
  assert_false(answer.sdp().contains("192.0.2.71"))
  answerer.set_local_description(answer, sample.monotonic())
  offerer.set_remote_description(answer, sample.monotonic())
  assert_true(
    pump_relayed_peers(
      offerer,
      answerer,
      offerer_relay,
      answerer_relay,
      offerer_local,
      answerer_local,
      server,
      sample.monotonic(),
    ),
  )
  assert_eq(offerer.connection_state(), Connected)
  assert_eq(answerer.connection_state(), Connected)
  assert_true(saw_channel_open(offerer, channel.id()))
  assert_true(saw_channel_open(answerer, channel.id()))
  offerer.handle_message(
    DataChannel(
      channel_id=channel.id(),
      message=Text("TURN carried this message"),
    ),
    sample.monotonic(),
  )
  assert_true(
    pump_relayed_peers(
      offerer,
      answerer,
      offerer_relay,
      answerer_relay,
      offerer_local,
      answerer_local,
      server,
      sample.monotonic(),
    ),
  )
  assert_eq(
    answerer.poll_message(),
    Some(
      DataChannel(
        channel_id=channel.id(),
        message=Text("TURN carried this message"),
      ),
    ),
  )
}
