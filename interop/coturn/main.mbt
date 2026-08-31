///|
async fn gather_relay(
  peer : @rtc.PeerConnection,
  socket : @socket.UdpServer,
  local_address : @rtc.SocketAddress,
  server_address : @rtc.SocketAddress,
) -> @ice.IceCandidate {
  let server = @socket.Addr::parse(server_address.to_string())
  let buffer : FixedArray[Byte] = FixedArray::make(65536, b'\x00')
  for attempt = 0; attempt < 12; attempt = attempt + 1 {
    let mut sent = false
    while peer.poll_datagram() is Some(datagram) {
      if datagram.context.local_address != local_address ||
        datagram.context.peer != server_address {
        fail("TURN gatherer emitted a datagram on an unexpected path")
      }
      socket.sendto(datagram.payload, server)
      sent = true
    }
    if !sent {
      fail("TURN gatherer stopped before publishing a relay candidate")
    }
    let (length, source) = socket.recvfrom(buffer)
    if source != server || length < 1 {
      fail("coturn replied from an unexpected address")
    }
    let payload = buffer.unsafe_reinterpret_as_bytes()[0:length].to_owned()
    let response = @stun.Message::decode(payload)
    match response.class() {
      ErrorResponse =>
        match response.first_attribute(ErrorCode) {
          Some(attribute) =>
            println(
              "coturn error response: " +
              attribute.to_error().code().to_string(),
            )
          None => println("coturn returned an error without ERROR-CODE")
        }
      SuccessResponse => println("coturn response: success")
      _ => println("coturn returned a non-response STUN message")
    }
    peer.handle_datagram({
      now: @rtc_async.sample_clock().monotonic(),
      context: {
        local_address,
        peer: server_address,
        ecn: None,
        protocol: Udp,
      },
      payload,
    })
    while peer.poll_event() is Some(event) {
      match event {
        IceCandidateDiscovered(candidate) if candidate.candidate_type() == Relay =>
          return candidate
        _ => ()
      }
    }
  }
  fail("coturn did not publish a relay candidate")
}

///|
async fn wait_for_open(
  events : @rtc_async.EventStream,
  channel : @rtc.DataChannel,
) -> Unit raise @rtc_async.DriverError {
  for ;; {
    match events.next() {
      Some(DataChannelOpened(opened)) if opened.id() == channel.id() => return
      Some(ConnectionStateChanged(Failed)) =>
        raise Io("PeerConnection failed before relayed DataChannel open")
      Some(_) => ()
      None => raise Io("event stream ended before relayed DataChannel open")
    }
  }
}

///|
async fn wait_for_close(
  events : @rtc_async.EventStream,
  channel : @rtc.DataChannel,
) -> Unit raise @rtc_async.DriverError {
  for ;; {
    match events.next() {
      Some(DataChannelClosed(channel_id)) if channel_id == channel.id() =>
        return
      Some(_) => ()
      None => raise Io("event stream ended before relayed DataChannel close")
    }
  }
}

///|
fn binary_fixture() -> Bytes {
  let bytes : Array[Byte] = []
  for index = 0; index < 2500; index = index + 1 {
    bytes.push(((index * 31 + 7) % 251).to_byte())
  }
  Bytes::from_array(bytes)
}

///|
async fn run(
  server_host : String,
  server_port : UInt16,
  username : String,
  password : String,
) -> Unit {
  let loopback = @rtc.IpAddress::loopback_v4()
  let server_address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::parse(server_host),
    port=server_port,
  )
  let offerer_socket = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
  let answerer_socket = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
  let offerer_local = @rtc.SocketAddress::new(
    address=loopback,
    port=offerer_socket.addr.port().to_uint16(),
  )
  let answerer_local = @rtc.SocketAddress::new(
    address=loopback,
    port=answerer_socket.addr.port().to_uint16(),
  )
  let turn_server = @rtc.IceServer::new(
    urls=["turn:" + server_address.to_string() + "?transport=udp"],
    username~,
    credential=password,
  )
  let sample = @rtc_async.sample_clock()
  let offerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[turn_server],
      ice_transport_policy=Relay,
      host_candidates=[
        @ice.IceCandidate::host(foundation="coturn-offerer", offerer_local),
      ],
    ),
    sample,
  )
  let answerer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(
      ice_servers=[turn_server],
      ice_transport_policy=Relay,
      host_candidates=[
        @ice.IceCandidate::host(foundation="coturn-answerer", answerer_local),
      ],
    ),
    sample,
  )
  ignore(offerer.create_offer(sample.monotonic()))
  ignore(answerer.create_offer(sample.monotonic()))
  let offerer_relay = gather_relay(
    offerer, offerer_socket, offerer_local, server_address,
  )
  let answerer_relay = gather_relay(
    answerer, answerer_socket, answerer_local, server_address,
  )
  if offerer_relay.candidate_type() != Relay ||
    answerer_relay.candidate_type() != Relay {
    fail("coturn gathering did not produce relay candidates")
  }
  offerer_socket.close()
  answerer_socket.close()
  @async_runtime.sleep(10)

  let now = @rtc_async.sample_clock().monotonic()
  let channel = offerer.create_data_channel(
    @datachannel.DataChannelConfig::new(label="coturn"),
    now,
  )
  let offer = offerer.create_offer(now)
  offerer.set_local_description(offer, now)
  answerer.set_remote_description(offer, now)
  let answer = answerer.create_answer(now)
  answerer.set_local_description(answer, now)
  offerer.set_remote_description(answer, now)

  let (offerer_driver, offerer_handle, offerer_events, _) = @rtc_async.Driver::create(
    offerer,
  )
  let (answerer_driver, answerer_handle, answerer_events, answerer_messages) = @rtc_async.Driver::create(
    answerer,
  )
  @async_runtime.with_task_group <| group => {
    let offerer_task = group.spawn(() => offerer_driver.run())
    let answerer_task = group.spawn(() => answerer_driver.run())
    wait_for_open(offerer_events, channel)
    wait_for_open(answerer_events, channel)
    offerer_handle.send(
      DataChannel(channel_id=channel.id(), message=Text("coturn relay text")),
    )
    offerer_handle.send(
      DataChannel(channel_id=channel.id(), message=Binary(binary_fixture())),
    )
    let mut saw_text = false
    let mut saw_binary = false
    while !saw_text || !saw_binary {
      match answerer_messages.next() {
        Some(DataChannel(channel_id~, message=Text(text))) if channel_id ==
          channel.id() &&
          text == "coturn relay text" => saw_text = true
        Some(DataChannel(channel_id~, message=Binary(bytes))) if channel_id ==
          channel.id() &&
          bytes == binary_fixture() => saw_binary = true
        Some(_) => fail("coturn relay delivered an unexpected message")
        None => fail("coturn relay message stream ended early")
      }
    }
    offerer_handle.close_data_channel(channel)
    wait_for_close(offerer_events, channel)
    wait_for_close(answerer_events, channel)
    offerer_handle.close()
    answerer_handle.close()
    offerer_task.wait()
    answerer_task.wait()
  }
}

///|
async fn main {
  guard @env.args()[1:] is [host, port_text, username, password] else {
    fail("usage: coturn HOST PORT USERNAME PASSWORD")
  }
  let port = @string.parse_int(port_text)
  if port < 1 || port > 65535 {
    fail("coturn port must be in 1..65535")
  }
  @async_runtime.with_timeout(30000) <| () => {
    run(host, port.to_uint16(), username, password)
  }
  println("Pinned coturn relay DataChannel interoperability: PASS")
}
