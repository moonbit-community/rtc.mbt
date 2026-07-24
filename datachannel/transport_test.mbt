///|
fn[T] test_from_sctp(
  operation : () -> T raise @sctp.SctpError,
) -> T raise DataChannelError {
  operation() catch {
    error => raise Sctp(error)
  }
}

///|
fn transport_pair() -> (Transport, Transport) raise DataChannelError {
  let client = Transport::new(
    role=DtlsClient,
    association_config=test_from_sctp(() => {
      @sctp.AssociationConfig::new(
        role=Active,
        initial_tag=0x12345678U,
        initial_tsn=100U,
        max_payload_size=7,
      )
    }),
  )
  let server = Transport::new(
    role=DtlsServer,
    association_config=test_from_sctp(() => {
      @sctp.AssociationConfig::new(
        role=Passive,
        initial_tag=0x87654321U,
        initial_tsn=500U,
        max_payload_size=7,
      )
    }),
  )
  (client, server)
}

///|
fn pump_transports(
  client : Transport,
  server : Transport,
  now : @transport.Instant,
) -> Bool raise DataChannelError {
  for round = 0; round < 256; round = round + 1 {
    let mut progressed = false
    match client.poll_datagram() {
      Some(packet) => {
        server.handle_datagram(now, packet)
        progressed = true
      }
      None => ()
    }
    match server.poll_datagram() {
      Some(packet) => {
        client.handle_datagram(now, packet)
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
fn collect_messages(
  transport : Transport,
) -> Array[(@sctp.StreamId, DataChannelMessage)] {
  let result : Array[(@sctp.StreamId, DataChannelMessage)] = []
  while transport.poll_event() is Some(event) {
    match event {
      MessageReceived(stream, message) => result.push((stream, message))
      _ => ()
    }
  }
  result
}

///|
fn saw_opened(transport : Transport, stream : @sctp.StreamId) -> Bool {
  let mut found = false
  while transport.poll_event() is Some(event) {
    match event {
      Opened(channel) if channel.id() == stream => found = true
      _ => ()
    }
  }
  found
}

///|
fn saw_closed(transport : Transport, stream : @sctp.StreamId) -> Bool {
  let mut found = false
  while transport.poll_event() is Some(event) {
    match event {
      ClosedEvent(value) if value == stream => found = true
      _ => ()
    }
  }
  found
}

///|
fn saw_buffered_amount_low(
  transport : Transport,
  stream : @sctp.StreamId,
) -> Bool {
  let mut found = false
  while transport.poll_event() is Some(event) {
    match event {
      BufferedAmountLowEvent(value) if value == stream => found = true
      _ => ()
    }
  }
  found
}

///|
test "DataChannel transport runs SCTP, DCEP, fragmentation, empty PPIDs, and close" {
  let (client, server) = transport_pair()
  let now = @transport.Instant::from_milliseconds(0)
  client.start(now)
  server.start(now)
  assert_true(pump_transports(client, server, now))
  assert_eq(client.association_state(), Established)
  assert_eq(server.association_state(), Established)

  let channel = client.create_channel(
    DataChannelConfig::new(label="chat", protocol="moonbit"),
    now,
  )
  assert_eq(channel.id(), StreamId(0))
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(1)),
  )
  assert_true(saw_opened(client, channel.id()))
  assert_true(saw_opened(server, channel.id()))

  client.send(channel.id(), Text("fragmented hello 🌙"), now)
  client.send(channel.id(), Text(""), now)
  client.send(channel.id(), Binary(b""), now)
  client.send(
    channel.id(),
    Binary(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09"),
    now,
  )
  assert_true(client.buffered_amount(channel.id()) > 0UL)
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(2)),
  )
  assert_eq(client.buffered_amount(channel.id()), 0UL)
  assert_eq(collect_messages(server), [
    (channel.id(), Text("fragmented hello 🌙")),
    (channel.id(), Text("")),
    (channel.id(), Binary(b"")),
    (channel.id(), Binary(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09")),
  ])

  client.close_channel(channel.id(), @transport.Instant::from_milliseconds(3))
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(3)),
  )
  assert_true(saw_closed(client, channel.id()))
  assert_true(saw_closed(server, channel.id()))
  assert_eq(client.channel(channel.id()).unwrap().state(), Closed)
  assert_eq(server.channel(channel.id()).unwrap().state(), Closed)
}

///|
test "DataChannel transport multiplexes ordered, unordered, and PR-SCTP channels" {
  let (client, server) = transport_pair()
  let start = @transport.Instant::from_milliseconds(0)
  client.start(start)
  server.start(start)
  assert_true(pump_transports(client, server, start))
  let reliable = client.create_channel(
    DataChannelConfig::new(label="reliable"),
    start,
  )
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(1)),
  )
  assert_true(saw_opened(client, reliable.id()))
  assert_true(saw_opened(server, reliable.id()))
  let unordered = client.create_channel(
    DataChannelConfig::new(label="unordered", ordering=Unordered),
    @transport.Instant::from_milliseconds(2),
  )
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(2)),
  )
  assert_true(saw_opened(client, unordered.id()))
  assert_true(saw_opened(server, unordered.id()))
  let retransmit_limited = client.create_channel(
    DataChannelConfig::new(
      label="max-retransmits",
      ordering=Unordered,
      reliability=RetransmitCount(2),
    ),
    @transport.Instant::from_milliseconds(3),
  )
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(3)),
  )
  assert_true(saw_opened(client, retransmit_limited.id()))
  assert_true(saw_opened(server, retransmit_limited.id()))
  let lifetime_limited = client.create_channel(
    DataChannelConfig::new(label="max-lifetime", reliability=Timed(750U)),
    @transport.Instant::from_milliseconds(4),
  )
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(4)),
  )
  assert_true(saw_opened(client, lifetime_limited.id()))
  assert_true(saw_opened(server, lifetime_limited.id()))
  assert_eq(
    [
      reliable.id(),
      unordered.id(),
      retransmit_limited.id(),
      lifetime_limited.id(),
    ],
    [StreamId(0), StreamId(2), StreamId(4), StreamId(6)],
  )
  assert_eq(server.channel(unordered.id()).unwrap().ordering(), Unordered)
  assert_eq(
    server.channel(retransmit_limited.id()).unwrap().reliability(),
    RetransmitCount(2),
  )
  assert_eq(
    server.channel(lifetime_limited.id()).unwrap().reliability(),
    Timed(750U),
  )
  client.set_buffered_amount_low_threshold(unordered.id(), 4UL)
  client.send(reliable.id(), Text("ordered"), start)
  client.send(unordered.id(), Binary(b"unordered"), start)
  client.send(retransmit_limited.id(), Text("retry budget"), start)
  client.send(lifetime_limited.id(), Text("lifetime budget"), start)
  assert_true(
    pump_transports(client, server, @transport.Instant::from_milliseconds(5)),
  )
  assert_eq(collect_messages(server), [
    (reliable.id(), Text("ordered")),
    (unordered.id(), Binary(b"unordered")),
    (retransmit_limited.id(), Text("retry budget")),
    (lifetime_limited.id(), Text("lifetime budget")),
  ])
  assert_true(saw_buffered_amount_low(client, unordered.id()))
}
