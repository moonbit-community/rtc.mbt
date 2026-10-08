///|
fn association_pair() -> (@sctp.Association, @sctp.Association) raise @sctp.SctpError {
  let active = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Active,
      initial_tag=0x11111111U,
      initial_tsn=100U,
      max_payload_size=8,
    ),
  )
  let passive = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Passive,
      initial_tag=0x22222222U,
      initial_tsn=500U,
      max_payload_size=8,
    ),
  )
  (active, passive)
}

///|
fn pump_association_setup(
  active : @sctp.Association,
  passive : @sctp.Association,
  now : @transport.Instant,
) -> Bool raise @sctp.SctpError {
  for step = 0; step < 20; step = step + 1 {
    match active.poll_datagram() {
      Some(packet) => passive.handle_datagram(now, packet)
      None => ()
    }
    match passive.poll_datagram() {
      Some(packet) => active.handle_datagram(now, packet)
      None => ()
    }
    if active.state() == Established && passive.state() == Established {
      return true
    }
  }
  false
}

///|
fn drain_packets(association : @sctp.Association) -> Array[Bytes] {
  let packets : Array[Bytes] = []
  while association.poll_datagram() is Some(packet) {
    packets.push(packet)
  }
  packets
}

///|
fn received_message(association : @sctp.Association) -> @sctp.Message? {
  let mut message : @sctp.Message? = None
  for index = 0; index < 32; index = index + 1 {
    match association.poll_event() {
      Some(MessageReceived(received)) => message = Some(received)
      Some(_) => ()
      None => ()
    }
  }
  message
}

///|
fn saw_stream_event(
  association : @sctp.Association,
  expected : @sctp.AssociationEvent,
) -> Bool {
  let mut found = false
  for index = 0; index < 32; index = index + 1 {
    match association.poll_event() {
      Some(event) if event == expected => found = true
      Some(_) => ()
      None => ()
    }
  }
  found
}

///|
test "SCTP INIT/COOKIE association survives a dropped INIT-ACK" {
  let (active, passive) = association_pair()
  let start = @transport.Instant::from_milliseconds(0)
  active.start(start)
  passive.start(start)
  guard active.poll_datagram() is Some(init) else {
    fail("active SCTP endpoint did not send INIT")
  }
  passive.handle_datagram(start, init)
  ignore(passive.poll_datagram())
  assert_eq(
    active.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(1000)),
  )
  active.handle_timeout(@transport.Instant::from_milliseconds(1000))
  guard active.poll_datagram() is Some(retransmitted_init) else {
    fail("active SCTP endpoint did not retransmit INIT")
  }
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(1000),
    retransmitted_init,
  )
  guard passive.poll_datagram() is Some(init_ack) else {
    fail("passive endpoint did not repeat INIT-ACK")
  }
  active.handle_datagram(@transport.Instant::from_milliseconds(1000), init_ack)
  guard active.poll_datagram() is Some(cookie_echo) else {
    fail("active endpoint did not send COOKIE-ECHO")
  }
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(1000),
    cookie_echo,
  )
  guard passive.poll_datagram() is Some(cookie_ack) else {
    fail("passive endpoint did not send COOKIE-ACK")
  }
  active.handle_datagram(
    @transport.Instant::from_milliseconds(1000),
    cookie_ack,
  )
  assert_eq(active.state(), Established)
  assert_eq(passive.state(), Established)
}

///|
test "SCTP simultaneous active open completes the cookie handshake" {
  let first = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Active,
      initial_tag=0x11111111U,
      initial_tsn=100U,
      max_payload_size=8,
    ),
  )
  let second = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Active,
      initial_tag=0x22222222U,
      initial_tsn=500U,
      max_payload_size=8,
    ),
  )
  let now = @transport.Instant::from_milliseconds(0)
  first.start(now)
  second.start(now)
  assert_true(pump_association_setup(first, second, now))
  first.send(
    @sctp.Message::new(
      stream=StreamId(1),
      protocol_id=53U,
      payload=b"simultaneous open",
    ),
    now~,
  )
  for packet in drain_packets(first) {
    second.handle_datagram(now, packet)
  }
  assert_eq(
    received_message(second),
    Some(
      @sctp.Message::new(
        stream=StreamId(1),
        protocol_id=53U,
        payload=b"simultaneous open",
      ),
    ),
  )
}

///|
test "reliable ordered SCTP reassembles out-of-order fragments and SACKs them" {
  let (active, passive) = association_pair()
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  let payload = b"abcdefghijklmnopqrstuvwxyz"
  active.send(
    @sctp.Message::new(stream=StreamId(3), protocol_id=53U, payload~),
    now~,
  )
  assert_eq(active.buffered_amount(StreamId(3)), 26UL)
  let fragments = drain_packets(active)
  assert_eq(fragments.length(), 4)
  for index = fragments.length() - 1; index >= 0; index = index - 1 {
    passive.handle_datagram(
      @transport.Instant::from_milliseconds(1),
      fragments[index],
    )
  }
  assert_eq(
    received_message(passive),
    Some(@sctp.Message::new(stream=StreamId(3), protocol_id=53U, payload~)),
  )
  let sacks = drain_packets(passive)
  assert_eq(sacks.length(), 4)
  for sack in sacks {
    active.handle_datagram(@transport.Instant::from_milliseconds(2), sack)
  }
  assert_eq(active.buffered_amount(StreamId(3)), 0UL)
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(3),
    fragments[0],
  )
  assert_eq(received_message(passive), None)
}

///|
test "SCTP TSN wraparound preserves reassembly and acknowledgements" {
  let active = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Active,
      initial_tag=0x11111111U,
      initial_tsn=0xfffffffeU,
      max_payload_size=8,
    ),
  )
  let passive = @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Passive,
      initial_tag=0x22222222U,
      initial_tsn=500U,
      max_payload_size=8,
    ),
  )
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  let payload = b"abcdefghijklmnopqrstuvwxyz"
  active.send(
    @sctp.Message::new(stream=StreamId(4), protocol_id=53U, payload~),
    now~,
  )
  let fragments = drain_packets(active)
  assert_eq(fragments.length(), 4)
  let tsns : Array[UInt] = []
  for fragment in fragments {
    guard @sctp.Packet::decode(fragment).chunks() is [DataChunkValue(chunk)] else {
      fail("wrapped SCTP send emitted a non-DATA packet")
    }
    tsns.push(chunk.tsn())
  }
  assert_eq(tsns, [0xfffffffeU, 0xffffffffU, 0U, 1U])
  for index = fragments.length() - 1; index >= 0; index = index - 1 {
    passive.handle_datagram(
      @transport.Instant::from_milliseconds(1),
      fragments[index],
    )
  }
  assert_eq(
    received_message(passive),
    Some(@sctp.Message::new(stream=StreamId(4), protocol_id=53U, payload~)),
  )
  for sack in drain_packets(passive) {
    active.handle_datagram(@transport.Instant::from_milliseconds(2), sack)
  }
  assert_eq(active.buffered_amount(StreamId(4)), 0UL)
}

///|
test "reliable unordered SCTP preserves the unordered flag across fragments" {
  let (active, passive) = association_pair()
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  let payload = b"unordered fragmented payload"
  active.send(
    @sctp.Message::new(
      stream=StreamId(7),
      protocol_id=53U,
      unordered=true,
      payload~,
    ),
    now~,
  )
  let fragments = drain_packets(active)
  assert_true(fragments.length() > 1)
  for index = fragments.length() - 1; index >= 0; index = index - 1 {
    passive.handle_datagram(
      @transport.Instant::from_milliseconds(1),
      fragments[index],
    )
  }
  assert_eq(
    received_message(passive),
    Some(
      @sctp.Message::new(
        stream=StreamId(7),
        protocol_id=53U,
        unordered=true,
        payload~,
      ),
    ),
  )
}

///|
test "SCTP buffered amount low event fires on the configured crossing" {
  let (active, passive) = association_pair()
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  active.set_buffered_amount_low_threshold(StreamId(9), 10UL)
  active.send(
    @sctp.Message::new(
      stream=StreamId(9),
      protocol_id=53U,
      payload=b"abcdefghijklmnopqrstuvwxyz",
    ),
    now~,
  )
  let fragments = drain_packets(active)
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(1),
    fragments[0],
  )
  guard passive.poll_datagram() is Some(first_sack) else {
    fail("missing first SCTP SACK")
  }
  active.handle_datagram(@transport.Instant::from_milliseconds(2), first_sack)
  assert_eq(active.buffered_amount(StreamId(9)), 18UL)
  assert_true(!saw_stream_event(active, BufferedAmountLow(StreamId(9))))
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(3),
    fragments[1],
  )
  guard passive.poll_datagram() is Some(second_sack) else {
    fail("missing second SCTP SACK")
  }
  active.handle_datagram(@transport.Instant::from_milliseconds(4), second_sack)
  assert_eq(active.buffered_amount(StreamId(9)), 10UL)
  assert_true(saw_stream_event(active, BufferedAmountLow(StreamId(9))))
}

///|
test "PR-SCTP retransmit-count abandons a message and unblocks ordered data" {
  let (active, passive) = association_pair()
  let start = @transport.Instant::from_milliseconds(0)
  active.start(start)
  passive.start(start)
  assert_true(pump_association_setup(active, passive, start))
  active.send(
    @sctp.Message::new(stream=StreamId(11), protocol_id=53U, payload=b"dropped"),
    reliability=RetransmitCount(1),
    now=start,
  )
  let dropped = drain_packets(active)
  assert_eq(dropped.length(), 1)
  active.send(
    @sctp.Message::new(
      stream=StreamId(11),
      protocol_id=53U,
      payload=b"survives",
    ),
    now=start,
  )
  for packet in drain_packets(active) {
    passive.handle_datagram(@transport.Instant::from_milliseconds(1), packet)
  }
  for sack in drain_packets(passive) {
    active.handle_datagram(@transport.Instant::from_milliseconds(2), sack)
  }
  assert_eq(received_message(passive), None)
  active.handle_timeout(@transport.Instant::from_milliseconds(1000))
  assert_eq(drain_packets(active), dropped)
  active.handle_timeout(@transport.Instant::from_milliseconds(3000))
  guard active.poll_datagram() is Some(forward_packet) else {
    fail("missing SCTP FORWARD-TSN after retransmission budget")
  }
  guard @sctp.Packet::decode(forward_packet).chunks()
    is [ForwardTsnChunk(forward)] else {
    fail("partial reliability did not emit FORWARD-TSN")
  }
  assert_eq(forward.new_cumulative_tsn(), 101U)
  assert_eq(forward.streams(), [
    @sctp.ForwardTsnStream::new(stream=StreamId(11), sequence=0),
  ])
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(3000),
    forward_packet,
  )
  assert_eq(
    received_message(passive),
    Some(
      @sctp.Message::new(
        stream=StreamId(11),
        protocol_id=53U,
        payload=b"survives",
      ),
    ),
  )
  for sack in drain_packets(passive) {
    active.handle_datagram(@transport.Instant::from_milliseconds(3001), sack)
  }
  assert_eq(active.buffered_amount(StreamId(11)), 0UL)
}

///|
test "PR-SCTP timed reliability expires before the retransmission timer" {
  let (active, passive) = association_pair()
  let start = @transport.Instant::from_milliseconds(0)
  active.start(start)
  passive.start(start)
  assert_true(pump_association_setup(active, passive, start))
  active.send(
    @sctp.Message::new(stream=StreamId(13), protocol_id=53U, payload=b"expires"),
    reliability=Timed(250U),
    now=start,
  )
  ignore(drain_packets(active))
  assert_eq(
    active.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(250)),
  )
  active.handle_timeout(@transport.Instant::from_milliseconds(249))
  assert_true(drain_packets(active).is_empty())
  active.handle_timeout(@transport.Instant::from_milliseconds(250))
  guard active.poll_datagram() is Some(forward_packet) else {
    fail("timed PR-SCTP message did not emit FORWARD-TSN")
  }
  guard @sctp.Packet::decode(forward_packet).chunks()
    is [ForwardTsnChunk(forward)] else {
    fail("timed reliability emitted a non-FORWARD-TSN packet")
  }
  assert_eq(forward.new_cumulative_tsn(), 100U)
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(250),
    forward_packet,
  )
  for sack in drain_packets(passive) {
    active.handle_datagram(@transport.Instant::from_milliseconds(251), sack)
  }
  active.send(
    @sctp.Message::new(
      stream=StreamId(13),
      protocol_id=53U,
      payload=b"after expiry",
    ),
    now=@transport.Instant::from_milliseconds(252),
  )
  for packet in drain_packets(active) {
    passive.handle_datagram(@transport.Instant::from_milliseconds(252), packet)
  }
  assert_eq(
    received_message(passive),
    Some(
      @sctp.Message::new(
        stream=StreamId(13),
        protocol_id=53U,
        payload=b"after expiry",
      ),
    ),
  )
}

///|
test "SCTP DATA retransmission and RFC 6525 stream reset are deterministic" {
  let (active, passive) = association_pair()
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  active.send(
    @sctp.Message::new(
      stream=StreamId(5),
      protocol_id=51U,
      payload=b"before reset",
    ),
    now~,
  )
  let original_packets = drain_packets(active)
  assert_true(!original_packets.is_empty())
  assert_eq(
    active.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(1000)),
  )
  active.handle_timeout(@transport.Instant::from_milliseconds(1000))
  let retries = drain_packets(active)
  assert_eq(retries, original_packets)
  for packet in retries {
    passive.handle_datagram(@transport.Instant::from_milliseconds(1001), packet)
  }
  for sack in drain_packets(passive) {
    active.handle_datagram(@transport.Instant::from_milliseconds(1002), sack)
  }
  ignore(received_message(passive))
  active.reset_stream(StreamId(5), @transport.Instant::from_milliseconds(1003))
  guard active.poll_datagram() is Some(reset_request) else {
    fail("missing SCTP stream-reset request")
  }
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(1003),
    reset_request,
  )
  assert_true(saw_stream_event(passive, StreamReset(StreamId(5))))
  guard passive.poll_datagram() is Some(reset_response) else {
    fail("missing SCTP stream-reset response")
  }
  active.handle_datagram(
    @transport.Instant::from_milliseconds(1004),
    reset_response,
  )
  assert_true(saw_stream_event(active, StreamResetAcknowledged(StreamId(5))))
  active.send(
    @sctp.Message::new(
      stream=StreamId(5),
      protocol_id=51U,
      payload=b"after reset",
    ),
    now=@transport.Instant::from_milliseconds(1005),
  )
  for packet in drain_packets(active) {
    passive.handle_datagram(@transport.Instant::from_milliseconds(1005), packet)
  }
  assert_eq(
    received_message(passive),
    Some(
      @sctp.Message::new(
        stream=StreamId(5),
        protocol_id=51U,
        payload=b"after reset",
      ),
    ),
  )
}

///|
test "SCTP graceful shutdown exchanges SHUTDOWN, ACK, and COMPLETE" {
  let (active, passive) = association_pair()
  let now = @transport.Instant::from_milliseconds(0)
  active.start(now)
  passive.start(now)
  assert_true(pump_association_setup(active, passive, now))
  active.close(@transport.Instant::from_milliseconds(1))
  guard active.poll_datagram() is Some(shutdown) else {
    fail("missing SCTP SHUTDOWN")
  }
  passive.handle_datagram(@transport.Instant::from_milliseconds(1), shutdown)
  guard passive.poll_datagram() is Some(shutdown_ack) else {
    fail("missing SCTP SHUTDOWN-ACK")
  }
  active.handle_datagram(@transport.Instant::from_milliseconds(2), shutdown_ack)
  assert_eq(active.state(), ClosedState)
  guard active.poll_datagram() is Some(shutdown_complete) else {
    fail("missing SCTP SHUTDOWN-COMPLETE")
  }
  passive.handle_datagram(
    @transport.Instant::from_milliseconds(2),
    shutdown_complete,
  )
  assert_eq(passive.state(), ClosedState)
}
