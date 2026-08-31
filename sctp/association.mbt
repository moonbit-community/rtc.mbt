///|
let association_crypto_provider : Lazy[Result[@crypto.Provider, String]] = Lazy(() => {
    Ok(@crypto.Provider::open()) catch {
      CryptoUnavailable(message) => Err(message)
      InvalidLength(length) => Err("OpenSSL rejected length \{length}")
      OperationFailed(message) => Err(message)
    }
  },
)

///|
fn association_provider() -> @crypto.Provider raise SctpError {
  match association_crypto_provider.force() {
    Ok(provider) => provider
    Err(message) => raise CryptoUnavailable(message)
  }
}

///|
fn[T] association_crypto(
  operation : () -> T raise @crypto.CryptoError,
) -> T raise SctpError {
  operation() catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
}

///|
fn association_after(
  now : @transport.Instant,
  milliseconds : Int64,
) -> @transport.Instant raise SctpError {
  let duration = @transport.Duration::milliseconds(milliseconds) catch {
    error => raise Time(error)
  }
  now.checked_add(duration) catch {
    error => raise Time(error)
  }
}

///|
struct OutstandingData {
  chunk : DataChunk
  packet : Bytes
  reliability : Reliability
  expires_at : @transport.Instant?
  mut deadline : @transport.Instant
  mut rto_milliseconds : Int64
  mut retransmissions : Int
}

///|
struct Reassembly {
  stream : StreamId
  stream_sequence : UInt16
  protocol_id : UInt
  unordered : Bool
  first_tsn : UInt
  bytes : Array[Byte]
}

///|
struct ForwardTsnTransaction {
  new_cumulative_tsn : UInt
  packet : Bytes
  mut deadline : @transport.Instant
  mut rto_milliseconds : Int64
  mut retransmissions : Int
}

///|
struct ResetTransaction {
  streams : Array[StreamId]
  packet : Bytes
  mut deadline : @transport.Instant
  mut rto_milliseconds : Int64
  mut retransmissions : Int
}

///|
struct PendingReset {
  request_sequence : UInt
  sender_last_tsn : UInt
  streams : Array[StreamId]
}

///|
pub struct Association {
  config : AssociationConfig
  provider : @crypto.Provider
  outputs : @queue.Queue[Bytes]
  events : @queue.Queue[AssociationEvent]
  mut started : Bool
  mut state : AssociationState
  local_tag : UInt
  local_initial_tsn : UInt
  mut peer_tag : UInt?
  mut peer_initial_tsn : UInt?
  mut next_tsn : UInt
  mut cumulative_tsn : UInt?
  mut cookie : Bytes?
  mut init_ack_packet : Bytes?
  mut peer_supports_reconfig : Bool
  mut peer_supports_forward_tsn : Bool
  mut last_control_packet : Bytes?
  mut control_deadline : @transport.Instant?
  mut control_rto_milliseconds : Int64
  mut control_retransmissions : Int
  outstanding : Map[UInt, OutstandingData]
  abandoned : Map[UInt, DataChunk]
  mut peer_cumulative_tsn_ack : UInt
  mut forward_tsn_transaction : ForwardTsnTransaction?
  received : Map[UInt, DataChunk]
  duplicates : Array[UInt]
  send_sequences : Map[StreamId, UInt16]
  receive_sequences : Map[StreamId, UInt16]
  reassemblies : Map[UInt64, Reassembly]
  completed_messages : Map[UInt64, Message]
  buffered_by_stream : Map[StreamId, UInt64]
  buffered_amount_low_thresholds : Map[StreamId, UInt64]
  mut buffered_amount : UInt64
  mut next_reset_request : UInt
  mut expected_peer_reset_request : UInt?
  reset_transactions : Map[UInt, ResetTransaction]
  pending_resets : Map[UInt, PendingReset]
  reset_responses : Map[UInt, Bytes]
}

///|
fn random_uint(provider : @crypto.Provider) -> UInt raise SctpError {
  let bytes = association_crypto(() => provider.random_bytes(4))
  let value = (bytes[0].to_uint() << 24) |
    (bytes[1].to_uint() << 16) |
    (bytes[2].to_uint() << 8) |
    bytes[3].to_uint()
  if value == 0U {
    1U
  } else {
    value
  }
}

///|
pub fn Association::new(
  config : AssociationConfig,
) -> Association raise SctpError {
  let provider = association_provider()
  let local_tag = match config.initial_tag {
    Some(value) => value
    None => random_uint(provider)
  }
  let local_initial_tsn = match config.initial_tsn {
    Some(value) => value
    None => random_uint(provider)
  }
  {
    config,
    provider,
    outputs: Queue([]),
    events: Queue([]),
    started: false,
    state: ClosedState,
    local_tag,
    local_initial_tsn,
    peer_tag: None,
    peer_initial_tsn: None,
    next_tsn: local_initial_tsn,
    cumulative_tsn: None,
    cookie: None,
    init_ack_packet: None,
    peer_supports_reconfig: false,
    peer_supports_forward_tsn: false,
    last_control_packet: None,
    control_deadline: None,
    control_rto_milliseconds: 0L,
    control_retransmissions: 0,
    outstanding: Map([]),
    abandoned: Map([]),
    peer_cumulative_tsn_ack: local_initial_tsn - 1U,
    forward_tsn_transaction: None,
    received: Map([]),
    duplicates: [],
    send_sequences: Map([]),
    receive_sequences: Map([]),
    reassemblies: Map([]),
    completed_messages: Map([]),
    buffered_by_stream: Map([]),
    buffered_amount_low_thresholds: Map([]),
    buffered_amount: 0UL,
    next_reset_request: local_initial_tsn,
    expected_peer_reset_request: None,
    reset_transactions: Map([]),
    pending_resets: Map([]),
    reset_responses: Map([]),
  }
}

///|
pub fn Association::state(self : Association) -> AssociationState {
  self.state
}

///|
fn Association::set_state(self : Association, state : AssociationState) -> Unit {
  if self.state != state {
    self.state = state
    self.events.push(StateChanged(state))
  }
}

///|
fn Association::packet(
  self : Association,
  verification_tag : UInt,
  chunks : Array[Chunk],
) -> Bytes raise SctpError {
  Packet::new(
    source_port=self.config.local_port,
    destination_port=self.config.remote_port,
    verification_tag~,
    chunks~,
  ).encode()
}

///|
fn Association::normal_packet(
  self : Association,
  chunks : Array[Chunk],
) -> Bytes raise SctpError {
  guard self.peer_tag is Some(peer_tag) else {
    raise AssociationFailed("peer verification tag is unknown")
  }
  self.packet(peer_tag, chunks)
}

///|
fn Association::queue_control(
  self : Association,
  packet : Bytes,
  now : @transport.Instant,
  retransmit : Bool,
) -> Unit raise SctpError {
  self.outputs.push(packet)
  self.last_control_packet = Some(packet)
  self.control_retransmissions = 0
  if retransmit {
    self.control_rto_milliseconds = self.config.initial_rto.as_milliseconds()
    self.control_deadline = Some(
      association_after(now, self.control_rto_milliseconds),
    )
  } else {
    self.control_deadline = None
  }
}

///|
fn Association::init_chunk(
  self : Association,
  acknowledgement : Bool,
  parameters : Array[Parameter],
) -> InitChunk raise SctpError {
  InitChunk::new(
    acknowledgement~,
    initiate_tag=self.local_tag,
    advertised_receiver_window=self.config.receive_buffer_size,
    initial_tsn=self.local_initial_tsn,
    parameters~,
  )
}

///|
pub fn Association::start(
  self : Association,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if self.started {
    raise InvalidState("SCTP association has already started")
  }
  self.started = true
  if self.config.role == Active {
    let init = self.packet(0U, [
      InitChunkValue(
        self.init_chunk(false, [
          ForwardTsnSupportedParameter,
          SupportedExtensionsParameter(b"\x82\xc0"),
        ]),
      ),
    ])
    self.set_state(CookieWait)
    self.queue_control(init, now, true)
  }
}

///|
pub fn Association::poll_datagram(self : Association) -> Bytes? {
  self.outputs.pop()
}

///|
pub fn Association::poll_event(self : Association) -> AssociationEvent? {
  self.events.pop()
}

///|
fn parameter_supports_reconfig(parameter : Parameter) -> Bool {
  match parameter {
    SupportedExtensionsParameter(chunk_types) => {
      for chunk_type in chunk_types {
        if chunk_type == 130 {
          return true
        }
      }
      false
    }
    _ => false
  }
}

///|
fn parameter_supports_forward_tsn(parameter : Parameter) -> Bool {
  match parameter {
    ForwardTsnSupportedParameter => true
    SupportedExtensionsParameter(chunk_types) => {
      for chunk_type in chunk_types {
        if chunk_type == 192 {
          return true
        }
      }
      false
    }
    _ => false
  }
}

///|
fn state_cookie(parameters : Array[Parameter]) -> Bytes? {
  for parameter in parameters {
    match parameter {
      StateCookieParameter(cookie) => return Some(cookie)
      _ => ()
    }
  }
  None
}

///|
fn tsn_after(left : UInt, right : UInt) -> Bool {
  left != right && left - right < 0x80000000U
}

///|
fn tsn_before(left : UInt, right : UInt) -> Bool {
  tsn_after(right, left)
}

///|
fn tsn_at_or_before(left : UInt, right : UInt) -> Bool {
  left == right || tsn_before(left, right)
}

///|
fn tsn_increment(value : UInt) -> UInt {
  value + 1U
}

///|
fn Association::accept_peer_initial_tsn(
  self : Association,
  initial_tsn : UInt,
) -> Unit {
  self.peer_initial_tsn = Some(initial_tsn)
  self.cumulative_tsn = Some(initial_tsn - 1U)
  self.expected_peer_reset_request = Some(initial_tsn)
}

///|
fn Association::handle_init(
  self : Association,
  packet : Packet,
  init : InitChunk,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if init.acknowledgement || packet.verification_tag != 0U {
    raise InvalidPacket("unexpected SCTP INIT")
  }
  let accepts_init = if self.config.role == Passive {
    self.state == ClosedState || self.state == CookieWait
  } else {
    self.state == CookieWait || self.state == CookieEchoed
  }
  if !accepts_init {
    raise InvalidPacket("unexpected SCTP INIT state")
  }
  if self.peer_tag == Some(init.initiate_tag) {
    match self.init_ack_packet {
      Some(response) => self.outputs.push(response)
      None => ()
    }
    return
  }
  self.peer_tag = Some(init.initiate_tag)
  self.accept_peer_initial_tsn(init.initial_tsn)
  self.peer_supports_reconfig = init.parameters.any(parameter_supports_reconfig)
  self.peer_supports_forward_tsn = init.parameters.any(
    parameter_supports_forward_tsn,
  )
  let cookie = association_crypto(() => self.provider.random_bytes(32))
  self.cookie = Some(cookie)
  let parameters : Array[Parameter] = [
    StateCookieParameter(cookie),
    ForwardTsnSupportedParameter,
    SupportedExtensionsParameter(b"\x82\xc0"),
  ]
  let response = self.packet(init.initiate_tag, [
    InitChunkValue(self.init_chunk(true, parameters)),
  ])
  self.init_ack_packet = Some(response)
  if self.config.role == Passive {
    self.set_state(CookieWait)
    self.queue_control(response, now, false)
  } else {
    // RFC 4960 permits both endpoints to send INIT concurrently. Preserve the
    // active side's INIT retransmission state while acknowledging the peer's
    // colliding INIT.
    self.outputs.push(response)
  }
}

///|
fn Association::handle_init_ack(
  self : Association,
  packet : Packet,
  init : InitChunk,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if self.config.role != Active ||
    !init.acknowledgement ||
    packet.verification_tag != self.local_tag {
    raise InvalidPacket("unexpected SCTP INIT-ACK")
  }
  if self.state == Established {
    return
  }
  if self.state == CookieEchoed {
    match self.last_control_packet {
      Some(cookie_echo) => self.outputs.push(cookie_echo)
      None => ()
    }
    return
  }
  if self.state != CookieWait {
    raise InvalidPacket("unexpected SCTP INIT-ACK state")
  }
  guard state_cookie(init.parameters) is Some(cookie) else {
    raise InvalidPacket("SCTP INIT-ACK omitted its state cookie")
  }
  self.peer_tag = Some(init.initiate_tag)
  self.accept_peer_initial_tsn(init.initial_tsn)
  self.peer_supports_reconfig = init.parameters.any(parameter_supports_reconfig)
  self.peer_supports_forward_tsn = init.parameters.any(
    parameter_supports_forward_tsn,
  )
  let echo = self.normal_packet([CookieEchoChunk(cookie)])
  self.set_state(CookieEchoed)
  self.queue_control(echo, now, true)
}

///|
fn Association::handle_cookie_echo(
  self : Association,
  packet : Packet,
  cookie : Bytes,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if packet.verification_tag != self.local_tag {
    raise InvalidPacket("unexpected SCTP COOKIE-ECHO")
  }
  guard self.cookie is Some(expected_cookie) else {
    raise AssociationFailed("SCTP state cookie is missing")
  }
  if !self.provider.constant_time_equal(expected_cookie, cookie) {
    raise InvalidPacket("SCTP state cookie is invalid")
  }
  if self.state == Established {
    match self.last_control_packet {
      Some(cookie_ack) => self.outputs.push(cookie_ack)
      None => ()
    }
    return
  }
  let accepts_echo = if self.config.role == Passive {
    self.state == CookieWait
  } else {
    self.state == CookieWait || self.state == CookieEchoed
  }
  if !accepts_echo {
    raise InvalidPacket("unexpected SCTP COOKIE-ECHO state")
  }
  let acknowledgement = self.normal_packet([CookieAckChunk])
  self.queue_control(acknowledgement, now, false)
  self.set_state(Established)
}

///|
fn Association::handle_cookie_ack(
  self : Association,
  packet : Packet,
) -> Unit raise SctpError {
  if self.config.role != Active || packet.verification_tag != self.local_tag {
    raise InvalidPacket("unexpected SCTP COOKIE-ACK")
  }
  if self.state == Established {
    return
  }
  if self.state != CookieEchoed {
    raise InvalidPacket("unexpected SCTP COOKIE-ACK state")
  }
  self.control_deadline = None
  self.set_state(Established)
}

///|
fn Association::stream_key(
  stream : StreamId,
  stream_sequence : UInt16,
) -> UInt64 {
  (stream.value().to_uint64() << 16) | stream_sequence.to_uint64()
}

///|
fn stream_sequence_after(left : UInt16, right : UInt16) -> Bool {
  left != right && (left - right).to_uint() < 0x8000U
}

///|
fn stream_sequence_at_or_before(left : UInt16, right : UInt16) -> Bool {
  left == right || stream_sequence_after(right, left)
}

///|
fn Association::deliver_ordered(self : Association, stream : StreamId) -> Unit {
  let mut expected = self.receive_sequences.get_or_default(stream, 0)
  while self.completed_messages.get(Association::stream_key(stream, expected))
        is Some(ready) {
    self.completed_messages.remove(Association::stream_key(stream, expected))
    self.events.push(MessageReceived(ready))
    expected += 1
  }
  self.receive_sequences[stream] = expected
}

///|
fn Association::finish_message(
  self : Association,
  reassembly : Reassembly,
) -> Unit {
  let message = Message::new(
    stream=reassembly.stream,
    protocol_id=reassembly.protocol_id,
    unordered=reassembly.unordered,
    payload=Bytes::from_array(reassembly.bytes),
  )
  if reassembly.unordered {
    self.events.push(MessageReceived(message))
    return
  }
  let key = Association::stream_key(
    reassembly.stream,
    reassembly.stream_sequence,
  )
  self.completed_messages[key] = message
  self.deliver_ordered(reassembly.stream)
}

///|
fn Association::process_data_in_order(
  self : Association,
  chunk : DataChunk,
) -> Unit raise SctpError {
  let key = Association::stream_key(chunk.stream, chunk.stream_sequence)
  if chunk.beginning {
    if self.reassemblies.contains(key) {
      raise InvalidPacket("duplicate beginning SCTP DATA fragment")
    }
    self.reassemblies[key] = {
      stream: chunk.stream,
      stream_sequence: chunk.stream_sequence,
      protocol_id: chunk.protocol_id,
      unordered: chunk.unordered,
      first_tsn: chunk.tsn,
      bytes: [],
    }
  }
  guard self.reassemblies.get(key) is Some(reassembly) else {
    raise InvalidPacket("SCTP DATA fragment arrived without a beginning")
  }
  if reassembly.protocol_id != chunk.protocol_id ||
    reassembly.unordered != chunk.unordered {
    raise InvalidPacket("inconsistent SCTP DATA fragments")
  }
  for byte in chunk.user_data {
    reassembly.bytes.push(byte)
  }
  if reassembly.bytes.length().to_uint64() > self.config.max_message_size {
    raise MessageTooLarge(reassembly.bytes.length().to_uint64())
  }
  if chunk.ending {
    self.reassemblies.remove(key)
    self.finish_message(reassembly)
  }
}

///|
fn Association::drain_received(self : Association) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative) else {
    raise AssociationFailed("peer initial TSN is unknown")
  }
  let mut next = tsn_increment(cumulative)
  while self.received.get(next) is Some(ready) {
    self.received.remove(next)
    self.process_data_in_order(ready)
    self.cumulative_tsn = Some(next)
    next = tsn_increment(next)
  }
}

///|
fn Association::gap_ack_blocks(self : Association) -> Array[GapAckBlock] {
  guard self.cumulative_tsn is Some(cumulative) else { return [] }
  let offsets : Array[UInt] = []
  for tsn in self.received.keys() {
    let offset = tsn - cumulative
    if offset > 0U && offset <= 0xffffU {
      offsets.push(offset)
    }
  }
  offsets.sort()
  let gaps : Array[GapAckBlock] = []
  let mut index = 0
  while index < offsets.length() {
    let start = offsets[index]
    let mut end = start
    index += 1
    while index < offsets.length() && offsets[index] == end + 1U {
      end = offsets[index]
      index += 1
    }
    gaps.push({ start: start.to_uint16(), end: end.to_uint16(), })
  }
  gaps
}

///|
fn Association::send_sack(self : Association) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative_tsn_ack) else { return }
  let sack = SackChunk::new(
    cumulative_tsn_ack~,
    advertised_receiver_window=self.config.receive_buffer_size,
    gap_ack_blocks=self.gap_ack_blocks(),
    duplicate_tsns=self.duplicates,
  )
  self.duplicates.clear()
  self.outputs.push(self.normal_packet([SackChunkValue(sack)]))
}

///|
fn Association::handle_data(
  self : Association,
  chunk : DataChunk,
) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative) else {
    raise AssociationFailed("peer initial TSN is unknown")
  }
  let expected = tsn_increment(cumulative)
  if chunk.tsn == cumulative || tsn_before(chunk.tsn, expected) {
    self.duplicates.push(chunk.tsn)
    self.send_sack()
    return
  }
  if !self.received.contains(chunk.tsn) {
    self.received[chunk.tsn] = chunk
  } else {
    self.duplicates.push(chunk.tsn)
  }
  self.drain_received()
  self.process_pending_resets()
  self.send_sack()
}

///|
fn Association::handle_forward_tsn(
  self : Association,
  forward : ForwardTsn,
) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative) else {
    raise AssociationFailed("peer initial TSN is unknown")
  }
  if tsn_at_or_before(forward.new_cumulative_tsn, cumulative) {
    self.send_sack()
    return
  }
  let skipped : Map[StreamId, UInt16] = Map([])
  for stream in forward.streams {
    match skipped.get(stream.stream) {
      Some(current) if stream_sequence_after(current, stream.sequence) => ()
      _ => skipped[stream.stream] = stream.sequence
    }
  }
  let forwarded_received : Array[UInt] = []
  for tsn in self.received.keys() {
    if tsn_after(tsn, cumulative) &&
      tsn_at_or_before(tsn, forward.new_cumulative_tsn) {
      forwarded_received.push(tsn)
    }
  }
  forwarded_received.sort_by((left, right) => {
    (left - cumulative).compare(right - cumulative)
  })
  for tsn in forwarded_received {
    guard self.received.get(tsn) is Some(chunk) else { continue }
    self.received.remove(tsn)
    let skip_ordered = match skipped.get(chunk.stream) {
      Some(sequence) =>
        !chunk.unordered &&
        stream_sequence_at_or_before(chunk.stream_sequence, sequence)
      None => false
    }
    if skip_ordered {
      continue
    }
    let key = Association::stream_key(chunk.stream, chunk.stream_sequence)
    if !chunk.beginning && !self.reassemblies.contains(key) {
      continue
    }
    self.process_data_in_order(chunk)
  }
  self.received.retain((tsn, _) => {
    !tsn_at_or_before(tsn, forward.new_cumulative_tsn)
  })
  self.reassemblies.retain((_, reassembly) => {
    if reassembly.unordered {
      !tsn_at_or_before(reassembly.first_tsn, forward.new_cumulative_tsn)
    } else {
      match skipped.get(reassembly.stream) {
        Some(sequence) =>
          !stream_sequence_at_or_before(reassembly.stream_sequence, sequence)
        None => true
      }
    }
  })
  self.completed_messages.retain((key, message) => {
    match skipped.get(message.stream()) {
      Some(sequence) => !stream_sequence_at_or_before(key.to_uint16(), sequence)
      None => true
    }
  })
  self.cumulative_tsn = Some(forward.new_cumulative_tsn)
  for entry in skipped {
    let (stream, sequence) = entry
    let expected = self.receive_sequences.get_or_default(stream, 0)
    if sequence == expected || stream_sequence_after(sequence, expected) {
      self.receive_sequences[stream] = sequence + 1
    }
    self.deliver_ordered(stream)
  }
  self.drain_received()
  self.process_pending_resets()
  self.send_sack()
}

///|
fn sack_acknowledges(sack : SackChunk, tsn : UInt) -> Bool {
  if tsn_at_or_before(tsn, sack.cumulative_tsn_ack) {
    return true
  }
  let offset = tsn - sack.cumulative_tsn_ack
  if offset == 0U || offset > 0xffffU {
    return false
  }
  for gap in sack.gap_ack_blocks {
    if offset >= gap.start.to_uint() && offset <= gap.end.to_uint() {
      return true
    }
  }
  false
}

///|
fn Association::release_buffered_data(
  self : Association,
  data : OutstandingData,
) -> Unit {
  let length = data.chunk.user_data.length().to_uint64()
  self.buffered_amount -= length
  let stream = data.chunk.stream
  let current = self.buffered_by_stream.get_or_default(stream, 0UL)
  let next = if length > current { 0UL } else { current - length }
  self.buffered_by_stream[stream] = next
  let threshold = self.buffered_amount_low_thresholds.get_or_default(
    stream, 0UL,
  )
  if current > threshold && next <= threshold {
    self.events.push(BufferedAmountLow(stream))
  }
}

///|
fn Association::maybe_send_forward_tsn(
  self : Association,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if self.abandoned.is_empty() || !self.peer_supports_forward_tsn {
    return
  }
  let mut candidate = self.peer_cumulative_tsn_ack
  let mut next = tsn_increment(candidate)
  while next != self.next_tsn && !self.outstanding.contains(next) {
    candidate = next
    next = tsn_increment(next)
  }
  if candidate == self.peer_cumulative_tsn_ack {
    return
  }
  let mut includes_abandoned = false
  for tsn in self.abandoned.keys() {
    if tsn_after(tsn, self.peer_cumulative_tsn_ack) &&
      tsn_at_or_before(tsn, candidate) {
      includes_abandoned = true
      break
    }
  }
  if !includes_abandoned {
    return
  }
  match self.forward_tsn_transaction {
    Some(transaction) if !tsn_after(candidate, transaction.new_cumulative_tsn) =>
      return
    _ => ()
  }
  let stream_sequences : Map[StreamId, UInt16] = Map([])
  for entry in self.abandoned {
    let (tsn, chunk) = entry
    if chunk.unordered ||
      !tsn_after(tsn, self.peer_cumulative_tsn_ack) ||
      !tsn_at_or_before(tsn, candidate) {
      continue
    }
    match stream_sequences.get(chunk.stream) {
      Some(sequence) if !stream_sequence_after(chunk.stream_sequence, sequence) =>
        ()
      _ => stream_sequences[chunk.stream] = chunk.stream_sequence
    }
  }
  let streams : Array[ForwardTsnStream] = []
  for entry in stream_sequences {
    let (stream, sequence) = entry
    streams.push(ForwardTsnStream::new(stream~, sequence~))
  }
  streams.sort_by((left, right) => {
    left.stream.value().compare(right.stream.value())
  })
  let forward = ForwardTsn::new(new_cumulative_tsn=candidate, streams~)
  let packet = self.normal_packet([ForwardTsnChunk(forward)])
  self.outputs.push(packet)
  let initial_rto = self.config.initial_rto.as_milliseconds()
  self.forward_tsn_transaction = Some({
    new_cumulative_tsn: candidate,
    packet,
    deadline: association_after(now, initial_rto),
    rto_milliseconds: initial_rto,
    retransmissions: 0,
  })
}

///|
fn Association::abandon_message(
  self : Association,
  stream : StreamId,
  stream_sequence : UInt16,
  now : @transport.Instant,
) -> Unit raise SctpError {
  let abandoned_tsns : Array[UInt] = []
  for entry in self.outstanding {
    let (tsn, data) = entry
    if data.chunk.stream == stream &&
      data.chunk.stream_sequence == stream_sequence {
      abandoned_tsns.push(tsn)
    }
  }
  for tsn in abandoned_tsns {
    guard self.outstanding.get(tsn) is Some(data) else { continue }
    self.outstanding.remove(tsn)
    self.abandoned[tsn] = data.chunk
    self.release_buffered_data(data)
  }
  self.maybe_send_forward_tsn(now)
}

///|
fn Association::handle_sack(
  self : Association,
  sack : SackChunk,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if tsn_after(sack.cumulative_tsn_ack, self.peer_cumulative_tsn_ack) {
    self.peer_cumulative_tsn_ack = sack.cumulative_tsn_ack
  }
  let acknowledged : Array[UInt] = []
  for entry in self.outstanding {
    let (tsn, data) = entry
    if sack_acknowledges(sack, tsn) {
      acknowledged.push(tsn)
      self.release_buffered_data(data)
    }
  }
  for tsn in acknowledged {
    self.outstanding.remove(tsn)
  }
  let acknowledged_abandoned : Array[UInt] = []
  for tsn in self.abandoned.keys() {
    if sack_acknowledges(sack, tsn) {
      acknowledged_abandoned.push(tsn)
    }
  }
  for tsn in acknowledged_abandoned {
    self.abandoned.remove(tsn)
  }
  match self.forward_tsn_transaction {
    Some(transaction) if tsn_at_or_before(
        transaction.new_cumulative_tsn,
        sack.cumulative_tsn_ack,
      ) => self.forward_tsn_transaction = None
    _ => ()
  }
  self.maybe_send_forward_tsn(now)
  if self.state == ShutdownPending &&
    self.outstanding.is_empty() &&
    self.forward_tsn_transaction is None {
    self.send_shutdown(now)
  }
}

///|
fn Association::reset_receive_streams(
  self : Association,
  streams : Array[StreamId],
) -> Unit {
  if streams.is_empty() {
    self.receive_sequences.clear()
    self.reassemblies.clear()
    self.completed_messages.clear()
    return
  }
  for stream in streams {
    self.receive_sequences[stream] = 0
    let stream_value = stream.value()
    self.reassemblies.retain((key, _) => (key >> 16).to_uint16() != stream_value)
    self.completed_messages.retain((key, _) => {
      (key >> 16).to_uint16() != stream_value
    })
  }
}

///|
fn Association::send_reset_response(
  self : Association,
  request_sequence : UInt,
  result : UInt,
) -> Bytes raise SctpError {
  let packet = self.normal_packet([
    ReconfigChunk([ReconfigResponse(request_sequence~, result~)]),
  ])
  self.outputs.push(packet)
  packet
}

///|
fn Association::complete_pending_reset(
  self : Association,
  pending : PendingReset,
) -> Unit raise SctpError {
  self.reset_receive_streams(pending.streams)
  let response = self.send_reset_response(pending.request_sequence, 1U)
  self.reset_responses[pending.request_sequence] = response
  self.expected_peer_reset_request = Some(pending.request_sequence + 1U)
  for stream in pending.streams {
    self.events.push(StreamReset(stream))
  }
}

///|
fn Association::process_pending_resets(
  self : Association,
) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative) else { return }
  let ready : Array[UInt] = []
  for entry in self.pending_resets {
    let (request_sequence, pending) = entry
    if tsn_at_or_before(pending.sender_last_tsn, cumulative) {
      ready.push(request_sequence)
    }
  }
  ready.sort()
  for request_sequence in ready {
    match self.pending_resets.get(request_sequence) {
      Some(pending) => {
        self.pending_resets.remove(request_sequence)
        self.complete_pending_reset(pending)
      }
      None => ()
    }
  }
}

///|
fn Association::handle_outgoing_reset_request(
  self : Association,
  request_sequence : UInt,
  sender_last_tsn : UInt,
  streams : Array[StreamId],
) -> Unit raise SctpError {
  match self.reset_responses.get(request_sequence) {
    Some(response) => {
      self.outputs.push(response)
      return
    }
    None => ()
  }
  guard self.expected_peer_reset_request is Some(expected) else {
    raise AssociationFailed("peer reset sequence is unknown")
  }
  if request_sequence != expected {
    ignore(self.send_reset_response(request_sequence, 5U))
    return
  }
  guard self.cumulative_tsn is Some(cumulative) else {
    raise AssociationFailed("peer cumulative TSN is unknown")
  }
  let pending : PendingReset = {
    request_sequence,
    sender_last_tsn,
    streams: streams.copy(),
  }
  if tsn_at_or_before(sender_last_tsn, cumulative) {
    self.complete_pending_reset(pending)
  } else {
    self.pending_resets[request_sequence] = pending
  }
}

///|
fn Association::handle_reconfig_response(
  self : Association,
  request_sequence : UInt,
  result : UInt,
) -> Unit raise SctpError {
  guard self.reset_transactions.get(request_sequence) is Some(transaction) else {
    return
  }
  if result != 0U && result != 1U {
    let stream = if transaction.streams.is_empty() {
      StreamId(0)
    } else {
      transaction.streams[0]
    }
    raise StreamResetFailed(stream.value())
  }
  self.reset_transactions.remove(request_sequence)
  for stream in transaction.streams {
    self.send_sequences[stream] = 0
    self.events.push(StreamResetAcknowledged(stream))
  }
}

///|
fn Association::handle_reconfig(
  self : Association,
  parameters : Array[ReconfigParameter],
) -> Unit raise SctpError {
  if !self.peer_supports_reconfig {
    raise InvalidPacket("peer used unnegotiated SCTP reconfiguration")
  }
  for parameter in parameters {
    match parameter {
      OutgoingResetRequest(
        request_sequence~,
        response_sequence=_,
        sender_last_tsn~,
        streams~
      ) =>
        self.handle_outgoing_reset_request(
          request_sequence, sender_last_tsn, streams,
        )
      ReconfigResponse(request_sequence~, result~) =>
        self.handle_reconfig_response(request_sequence, result)
      UnknownReconfigParameter(_, _) => ()
    }
  }
}

///|
fn Association::send_shutdown(
  self : Association,
  now : @transport.Instant,
) -> Unit raise SctpError {
  guard self.cumulative_tsn is Some(cumulative) else {
    raise AssociationFailed("peer cumulative TSN is unknown")
  }
  let packet = self.normal_packet([ShutdownChunk(cumulative)])
  self.set_state(ShutdownSent)
  self.queue_control(packet, now, true)
}

///|
fn Association::handle_established_chunk(
  self : Association,
  chunk : Chunk,
  now : @transport.Instant,
) -> Unit raise SctpError {
  match chunk {
    DataChunkValue(data) => self.handle_data(data)
    SackChunkValue(sack) => self.handle_sack(sack, now)
    ReconfigChunk(parameters) => self.handle_reconfig(parameters)
    ForwardTsnChunk(forward) => self.handle_forward_tsn(forward)
    HeartbeatChunk(value) =>
      self.outputs.push(self.normal_packet([HeartbeatAckChunk(value)]))
    HeartbeatAckChunk(_) => ()
    ShutdownChunk(_) => {
      let acknowledgement = self.normal_packet([ShutdownAckChunk])
      self.set_state(ShutdownAckSent)
      self.queue_control(acknowledgement, now, false)
    }
    ShutdownAckChunk if self.state == ShutdownSent => {
      self.outputs.push(self.normal_packet([ShutdownCompleteChunk]))
      self.control_deadline = None
      self.set_state(ClosedState)
    }
    ShutdownCompleteChunk if self.state == ShutdownAckSent =>
      self.set_state(ClosedState)
    AbortChunk(_) => {
      self.control_deadline = None
      self.set_state(ClosedState)
      raise AssociationFailed("peer aborted SCTP association")
    }
    ErrorChunk(_) => ()
    UnknownChunk(chunk_type, _, _) => {
      let action = chunk_type >> 6
      if action == 0 || action == 1 {
        raise InvalidPacket("peer sent an unsupported mandatory SCTP chunk")
      }
    }
    _ => raise InvalidPacket("unexpected SCTP control chunk")
  }
}

///|
pub fn Association::handle_datagram(
  self : Association,
  now : @transport.Instant,
  datagram : Bytes,
) -> Unit raise SctpError {
  if !self.started {
    raise InvalidState("SCTP association has not started")
  }
  let packet = Packet::decode(datagram)
  if packet.destination_port != self.config.local_port ||
    packet.source_port != self.config.remote_port {
    raise InvalidPacket("SCTP packet ports do not match the association")
  }
  if packet.chunks.is_empty() {
    return
  }
  for chunk in packet.chunks {
    match chunk {
      InitChunkValue(init) if !init.acknowledgement =>
        self.handle_init(packet, init, now)
      InitChunkValue(init) => self.handle_init_ack(packet, init, now)
      CookieEchoChunk(cookie) => self.handle_cookie_echo(packet, cookie, now)
      CookieAckChunk => self.handle_cookie_ack(packet)
      _ => {
        if self.state != Established &&
          self.state != ShutdownPending &&
          self.state != ShutdownSent &&
          self.state != ShutdownAckSent {
          raise InvalidPacket("SCTP chunk arrived before association setup")
        }
        if packet.verification_tag != self.local_tag {
          raise InvalidPacket("SCTP verification tag mismatch")
        }
        self.handle_established_chunk(chunk, now)
      }
    }
  }
}

///|
pub fn Association::send(
  self : Association,
  message : Message,
  reliability? : Reliability = Reliable,
  now~ : @transport.Instant,
) -> Unit raise SctpError {
  if self.state != Established {
    raise InvalidState("SCTP association is not established")
  }
  if reliability != Reliable && !self.peer_supports_forward_tsn {
    raise InvalidState("peer did not negotiate SCTP FORWARD-TSN")
  }
  let message_length = message.payload.length().to_uint64()
  if message_length > self.config.max_message_size {
    raise MessageTooLarge(message_length)
  }
  if self.buffered_amount + message_length > self.config.send_buffer_size {
    raise BufferFull
  }
  let expires_at = match reliability {
    Timed(lifetime_milliseconds) =>
      Some(association_after(now, lifetime_milliseconds.to_int64()))
    Reliable | RetransmitCount(_) => None
  }
  let stream_sequence = self.send_sequences.get_or_default(message.stream, 0)
  let fragment_count = if message.payload.is_empty() {
    1
  } else {
    (message.payload.length() + self.config.max_payload_size - 1) /
    self.config.max_payload_size
  }
  for fragment_index = 0
      fragment_index < fragment_count
      fragment_index = fragment_index + 1 {
    let start = fragment_index * self.config.max_payload_size
    let end = if start + self.config.max_payload_size < message.payload.length() {
      start + self.config.max_payload_size
    } else {
      message.payload.length()
    }
    let user_data = if message.payload.is_empty() {
      b""
    } else {
      message.payload[start:end].to_owned()
    }
    let tsn = self.next_tsn
    self.next_tsn = tsn_increment(self.next_tsn)
    let chunk = DataChunk::new(
      tsn~,
      stream=message.stream,
      stream_sequence~,
      protocol_id=message.protocol_id,
      user_data~,
      unordered=message.unordered,
      beginning=fragment_index == 0,
      ending=fragment_index + 1 == fragment_count,
    )
    let packet = self.normal_packet([DataChunkValue(chunk)])
    self.outputs.push(packet)
    self.outstanding[tsn] = {
      chunk,
      packet,
      reliability,
      expires_at,
      deadline: association_after(
        now,
        self.config.initial_rto.as_milliseconds(),
      ),
      rto_milliseconds: self.config.initial_rto.as_milliseconds(),
      retransmissions: 0,
    }
    let length = user_data.length().to_uint64()
    self.buffered_amount += length
    self.buffered_by_stream[message.stream] = self.buffered_by_stream.get_or_default(
        message.stream,
        0UL,
      ) +
      length
  }
  self.send_sequences[message.stream] = stream_sequence + 1
}

///|
pub fn Association::buffered_amount(
  self : Association,
  stream : StreamId,
) -> UInt64 {
  self.buffered_by_stream.get_or_default(stream, 0UL)
}

///|
pub fn Association::set_buffered_amount_low_threshold(
  self : Association,
  stream : StreamId,
  threshold : UInt64,
) -> Unit {
  self.buffered_amount_low_thresholds[stream] = threshold
}

///|
pub fn Association::reset_stream(
  self : Association,
  stream : StreamId,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if self.state != Established {
    raise InvalidState("SCTP association is not established")
  }
  if !self.peer_supports_reconfig {
    raise StreamResetFailed(stream.value())
  }
  let request_sequence = self.next_reset_request
  self.next_reset_request += 1U
  let response_sequence = match self.expected_peer_reset_request {
    Some(value) => value - 1U
    None => 0U
  }
  let sender_last_tsn = self.next_tsn - 1U
  let packet = self.normal_packet([
    ReconfigChunk([
      OutgoingResetRequest(
        request_sequence~,
        response_sequence~,
        sender_last_tsn~,
        streams=[stream],
      ),
    ]),
  ])
  self.outputs.push(packet)
  self.reset_transactions[request_sequence] = {
    streams: [stream],
    packet,
    deadline: association_after(now, self.config.initial_rto.as_milliseconds()),
    rto_milliseconds: self.config.initial_rto.as_milliseconds(),
    retransmissions: 0,
  }
}

///|
fn earliest(
  current : @transport.Instant?,
  candidate : @transport.Instant,
) -> @transport.Instant? {
  match current {
    None => Some(candidate)
    Some(value) => if candidate < value { Some(candidate) } else { current }
  }
}

///|
pub fn Association::poll_timeout(self : Association) -> @transport.Instant? {
  let mut result = self.control_deadline
  for data in self.outstanding.values() {
    result = earliest(result, data.deadline)
    match data.expires_at {
      Some(expires_at) => result = earliest(result, expires_at)
      None => ()
    }
  }
  match self.forward_tsn_transaction {
    Some(transaction) => result = earliest(result, transaction.deadline)
    None => ()
  }
  for reset in self.reset_transactions.values() {
    result = earliest(result, reset.deadline)
  }
  result
}

///|
fn next_rto(current : Int64) -> Int64 {
  if current >= 60000L {
    60000L
  } else if current * 2L > 60000L {
    60000L
  } else {
    current * 2L
  }
}

///|
pub fn Association::handle_timeout(
  self : Association,
  now : @transport.Instant,
) -> Unit raise SctpError {
  match self.control_deadline {
    Some(deadline) if deadline <= now => {
      if self.control_retransmissions >= 8 {
        self.control_deadline = None
        self.set_state(ClosedState)
        raise AssociationFailed("SCTP control retransmission limit reached")
      }
      match self.last_control_packet {
        Some(packet) => self.outputs.push(packet)
        None => ()
      }
      self.control_retransmissions += 1
      self.control_rto_milliseconds = next_rto(self.control_rto_milliseconds)
      self.control_deadline = Some(
        association_after(now, self.control_rto_milliseconds),
      )
    }
    _ => ()
  }
  let due_data : Array[UInt] = []
  for entry in self.outstanding {
    let (tsn, data) = entry
    let expired = match data.expires_at {
      Some(expires_at) => expires_at <= now
      None => false
    }
    if data.deadline <= now || expired {
      due_data.push(tsn)
    }
  }
  for tsn in due_data {
    guard self.outstanding.get(tsn) is Some(data) else { continue }
    let should_abandon = match data.reliability {
      Reliable => false
      RetransmitCount(maximum) => data.retransmissions >= maximum.to_int()
      Timed(_) =>
        match data.expires_at {
          Some(expires_at) => expires_at <= now
          None => false
        }
    }
    if should_abandon {
      self.abandon_message(data.chunk.stream, data.chunk.stream_sequence, now)
      continue
    }
    if data.reliability == Reliable && data.retransmissions >= 10 {
      self.set_state(ClosedState)
      raise AssociationFailed("SCTP DATA retransmission limit reached")
    }
    self.outputs.push(data.packet)
    data.retransmissions += 1
    data.rto_milliseconds = next_rto(data.rto_milliseconds)
    data.deadline = association_after(now, data.rto_milliseconds)
  }
  match self.forward_tsn_transaction {
    Some(transaction) if transaction.deadline <= now => {
      if transaction.retransmissions >= 10 {
        self.set_state(ClosedState)
        raise AssociationFailed("SCTP FORWARD-TSN retransmission limit reached")
      }
      self.outputs.push(transaction.packet)
      transaction.retransmissions += 1
      transaction.rto_milliseconds = next_rto(transaction.rto_milliseconds)
      transaction.deadline = association_after(
        now,
        transaction.rto_milliseconds,
      )
    }
    _ => ()
  }
  let due_resets : Array[UInt] = []
  for entry in self.reset_transactions {
    let (request_sequence, transaction) = entry
    if transaction.deadline <= now {
      due_resets.push(request_sequence)
    }
  }
  for request_sequence in due_resets {
    guard self.reset_transactions.get(request_sequence) is Some(transaction) else {
      continue
    }
    if transaction.retransmissions >= 8 {
      let stream = transaction.streams[0]
      self.reset_transactions.remove(request_sequence)
      raise StreamResetFailed(stream.value())
    }
    self.outputs.push(transaction.packet)
    transaction.retransmissions += 1
    transaction.rto_milliseconds = next_rto(transaction.rto_milliseconds)
    transaction.deadline = association_after(now, transaction.rto_milliseconds)
  }
}

///|
pub fn Association::close(
  self : Association,
  now : @transport.Instant,
) -> Unit raise SctpError {
  if self.state == ClosedState {
    return
  }
  if self.state != Established && self.state != ShutdownPending {
    self.control_deadline = None
    self.set_state(ClosedState)
    return
  }
  if self.outstanding.is_empty() && self.forward_tsn_transaction is None {
    self.send_shutdown(now)
  } else {
    self.set_state(ShutdownPending)
  }
}
