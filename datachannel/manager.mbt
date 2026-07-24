///|
pub struct Manager {
  mut role : StreamRole
  channels : Map[@sctp.StreamId, DataChannel]
  local_channels : Map[@sctp.StreamId, Bool]
  incoming_resets : Map[@sctp.StreamId, Bool]
  outgoing_resets : Map[@sctp.StreamId, Bool]
  acknowledged_resets : Map[@sctp.StreamId, Bool]
  commands : @queue.Queue[DataChannelCommand]
  events : @queue.Queue[DataChannelEvent]
  mut transport_ready : Bool
  mut next_stream : UInt
}

///|
pub fn Manager::new(role~ : StreamRole) -> Manager {
  {
    role,
    channels: Map([]),
    local_channels: Map([]),
    incoming_resets: Map([]),
    outgoing_resets: Map([]),
    acknowledged_resets: Map([]),
    commands: Queue([]),
    events: Queue([]),
    transport_ready: false,
    next_stream: if role == DtlsClient {
      0U
    } else {
      1U
    },
  }
}

///|
pub fn Manager::role(self : Manager) -> StreamRole {
  self.role
}

///|
pub fn Manager::set_role(
  self : Manager,
  role : StreamRole,
) -> Array[(@sctp.StreamId, @sctp.StreamId)] raise DataChannelError {
  if self.role == role {
    return []
  }
  if self.transport_ready ||
    !self.commands.is_empty() ||
    !self.incoming_resets.is_empty() ||
    !self.outgoing_resets.is_empty() ||
    !self.acknowledged_resets.is_empty() {
    raise InvalidConfiguration(
      "cannot change the DataChannel DTLS role after transport activity",
    )
  }
  let entries : Array[(DataChannel, Bool)] = []
  for entry in self.channels {
    let (stream, channel) = entry
    entries.push((channel, self.local_channels.get_or_default(stream, false)))
  }
  self.channels.clear()
  self.local_channels.clear()
  self.role = role
  self.next_stream = if role == DtlsClient { 0U } else { 1U }
  for entry in entries {
    let (channel, locally_created) = entry
    if channel.negotiated || !locally_created {
      self.channels[channel.id] = channel
      self.local_channels[channel.id] = locally_created
    }
  }
  let remapped : Array[(@sctp.StreamId, @sctp.StreamId)] = []
  for entry in entries {
    let (channel, locally_created) = entry
    if channel.negotiated || !locally_created {
      continue
    }
    let previous = channel.id
    let replacement = self.allocate_stream()
    channel.id = replacement
    self.channels[replacement] = channel
    self.local_channels[replacement] = true
    remapped.push((previous, replacement))
  }
  remapped
}

///|
fn snapshot(channel : DataChannel) -> DataChannel {
  {
    id: channel.id,
    label: channel.label,
    protocol: channel.protocol,
    ordering: channel.ordering,
    reliability: channel.reliability,
    negotiated: channel.negotiated,
    priority: channel.priority,
    state: channel.state,
  }
}

///|
fn local_parity(role : StreamRole) -> UInt16 {
  if role == DtlsClient {
    0
  } else {
    1
  }
}

///|
fn peer_parity(role : StreamRole) -> UInt16 {
  if role == DtlsClient {
    1
  } else {
    0
  }
}

///|
fn stream_has_parity(stream : @sctp.StreamId, parity : UInt16) -> Bool {
  (stream.value() & 1) == parity
}

///|
fn channel_parameters(
  ordering : @sctp.Ordering,
  reliability : @sctp.Reliability,
) -> (ChannelType, UInt) {
  match (ordering, reliability) {
    (Ordered, Reliable) => (ReliableChannel, 0U)
    (Unordered, Reliable) => (ReliableUnorderedChannel, 0U)
    (Ordered, RetransmitCount(count)) =>
      (PartialReliableRetransmitChannel, count.to_uint())
    (Unordered, RetransmitCount(count)) =>
      (PartialReliableRetransmitUnorderedChannel, count.to_uint())
    (Ordered, Timed(milliseconds)) =>
      (PartialReliableTimedChannel, milliseconds)
    (Unordered, Timed(milliseconds)) =>
      (PartialReliableTimedUnorderedChannel, milliseconds)
  }
}

///|
fn parameters_from_open(
  open : DcepOpen,
) -> (@sctp.Ordering, @sctp.Reliability) raise DataChannelError {
  match open.channel_type {
    ReliableChannel => {
      if open.reliability_parameter != 0U {
        raise ProtocolViolation(
          "reliable DCEP OPEN has a nonzero reliability parameter",
        )
      }
      (Ordered, Reliable)
    }
    ReliableUnorderedChannel => {
      if open.reliability_parameter != 0U {
        raise ProtocolViolation(
          "reliable DCEP OPEN has a nonzero reliability parameter",
        )
      }
      (Unordered, Reliable)
    }
    PartialReliableRetransmitChannel => {
      if open.reliability_parameter > 65535U {
        raise ProtocolViolation(
          "DCEP retransmission count exceeds the SCTP API limit",
        )
      }
      (Ordered, RetransmitCount(open.reliability_parameter.to_uint16()))
    }
    PartialReliableRetransmitUnorderedChannel => {
      if open.reliability_parameter > 65535U {
        raise ProtocolViolation(
          "DCEP retransmission count exceeds the SCTP API limit",
        )
      }
      (Unordered, RetransmitCount(open.reliability_parameter.to_uint16()))
    }
    PartialReliableTimedChannel => (Ordered, Timed(open.reliability_parameter))
    PartialReliableTimedUnorderedChannel =>
      (Unordered, Timed(open.reliability_parameter))
  }
}

///|
fn open_for_channel(channel : DataChannel) -> DcepOpen {
  let (channel_type, reliability_parameter) = channel_parameters(
    channel.ordering,
    channel.reliability,
  )
  {
    channel_type,
    priority: channel.priority,
    reliability_parameter,
    label: channel.label,
    protocol: channel.protocol,
  }
}

///|
fn Manager::queue_dcep(
  self : Manager,
  stream : @sctp.StreamId,
  message : DcepMessage,
) -> Unit raise DataChannelError {
  self.commands.push(
    SendSctp(
      @sctp.Message::new(
        stream~,
        protocol_id=Dcep.code(),
        payload=message.encode(),
      ),
      Reliable,
    ),
  )
}

///|
fn Manager::mark_open(self : Manager, channel : DataChannel) -> Unit {
  if channel.state != Open {
    channel.state = Open
    self.events.push(Opened(snapshot(channel)))
  }
}

///|
fn Manager::activate_channel(
  self : Manager,
  channel : DataChannel,
) -> Unit raise DataChannelError {
  if channel.negotiated {
    self.mark_open(channel)
  } else {
    self.queue_dcep(channel.id, Open(open_for_channel(channel)))
  }
}

///|
fn Manager::allocate_stream(
  self : Manager,
) -> @sctp.StreamId raise DataChannelError {
  let mut candidate = self.next_stream
  while candidate <= 65534U {
    let stream = @sctp.StreamId(candidate.to_uint16())
    if !self.channels.contains(stream) {
      self.next_stream = candidate + 2U
      return stream
    }
    candidate += 2U
  }
  raise InvalidConfiguration("no SCTP stream id is available for data channel")
}

///|
pub fn Manager::create_channel(
  self : Manager,
  config : DataChannelConfig,
) -> DataChannel raise DataChannelError {
  let stream = match config.id {
    Some(value) => value
    None => self.allocate_stream()
  }
  if stream.value() == 0xffff {
    raise InvalidConfiguration("SCTP stream id 65535 is not negotiable")
  }
  if self.channels.contains(stream) {
    raise InvalidConfiguration(
      "SCTP stream \{stream.value()} is already assigned",
    )
  }
  if !config.negotiated && !stream_has_parity(stream, local_parity(self.role)) {
    raise InvalidConfiguration(
      "in-band data channel stream id has the peer's parity",
    )
  }
  let channel = DataChannel::new(
    id=stream,
    label=config.label,
    protocol=config.protocol,
    ordering=config.ordering,
    reliability=config.reliability,
    negotiated=config.negotiated,
    priority=config.priority,
  )
  self.channels[stream] = channel
  self.local_channels[stream] = true
  if self.transport_ready {
    self.activate_channel(channel)
  }
  channel
}

///|
pub fn Manager::channel(
  self : Manager,
  stream : @sctp.StreamId,
) -> DataChannel? {
  match self.channels.get(stream) {
    Some(channel) => Some(snapshot(channel))
    None => None
  }
}

///|
pub fn Manager::all_channels(self : Manager) -> Array[DataChannel] {
  let result : Array[DataChannel] = []
  for channel in self.channels.values() {
    result.push(snapshot(channel))
  }
  result
}

///|
fn Manager::handle_established(self : Manager) -> Unit raise DataChannelError {
  if self.transport_ready {
    return
  }
  self.transport_ready = true
  for channel in self.channels.values() {
    if channel.state == Connecting {
      self.activate_channel(channel)
    }
  }
}

///|
fn Manager::handle_open(
  self : Manager,
  stream : @sctp.StreamId,
  open : DcepOpen,
) -> Unit raise DataChannelError {
  if !stream_has_parity(stream, peer_parity(self.role)) {
    raise ProtocolViolation("peer DCEP OPEN used a local-parity stream id")
  }
  match self.channels.get(stream) {
    Some(channel) => {
      if self.local_channels.contains(stream) {
        raise ProtocolViolation("peer DCEP OPEN collided with a local channel")
      }
      if open_for_channel(channel) != open {
        raise ProtocolViolation(
          "duplicate DCEP OPEN changed channel parameters",
        )
      }
      self.queue_dcep(stream, Acknowledgement)
    }
    None => {
      let (ordering, reliability) = parameters_from_open(open)
      let channel = DataChannel::new(
        id=stream,
        label=open.label,
        protocol=open.protocol,
        ordering~,
        reliability~,
        priority=open.priority,
      )
      self.channels[stream] = channel
      self.queue_dcep(stream, Acknowledgement)
      self.mark_open(channel)
    }
  }
}

///|
fn Manager::handle_ack(
  self : Manager,
  stream : @sctp.StreamId,
) -> Unit raise DataChannelError {
  guard self.channels.get(stream) is Some(channel) else {
    raise ProtocolViolation("DCEP ACK refers to an unknown stream")
  }
  if !self.local_channels.contains(stream) || channel.negotiated {
    raise ProtocolViolation(
      "unexpected DCEP ACK for a remote or negotiated channel",
    )
  }
  match channel.state {
    Connecting => self.mark_open(channel)
    Open => ()
    Closing | Closed =>
      raise ProtocolViolation("DCEP ACK arrived after channel close")
  }
}

///|
fn decode_user_message(
  ppid : PayloadProtocolIdentifier,
  payload : Bytes,
) -> DataChannelMessage raise DataChannelError {
  match ppid {
    StringPayload =>
      Text(
        @utf8.decode(payload) catch {
          _ => raise ProtocolViolation("data channel text is not valid UTF-8")
        },
      )
    BinaryPayload => Binary(payload)
    StringEmptyPayload => {
      if payload != b"\x00" {
        raise ProtocolViolation(
          "empty string PPID must carry one zero SCTP user byte",
        )
      }
      Text("")
    }
    BinaryEmptyPayload => {
      if payload != b"\x00" {
        raise ProtocolViolation(
          "empty binary PPID must carry one zero SCTP user byte",
        )
      }
      Binary(b"")
    }
    Dcep => raise ProtocolViolation("DCEP is not application data")
  }
}

///|
fn Manager::handle_message(
  self : Manager,
  message : @sctp.Message,
) -> Unit raise DataChannelError {
  let stream = message.stream()
  let ppid = PayloadProtocolIdentifier::from_code(message.protocol_id())
  if ppid == Dcep {
    match DcepMessage::decode(message.payload()) {
      Open(open) => self.handle_open(stream, open)
      Acknowledgement => self.handle_ack(stream)
    }
    return
  }
  guard self.channels.get(stream) is Some(channel) else {
    raise ProtocolViolation("application data arrived on an unknown stream")
  }
  if channel.state != Open {
    raise ProtocolViolation("application data arrived before DCEP completed")
  }
  self.events.push(
    MessageReceived(stream, decode_user_message(ppid, message.payload())),
  )
}

///|
fn Manager::maybe_finish_close(self : Manager, stream : @sctp.StreamId) -> Unit {
  if self.incoming_resets.contains(stream) &&
    self.acknowledged_resets.contains(stream) {
    match self.channels.get(stream) {
      Some(channel) if channel.state != Closed => {
        channel.state = Closed
        self.events.push(ClosedEvent(stream))
      }
      _ => ()
    }
    self.incoming_resets.remove(stream)
    self.outgoing_resets.remove(stream)
    self.acknowledged_resets.remove(stream)
  }
}

///|
fn Manager::handle_stream_reset(
  self : Manager,
  stream : @sctp.StreamId,
) -> Unit {
  guard self.channels.get(stream) is Some(channel) else { return }
  if channel.state == Closed {
    return
  }
  channel.state = Closing
  self.incoming_resets[stream] = true
  if !self.outgoing_resets.contains(stream) {
    self.outgoing_resets[stream] = true
    self.commands.push(ResetSctpStream(stream))
  }
  self.maybe_finish_close(stream)
}

///|
fn Manager::handle_reset_acknowledged(
  self : Manager,
  stream : @sctp.StreamId,
) -> Unit {
  if !self.outgoing_resets.contains(stream) {
    return
  }
  self.acknowledged_resets[stream] = true
  self.maybe_finish_close(stream)
}

///|
fn Manager::handle_association_closed(self : Manager) -> Unit {
  self.transport_ready = false
  for channel in self.channels.values() {
    if channel.state != Closed {
      channel.state = Closed
      self.events.push(ClosedEvent(channel.id))
    }
  }
}

///|
pub fn Manager::handle_sctp_event(
  self : Manager,
  event : @sctp.AssociationEvent,
) -> Unit raise DataChannelError {
  match event {
    StateChanged(Established) => self.handle_established()
    StateChanged(ClosedState) => self.handle_association_closed()
    StateChanged(_) => ()
    MessageReceived(message) => self.handle_message(message)
    StreamReset(stream) => self.handle_stream_reset(stream)
    StreamResetAcknowledged(stream) => self.handle_reset_acknowledged(stream)
    BufferedAmountLow(stream) =>
      if self.channels.contains(stream) {
        self.events.push(BufferedAmountLowEvent(stream))
      }
  }
}

///|
pub fn Manager::send(
  self : Manager,
  stream : @sctp.StreamId,
  message : DataChannelMessage,
) -> Unit raise DataChannelError {
  guard self.channels.get(stream) is Some(channel) else {
    raise InvalidConfiguration("unknown data channel stream")
  }
  if channel.state != Open {
    raise Closed
  }
  let (ppid, payload) = match message {
    Text(value) => {
      let bytes = @utf8.encode(value)
      if bytes.is_empty() {
        (StringEmptyPayload, b"\x00")
      } else {
        (StringPayload, bytes)
      }
    }
    Binary(bytes) =>
      if bytes.is_empty() {
        (BinaryEmptyPayload, b"\x00")
      } else {
        (BinaryPayload, bytes)
      }
  }
  self.commands.push(
    SendSctp(
      @sctp.Message::new(
        stream~,
        protocol_id=ppid.code(),
        unordered=channel.ordering == Unordered,
        payload~,
      ),
      channel.reliability,
    ),
  )
}

///|
pub fn Manager::close_channel(
  self : Manager,
  stream : @sctp.StreamId,
) -> Unit raise DataChannelError {
  guard self.channels.get(stream) is Some(channel) else {
    raise InvalidConfiguration("unknown data channel stream")
  }
  match channel.state {
    Closed | Closing => return
    Connecting | Open => {
      if !self.transport_ready {
        channel.state = Closed
        self.events.push(ClosedEvent(stream))
        return
      }
      channel.state = Closing
      self.outgoing_resets[stream] = true
      self.commands.push(ResetSctpStream(stream))
    }
  }
}

///|
pub fn Manager::poll_command(self : Manager) -> DataChannelCommand? {
  self.commands.pop()
}

///|
pub fn Manager::poll_event(self : Manager) -> DataChannelEvent? {
  self.events.pop()
}
