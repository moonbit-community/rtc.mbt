///|
priv enum TurnOperation {
  AllocateOperation
  RefreshOperation(UInt)
  PermissionOperation(@transport.SocketAddress)
  ChannelBindOperation(@transport.SocketAddress, UInt16)
}

///|
struct PendingTurnTransaction {
  operation : TurnOperation
  packet : Bytes
  authenticated : Bool
  mut deadline : @transport.Instant
  mut rto_milliseconds : Int64
  mut retransmissions : Int
}

///|
struct Permission {
  peer : @transport.SocketAddress
  mut expires_at : @transport.Instant
}

///|
struct ChannelBinding {
  peer : @transport.SocketAddress
  channel : UInt16
  expires_at : @transport.Instant
}

///|
pub struct Allocation {
  local_address : @transport.SocketAddress
  server : @transport.SocketAddress
  transport : TurnTransport
  credentials : TurnCredentials
  outputs : @queue.Queue[@transport.OutboundDatagram]
  stream_outputs : @queue.Queue[Bytes]
  events : @queue.Queue[AllocationEvent]
  transactions : Map[@stun.TransactionId, PendingTurnTransaction]
  permissions : Array[Permission]
  channels : Array[ChannelBinding]
  mut state : AllocationState
  mut realm : String?
  mut nonce : String?
  mut key : Bytes?
  mut relayed_address : RelayedAddress?
  mut expires_at : @transport.Instant?
  mut refresh_at : @transport.Instant?
  mut stream_input : Bytes
}

///|
fn[T] turn_stun(operation : () -> T raise @stun.StunError) -> T raise TurnError {
  operation() catch {
    error => raise Transaction(error)
  }
}

///|
fn turn_after(
  now : @transport.Instant,
  milliseconds : Int64,
) -> @transport.Instant raise TurnError {
  let duration = @transport.Duration::milliseconds(milliseconds) catch {
    error => raise Time(error)
  }
  now.checked_add(duration) catch {
    error => raise Time(error)
  }
}

///|
fn lifetime_deadline(
  now : @transport.Instant,
  seconds : UInt,
) -> @transport.Instant raise TurnError {
  turn_after(now, seconds.to_int64() * 1000L)
}

///|
pub fn Allocation::new(
  local_address~ : @transport.SocketAddress,
  server~ : @transport.SocketAddress,
  credentials~ : TurnCredentials,
  transport? : TurnTransport = Udp,
) -> Allocation raise TurnError {
  if server.port() == 0 {
    raise InvalidConfiguration("TURN server port must be nonzero")
  }
  {
    local_address,
    server,
    transport,
    credentials,
    outputs: Queue([]),
    stream_outputs: Queue([]),
    events: Queue([]),
    transactions: Map([]),
    permissions: [],
    channels: [],
    state: New,
    realm: None,
    nonce: None,
    key: None,
    relayed_address: None,
    expires_at: None,
    refresh_at: None,
    stream_input: b"",
  }
}

///|
pub fn Allocation::state(self : Allocation) -> AllocationState {
  self.state
}

///|
pub fn Allocation::local_address(self : Allocation) -> @transport.SocketAddress {
  self.local_address
}

///|
pub fn Allocation::server(self : Allocation) -> @transport.SocketAddress {
  self.server
}

///|
pub fn Allocation::transport(self : Allocation) -> TurnTransport {
  self.transport
}

///|
pub fn Allocation::relayed_address(self : Allocation) -> RelayedAddress? {
  self.relayed_address
}

///|
fn Allocation::set_state(self : Allocation, state : AllocationState) -> Unit {
  if self.state != state {
    self.state = state
    self.events.push(AllocationStateChanged(state))
  }
}

///|
fn Allocation::context(self : Allocation) -> @transport.TransportContext {
  {
    local_address: self.local_address,
    peer: self.server,
    ecn: None,
    protocol: if self.transport == Udp {
      Udp
    } else {
      Tcp
    },
  }
}

///|
fn pad_stream_channel_data(packet : Bytes) -> Bytes {
  if packet.is_empty() || (packet[0] & 0xc0) != 0x40 {
    return packet
  }
  let padded_length = (packet.length() + 3) / 4 * 4
  if padded_length == packet.length() {
    return packet
  }
  let result = packet.to_array()
  while result.length() < padded_length {
    result.push(0)
  }
  Bytes::from_array(result)
}

///|
fn Allocation::queue_packet(self : Allocation, packet : Bytes) -> Unit {
  if self.transport == Udp {
    self.outputs.push({ context: self.context(), payload: packet, })
  } else {
    self.stream_outputs.push(pad_stream_channel_data(packet))
  }
}

///|
pub fn Allocation::handles_context(
  self : Allocation,
  context : @transport.TransportContext,
) -> Bool {
  context == self.context()
}

///|
fn operation_method(operation : TurnOperation) -> @stun.Method {
  match operation {
    AllocateOperation => Allocate
    RefreshOperation(_) => Refresh
    PermissionOperation(_) => CreatePermission
    ChannelBindOperation(_) => ChannelBind
  }
}

///|
fn requested_transport_attribute() -> @stun.Attribute raise TurnError {
  turn_stun(() => {
    @stun.Attribute::new(
      attribute_type=RequestedTransport,
      value=b"\x11\x00\x00\x00",
    )
  })
}

///|
fn data_attribute(payload : Bytes) -> @stun.Attribute raise TurnError {
  turn_stun(() => {
    @stun.Attribute::new(attribute_type=DataAttribute, value=payload)
  })
}

///|
fn operation_attributes(
  operation : TurnOperation,
  transaction_id : @stun.TransactionId,
) -> Array[@stun.Attribute] raise TurnError {
  match operation {
    AllocateOperation => [requested_transport_attribute()]
    RefreshOperation(lifetime) =>
      [turn_stun(() => @stun.Attribute::lifetime(lifetime))]
    PermissionOperation(peer) =>
      [
        turn_stun(() => {
          @stun.Attribute::from_xor_address(
            peer,
            transaction_id,
            attribute_type=XorPeerAddress,
          )
        }),
      ]
    ChannelBindOperation(peer, channel) =>
      [
        turn_stun(() => @stun.Attribute::channel_number(channel)),
        turn_stun(() => {
          @stun.Attribute::from_xor_address(
            peer,
            transaction_id,
            attribute_type=XorPeerAddress,
          )
        }),
      ]
  }
}

///|
fn Allocation::encode_operation(
  self : Allocation,
  operation : TurnOperation,
) -> (@stun.TransactionId, Bytes, Bool) raise TurnError {
  let transaction_id = turn_stun(() => @stun.TransactionId::random())
  let attributes = operation_attributes(operation, transaction_id)
  let authenticated = self.key is Some(_)
  if authenticated {
    guard self.realm is Some(realm) &&
      self.nonce is Some(nonce) &&
      self.key is Some(key) else {
      raise AuthenticationFailed
    }
    attributes.push(
      turn_stun(() => @stun.Attribute::username(self.credentials.username)),
    )
    attributes.push(turn_stun(() => @stun.Attribute::realm(realm)))
    attributes.push(turn_stun(() => @stun.Attribute::nonce(nonce)))
    let message = @stun.Message::new(
      class=Request,
      stun_method=operation_method(operation),
      transaction_id~,
      attributes~,
    )
    (transaction_id, turn_stun(() => message.encode_authenticated(key)), true)
  } else {
    let message = @stun.Message::new(
      class=Request,
      stun_method=operation_method(operation),
      transaction_id~,
      attributes~,
    )
    (transaction_id, turn_stun(() => message.encode()), false)
  }
}

///|
fn Allocation::start_operation(
  self : Allocation,
  operation : TurnOperation,
  now : @transport.Instant,
) -> Unit raise TurnError {
  let (transaction_id, packet, authenticated) = self.encode_operation(operation)
  self.queue_packet(packet)
  self.transactions[transaction_id] = {
    operation,
    packet,
    authenticated,
    deadline: turn_after(now, if self.transport == Udp { 500L } else { 39500L }),
    rto_milliseconds: 500L,
    retransmissions: 0,
  }
}

///|
pub fn Allocation::start(
  self : Allocation,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state != New {
    raise InvalidState("TURN allocation has already started")
  }
  self.set_state(Allocating)
  self.start_operation(AllocateOperation, now)
}

///|
pub fn Allocation::poll_datagram(
  self : Allocation,
) -> @transport.OutboundDatagram? {
  if self.transport == Udp {
    self.outputs.pop()
  } else {
    None
  }
}

///|
pub fn Allocation::poll_stream_write(self : Allocation) -> Bytes? {
  if self.transport == Udp {
    None
  } else {
    self.stream_outputs.pop()
  }
}

///|
pub fn Allocation::poll_event(self : Allocation) -> AllocationEvent? {
  self.events.pop()
}

///|
fn earliest_turn_deadline(
  current : @transport.Instant?,
  candidate : @transport.Instant?,
) -> @transport.Instant? {
  match (current, candidate) {
    (None, value) => value
    (value, None) => value
    (Some(left), Some(right)) => Some(if left < right { left } else { right })
  }
}

///|
pub fn Allocation::poll_timeout(self : Allocation) -> @transport.Instant? {
  let mut result = earliest_turn_deadline(self.expires_at, self.refresh_at)
  for transaction in self.transactions.values() {
    result = earliest_turn_deadline(result, Some(transaction.deadline))
  }
  for permission in self.permissions {
    result = earliest_turn_deadline(result, Some(permission.expires_at))
  }
  for binding in self.channels {
    result = earliest_turn_deadline(result, Some(binding.expires_at))
  }
  result
}

///|
fn message_error_code(message : @stun.Message) -> UInt16? raise TurnError {
  match message.first_attribute(ErrorCode) {
    Some(attribute) => Some(turn_stun(() => attribute.to_error()).code())
    None => None
  }
}

///|
fn required_text_attribute(
  message : @stun.Message,
  attribute_type : @stun.AttributeType,
  context : String,
) -> String raise TurnError {
  guard message.first_attribute(attribute_type) is Some(attribute) else {
    raise InvalidResponse("TURN response omitted \{context}")
  }
  turn_stun(() => attribute.as_text())
}

///|
fn Allocation::handle_authentication_challenge(
  self : Allocation,
  message : @stun.Message,
  transaction : PendingTurnTransaction,
  code : UInt16,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if code != 401 && code != 438 {
    raise InvalidResponse("TURN server returned error \{code}")
  }
  if code == 401 && transaction.authenticated {
    self.set_state(Failed)
    raise AuthenticationFailed
  }
  let realm = required_text_attribute(message, Realm, "REALM")
  let nonce = required_text_attribute(message, Nonce, "NONCE")
  match self.realm {
    Some(previous) if previous != realm => {
      self.set_state(Failed)
      raise AuthenticationFailed
    }
    _ => ()
  }
  self.realm = Some(realm)
  self.nonce = Some(nonce)
  self.key = Some(
    long_term_key(self.credentials.username, realm, self.credentials.password),
  )
  self.start_operation(transaction.operation, now)
}

///|
fn response_lifetime(message : @stun.Message) -> UInt raise TurnError {
  match message.first_attribute(Lifetime) {
    Some(attribute) => turn_stun(() => attribute.as_u32())
    None => 600U
  }
}

///|
fn Allocation::schedule_lifetime(
  self : Allocation,
  now : @transport.Instant,
  lifetime : UInt,
) -> Unit raise TurnError {
  if lifetime == 0U {
    self.expires_at = Some(now)
    self.refresh_at = None
    return
  }
  self.expires_at = Some(lifetime_deadline(now, lifetime))
  let refresh_seconds = if lifetime > 2U { lifetime / 2U } else { 1U }
  self.refresh_at = Some(lifetime_deadline(now, refresh_seconds))
}

///|
fn Allocation::upsert_permission(
  self : Allocation,
  peer : @transport.SocketAddress,
  now : @transport.Instant,
) -> Unit raise TurnError {
  let expires_at = lifetime_deadline(now, 300U)
  for permission in self.permissions {
    if permission.peer == peer {
      permission.expires_at = expires_at
      return
    }
  }
  self.permissions.push({ peer, expires_at, })
}

///|
fn Allocation::upsert_channel(
  self : Allocation,
  peer : @transport.SocketAddress,
  channel : UInt16,
  now : @transport.Instant,
) -> Unit raise TurnError {
  let expires_at = lifetime_deadline(now, 600U)
  self.channels.retain(binding => {
    binding.peer != peer && binding.channel != channel
  })
  self.channels.push({ peer, channel, expires_at, })
  self.upsert_permission(peer, now)
}

///|
fn Allocation::handle_success(
  self : Allocation,
  message : @stun.Message,
  transaction : PendingTurnTransaction,
  now : @transport.Instant,
) -> Unit raise TurnError {
  match transaction.operation {
    AllocateOperation => {
      guard message.first_attribute(XorRelayedAddress) is Some(attribute) else {
        self.set_state(Failed)
        raise InvalidResponse(
          "TURN Allocate success omitted XOR-RELAYED-ADDRESS",
        )
      }
      let address = turn_stun(() => {
        attribute.to_xor_address(message.transaction_id())
      })
      let relayed = { address, server: self.server, transport: self.transport, }
      self.relayed_address = Some(relayed)
      self.schedule_lifetime(now, response_lifetime(message))
      self.set_state(Active)
      self.events.push(AllocationCreated(relayed))
    }
    RefreshOperation(requested_lifetime) => {
      let lifetime = response_lifetime(message)
      self.schedule_lifetime(now, lifetime)
      if requested_lifetime == 0U || lifetime == 0U {
        self.set_state(Closed)
      } else {
        self.set_state(Active)
      }
    }
    PermissionOperation(peer) => {
      self.upsert_permission(peer, now)
      self.events.push(PermissionCreated(peer))
    }
    ChannelBindOperation(peer, channel) => {
      self.upsert_channel(peer, channel, now)
      self.events.push(ChannelBound(peer~, channel~))
    }
  }
}

///|
fn Allocation::verify_authenticated_response(
  self : Allocation,
  message : @stun.Message,
  transaction : PendingTurnTransaction,
) -> Unit raise TurnError {
  if transaction.authenticated {
    guard self.key is Some(key) else { raise AuthenticationFailed }
    turn_stun(() => message.verify_integrity(key))
  }
  if message.first_attribute(Fingerprint) is Some(_) {
    turn_stun(() => message.verify_fingerprint())
  }
}

///|
fn decode_channel_data(packet : Bytes) -> (UInt16, Bytes)? raise TurnError {
  if packet.length() < 4 || (packet[0] & 0xc0) != 0x40 {
    return None
  }
  let channel = (packet[0].to_uint16() << 8) | packet[1].to_uint16()
  if channel < 0x4000 || channel > 0x7fff {
    raise InvalidPacket("invalid TURN ChannelData channel number")
  }
  let length = ((packet[2].to_uint() << 8) | packet[3].to_uint()).reinterpret_as_int()
  if 4 + length > packet.length() || packet.length() - (4 + length) > 3 {
    raise InvalidPacket("invalid TURN ChannelData length")
  }
  for byte in packet[4 + length:] {
    if byte != 0 {
      raise InvalidPacket("TURN ChannelData padding must be zero")
    }
  }
  Some((channel, packet[4:4 + length].to_owned()))
}

///|
fn encode_channel_data(
  channel : UInt16,
  payload : Bytes,
) -> Bytes raise TurnError {
  if channel < 0x4000 || channel > 0x7fff {
    raise InvalidPacket("invalid TURN ChannelData channel number")
  }
  if payload.length() > 0xffff {
    raise InvalidPacket("TURN ChannelData payload exceeds 65535 bytes")
  }
  Bytes::from_array([
    (channel >> 8).to_byte(),
    channel.to_byte(),
    (payload.length() >> 8).to_byte(),
    payload.length().to_byte(),
  ]) +
  payload
}

///|
fn Allocation::handle_data_indication(
  self : Allocation,
  message : @stun.Message,
) -> Unit raise TurnError {
  guard message.first_attribute(XorPeerAddress) is Some(peer_attribute) &&
    message.first_attribute(DataAttribute) is Some(payload_attribute) else {
    raise InvalidPacket("TURN DATA indication omitted peer address or payload")
  }
  let peer = turn_stun(() => {
    peer_attribute.to_xor_address(message.transaction_id())
  })
  self.events.push(PeerData(peer~, payload=payload_attribute.value()))
}

///|
fn Allocation::handle_packet(
  self : Allocation,
  now : @transport.Instant,
  payload : Bytes,
) -> Unit raise TurnError {
  if self.state == Closed {
    return
  }
  match decode_channel_data(payload) {
    Some((channel, payload)) => {
      for binding in self.channels {
        if binding.channel == channel && binding.expires_at > now {
          self.events.push(PeerData(peer=binding.peer, payload~))
          return
        }
      }
      raise ChannelBindingMissing
    }
    None => ()
  }
  let message = turn_stun(() => @stun.Message::decode(payload))
  if message.class() == Indication && message.stun_method() == Data {
    self.handle_data_indication(message)
    return
  }
  guard self.transactions.get(message.transaction_id()) is Some(transaction) else {
    return
  }
  if message.stun_method() != operation_method(transaction.operation) {
    return
  }
  self.transactions.remove(message.transaction_id())
  match message.class() {
    ErrorResponse => {
      let code = message_error_code(message).unwrap_or(0)
      if code == 438 && transaction.authenticated {
        self.verify_authenticated_response(message, transaction)
      }
      self.handle_authentication_challenge(message, transaction, code, now)
    }
    SuccessResponse => {
      self.verify_authenticated_response(message, transaction)
      self.handle_success(message, transaction, now)
    }
    Request | Indication =>
      raise InvalidResponse("TURN transaction received a non-response")
  }
}

///|
pub fn Allocation::handle_datagram(
  self : Allocation,
  datagram : @transport.InboundDatagram,
) -> Unit raise TurnError {
  if self.transport != Udp || datagram.context != self.context() {
    return
  }
  self.handle_packet(datagram.now, datagram.payload)
}

///|
fn turn_stream_frame_length(buffer : Bytes) -> Int? raise TurnError {
  if buffer.length() < 4 {
    return None
  }
  let packet_class = buffer[0] & 0xc0
  if packet_class == 0 {
    if buffer.length() < 20 {
      return None
    }
    let body_length = ((buffer[2].to_uint() << 8) | buffer[3].to_uint()).reinterpret_as_int()
    if body_length % 4 != 0 {
      raise InvalidPacket("TURN stream STUN length is not 32-bit aligned")
    }
    let frame_length = 20 + body_length
    if frame_length > 65555 {
      raise InvalidPacket("TURN stream STUN frame is too large")
    }
    if buffer.length() < frame_length {
      None
    } else {
      Some(frame_length)
    }
  } else if packet_class == 0x40 {
    let payload_length = ((buffer[2].to_uint() << 8) | buffer[3].to_uint()).reinterpret_as_int()
    let frame_length = (4 + payload_length + 3) / 4 * 4
    if buffer.length() < frame_length {
      None
    } else {
      Some(frame_length)
    }
  } else {
    raise InvalidPacket("invalid TURN stream frame prefix")
  }
}

///|
pub fn Allocation::handle_stream_bytes(
  self : Allocation,
  now : @transport.Instant,
  bytes : Bytes,
) -> Unit raise TurnError {
  if self.transport == Udp {
    raise InvalidState("UDP TURN allocation has no stream input")
  }
  if self.state == Closed {
    return
  }
  if self.stream_input.length() + bytes.length() > 1048576 {
    self.set_state(Failed)
    raise InvalidPacket("TURN stream input buffer exceeded one MiB")
  }
  self.stream_input = self.stream_input + bytes
  for ;; {
    match turn_stream_frame_length(self.stream_input) {
      None => return
      Some(frame_length) => {
        let frame = self.stream_input[0:frame_length].to_owned()
        self.stream_input = self.stream_input[frame_length:].to_owned()
        self.handle_packet(now, frame)
      }
    }
  }
}

///|
pub fn Allocation::handle_stream_closed(self : Allocation) -> Unit {
  self.stream_input = b""
  self.stream_outputs.clear()
  self.transactions.clear()
  self.expires_at = None
  self.refresh_at = None
  if self.state != Closed {
    self.set_state(Failed)
  }
}

///|
pub fn Allocation::create_permission(
  self : Allocation,
  peer : @transport.SocketAddress,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state != Active {
    raise InvalidState("TURN allocation is not active")
  }
  self.start_operation(PermissionOperation(peer), now)
}

///|
pub fn Allocation::bind_channel(
  self : Allocation,
  peer : @transport.SocketAddress,
  channel : UInt16,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state != Active {
    raise InvalidState("TURN allocation is not active")
  }
  if channel < 0x4000 || channel > 0x7fff {
    raise InvalidConfiguration("TURN channel number must be in 0x4000..0x7fff")
  }
  self.start_operation(ChannelBindOperation(peer, channel), now)
}

///|
fn Allocation::permission_active(
  self : Allocation,
  peer : @transport.SocketAddress,
  now : @transport.Instant,
) -> Bool {
  self.permissions.any(permission => {
    permission.peer == peer && permission.expires_at > now
  })
}

///|
fn Allocation::active_channel(
  self : Allocation,
  peer : @transport.SocketAddress,
  now : @transport.Instant,
) -> UInt16? {
  for binding in self.channels {
    if binding.peer == peer && binding.expires_at > now {
      return Some(binding.channel)
    }
  }
  None
}

///|
pub fn Allocation::send(
  self : Allocation,
  peer : @transport.SocketAddress,
  payload : Bytes,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state != Active {
    raise InvalidState("TURN allocation is not active")
  }
  match self.active_channel(peer, now) {
    Some(channel) => self.queue_packet(encode_channel_data(channel, payload))
    None => {
      if !self.permission_active(peer, now) {
        raise PermissionMissing
      }
      let transaction_id = turn_stun(() => @stun.TransactionId::random())
      let message = @stun.Message::new(
        class=Indication,
        stun_method=Send,
        transaction_id~,
        attributes=[
          turn_stun(() => {
            @stun.Attribute::from_xor_address(
              peer,
              transaction_id,
              attribute_type=XorPeerAddress,
            )
          }),
          data_attribute(payload),
        ],
      )
      self.queue_packet(turn_stun(() => message.encode()))
    }
  }
}

///|
pub fn Allocation::refresh(
  self : Allocation,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state != Active {
    raise InvalidState("TURN allocation is not active")
  }
  self.set_state(Refreshing)
  self.start_operation(RefreshOperation(600U), now)
}

///|
pub fn Allocation::handle_timeout(
  self : Allocation,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state == Closed || self.state == Failed {
    return
  }
  match self.expires_at {
    Some(deadline) if deadline <= now => {
      self.set_state(Failed)
      raise AllocationExpired
    }
    _ => ()
  }
  self.permissions.retain(permission => permission.expires_at > now)
  self.channels.retain(binding => binding.expires_at > now)
  match self.refresh_at {
    Some(deadline) if deadline <= now && self.state == Active => {
      self.refresh_at = None
      self.refresh(now)
    }
    _ => ()
  }
  let due : Array[@stun.TransactionId] = []
  for entry in self.transactions {
    let (transaction_id, transaction) = entry
    if transaction.deadline <= now {
      due.push(transaction_id)
    }
  }
  for transaction_id in due {
    guard self.transactions.get(transaction_id) is Some(transaction) else {
      continue
    }
    if self.transport != Udp {
      self.transactions.remove(transaction_id)
      match transaction.operation {
        AllocateOperation | RefreshOperation(_) => self.set_state(Failed)
        PermissionOperation(_) | ChannelBindOperation(_) => ()
      }
      raise Transaction(TransactionTimedOut)
    }
    if transaction.retransmissions >= 7 {
      self.transactions.remove(transaction_id)
      match transaction.operation {
        AllocateOperation | RefreshOperation(_) => self.set_state(Failed)
        PermissionOperation(_) | ChannelBindOperation(_) => ()
      }
      raise Transaction(TransactionTimedOut)
    }
    self.queue_packet(transaction.packet)
    transaction.retransmissions += 1
    transaction.rto_milliseconds = if transaction.rto_milliseconds < 8000L {
      transaction.rto_milliseconds * 2L
    } else {
      8000L
    }
    transaction.deadline = turn_after(now, transaction.rto_milliseconds)
  }
}

///|
pub fn Allocation::close(
  self : Allocation,
  now : @transport.Instant,
) -> Unit raise TurnError {
  if self.state == Closed {
    return
  }
  if self.state == Active && self.key is Some(_) {
    self.start_operation(RefreshOperation(0U), now)
  }
  self.transactions.clear()
  self.permissions.clear()
  self.channels.clear()
  self.expires_at = None
  self.refresh_at = None
  self.set_state(Closed)
}
