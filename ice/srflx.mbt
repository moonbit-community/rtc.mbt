///|
pub struct SrflxGatherer {
  local_candidate : IceCandidate
  server : @transport.SocketAddress
  outputs : @queue.Queue[@transport.OutboundDatagram]
  events : @queue.Queue[SrflxEvent]
  mut state : SrflxGatheringState
  mut transaction_id : @stun.TransactionId?
  mut request : Bytes?
  mut deadline : @transport.Instant?
  mut rto_milliseconds : Int64
  mut retransmissions : Int
}

///|
fn srflx_after(
  now : @transport.Instant,
  milliseconds : Int64,
) -> @transport.Instant raise IceError {
  let duration = @transport.Duration::milliseconds(milliseconds) catch {
    error => raise Time(error)
  }
  now.checked_add(duration) catch {
    error => raise Time(error)
  }
}

///|
fn[T] srflx_stun(operation : () -> T raise @stun.StunError) -> T raise IceError {
  operation() catch {
    error => raise Stun(error)
  }
}

///|
pub fn SrflxGatherer::new(
  local_candidate~ : IceCandidate,
  server~ : @transport.SocketAddress,
) -> SrflxGatherer raise IceError {
  if local_candidate.candidate_type() != Host ||
    local_candidate.protocol() != Udp ||
    local_candidate.socket_address() is None {
    raise InvalidCandidate(
      "srflx gathering requires a resolved UDP host candidate",
    )
  }
  {
    local_candidate,
    server,
    outputs: Queue([]),
    events: Queue([]),
    state: SrflxNew,
    transaction_id: None,
    request: None,
    deadline: None,
    rto_milliseconds: 500L,
    retransmissions: 0,
  }
}

///|
pub fn SrflxGatherer::state(self : SrflxGatherer) -> SrflxGatheringState {
  self.state
}

///|
fn SrflxGatherer::set_state(
  self : SrflxGatherer,
  state : SrflxGatheringState,
) -> Unit {
  if self.state != state {
    self.state = state
    self.events.push(SrflxStateChanged(state))
  }
}

///|
fn SrflxGatherer::context(self : SrflxGatherer) -> @transport.TransportContext {
  {
    local_address: self.local_candidate.socket_address().unwrap(),
    peer: self.server,
    ecn: None,
    protocol: Udp,
  }
}

///|
pub fn SrflxGatherer::handles_context(
  self : SrflxGatherer,
  context : @transport.TransportContext,
) -> Bool {
  self.state == SrflxGathering && context == self.context()
}

///|
pub fn SrflxGatherer::start(
  self : SrflxGatherer,
  now : @transport.Instant,
) -> Unit raise IceError {
  if self.state != SrflxNew {
    raise InvalidState("srflx gatherer has already started")
  }
  let transaction_id = srflx_stun(() => @stun.TransactionId::random())
  let request = srflx_stun(() => {
    @stun.Message::new(class=Request, stun_method=Binding, transaction_id~).encode()
  })
  self.transaction_id = Some(transaction_id)
  self.request = Some(request)
  self.rto_milliseconds = 500L
  self.retransmissions = 0
  self.deadline = Some(srflx_after(now, self.rto_milliseconds))
  self.outputs.push({ context: self.context(), payload: request, })
  self.set_state(SrflxGathering)
}

///|
pub fn SrflxGatherer::poll_datagram(
  self : SrflxGatherer,
) -> @transport.OutboundDatagram? {
  self.outputs.pop()
}

///|
pub fn SrflxGatherer::poll_event(self : SrflxGatherer) -> SrflxEvent? {
  self.events.pop()
}

///|
pub fn SrflxGatherer::poll_timeout(self : SrflxGatherer) -> @transport.Instant? {
  self.deadline
}

///|
pub fn SrflxGatherer::handle_timeout(
  self : SrflxGatherer,
  now : @transport.Instant,
) -> Unit raise IceError {
  guard self.state == SrflxGathering &&
    self.deadline is Some(deadline) &&
    deadline <= now else {
    return
  }
  if self.retransmissions >= 7 {
    self.deadline = None
    self.set_state(SrflxFailed)
    raise ChecklistFailed
  }
  guard self.request is Some(request) else {
    raise InvalidState("srflx request is missing")
  }
  self.outputs.push({ context: self.context(), payload: request, })
  self.retransmissions += 1
  self.rto_milliseconds = if self.rto_milliseconds < 8000L {
    self.rto_milliseconds * 2L
  } else {
    8000L
  }
  self.deadline = Some(srflx_after(now, self.rto_milliseconds))
}

///|
pub fn SrflxGatherer::handle_datagram(
  self : SrflxGatherer,
  datagram : @transport.InboundDatagram,
) -> Unit raise IceError {
  if self.state != SrflxGathering || datagram.context != self.context() {
    return
  }
  let message = srflx_stun(() => @stun.Message::decode(datagram.payload))
  guard self.transaction_id is Some(transaction_id) &&
    message.transaction_id() == transaction_id &&
    message.stun_method() == Binding else {
    return
  }
  if message.class() != SuccessResponse {
    self.deadline = None
    self.set_state(SrflxFailed)
    raise ChecklistFailed
  }
  let mapped = match message.first_attribute(XorMappedAddress) {
    Some(attribute) =>
      srflx_stun(() => attribute.to_xor_address(transaction_id))
    None =>
      match message.first_attribute(MappedAddress) {
        Some(attribute) => srflx_stun(() => attribute.to_address())
        None => {
          self.deadline = None
          self.set_state(SrflxFailed)
          raise InvalidCandidate("STUN response omitted its mapped address")
        }
      }
  }
  let related = self.local_candidate.socket_address().unwrap()
  let candidate = IceCandidate::new(
    foundation=self.local_candidate.foundation() + "-srflx",
    component=self.local_candidate.component(),
    protocol=Udp,
    priority=IceCandidate::priority_value(
      candidate_type=ServerReflexive,
      local_preference=65534,
      component=self.local_candidate.component(),
    ),
    address=IpAddress(mapped.address()),
    port=mapped.port(),
    candidate_type=ServerReflexive,
    related_address=IpAddress(related.address()),
    related_port=related.port(),
  )
  self.deadline = None
  self.events.push(ServerReflexiveCandidate(candidate))
  self.set_state(SrflxComplete)
}

///|
pub fn SrflxGatherer::close(self : SrflxGatherer) -> Unit {
  if self.state == SrflxClosed {
    return
  }
  self.outputs.clear()
  self.deadline = None
  self.request = None
  self.transaction_id = None
  self.set_state(SrflxClosed)
}
