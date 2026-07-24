///|
pub(all) enum CandidatePairState {
  PairWaiting
  PairInProgress
  PairSucceeded
  PairFailed
} derive(Debug, Eq)

///|
pub struct CandidatePair {
  local_candidate : IceCandidate
  remote_candidate : IceCandidate
  priority : UInt64
  mut state : CandidatePairState
  mut nominated : Bool
} derive(Debug, Eq)

///|
pub fn CandidatePair::local_candidate(self : CandidatePair) -> IceCandidate {
  self.local_candidate
}

///|
pub fn CandidatePair::remote_candidate(self : CandidatePair) -> IceCandidate {
  self.remote_candidate
}

///|
pub fn CandidatePair::priority(self : CandidatePair) -> UInt64 {
  self.priority
}

///|
pub fn CandidatePair::state(self : CandidatePair) -> CandidatePairState {
  self.state
}

///|
pub fn CandidatePair::is_nominated(self : CandidatePair) -> Bool {
  self.nominated
}

///|
pub(all) enum IceEvent {
  ConnectionStateChanged(IceConnectionState)
  RoleChanged(IceRole)
  SelectedPair(CandidatePair)
  ApplicationDatagram(@transport.InboundDatagram)
} derive(Debug, Eq)

///|
pub struct IceAgent {
  local_credentials : IceCredentials
  mut remote_credentials : IceCredentials?
  mut role : IceRole
  tie_breaker : UInt64
  local_candidates : Array[IceCandidate]
  remote_candidates : Array[IceCandidate]
  pairs : Array[CandidatePair]
  transactions : Map[
    @stun.TransactionId,
    (Int, Bytes, @transport.TransportContext, Int, Int64, @transport.Instant),
  ]
  outputs : @queue.Queue[@transport.OutboundDatagram]
  events : @queue.Queue[IceEvent]
  mut state : IceConnectionState
  mut selected_pair_index : Int?
  mut next_check : @transport.Instant?
  check_interval : @transport.Duration
  initial_rto : @transport.Duration
  reliable_timeout : @transport.Duration
  max_retransmissions : Int
  disconnected_timeout : @transport.Duration
  failed_timeout : @transport.Duration
  keepalive_interval : @transport.Duration
  mut next_keepalive : @transport.Instant?
  mut disconnected_deadline : @transport.Instant?
  mut failed_deadline : @transport.Instant?
}

///|
fn[T] from_stun(operation : () -> T raise @stun.StunError) -> T raise IceError {
  operation() catch {
    error => raise Stun(error)
  }
}

///|
fn ice_after(
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
pub fn IceAgent::new(
  local_credentials~ : IceCredentials,
  role~ : IceRole,
  tie_breaker~ : UInt64,
  check_interval? : @transport.Duration,
  initial_rto? : @transport.Duration,
  reliable_timeout? : @transport.Duration,
  max_retransmissions? : Int = 7,
  disconnected_timeout? : @transport.Duration,
  failed_timeout? : @transport.Duration,
  keepalive_interval? : @transport.Duration,
) -> IceAgent raise IceError {
  if tie_breaker == 0UL {
    raise InvalidState("ICE tie breaker must be nonzero")
  }
  let check_interval = match check_interval {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(50L) catch {
        error => raise Time(error)
      }
  }
  let initial_rto = match initial_rto {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(500L) catch {
        error => raise Time(error)
      }
  }
  let reliable_timeout = match reliable_timeout {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(39500L) catch {
        error => raise Time(error)
      }
  }
  let disconnected_timeout = match disconnected_timeout {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(5000L) catch {
        error => raise Time(error)
      }
  }
  let failed_timeout = match failed_timeout {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(25000L) catch {
        error => raise Time(error)
      }
  }
  let keepalive_interval = match keepalive_interval {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(2000L) catch {
        error => raise Time(error)
      }
  }
  if check_interval.as_milliseconds() <= 0L ||
    initial_rto.as_milliseconds() <= 0L ||
    reliable_timeout.as_milliseconds() <= 0L ||
    disconnected_timeout.as_milliseconds() <= 0L ||
    failed_timeout.as_milliseconds() <= 0L ||
    keepalive_interval.as_milliseconds() <= 0L {
    raise InvalidState("ICE timer durations must be positive")
  }
  if max_retransmissions < 0 || max_retransmissions > 32 {
    raise InvalidState("ICE maximum retransmissions is outside 0..32")
  }
  {
    local_credentials,
    remote_credentials: None,
    role,
    tie_breaker,
    local_candidates: [],
    remote_candidates: [],
    pairs: [],
    transactions: Map([]),
    outputs: Queue([]),
    events: Queue([]),
    state: New,
    selected_pair_index: None,
    next_check: None,
    check_interval,
    initial_rto,
    reliable_timeout,
    max_retransmissions,
    disconnected_timeout,
    failed_timeout,
    keepalive_interval,
    next_keepalive: None,
    disconnected_deadline: None,
    failed_deadline: None,
  }
}

///|
pub fn IceAgent::state(self : IceAgent) -> IceConnectionState {
  self.state
}

///|
pub fn IceAgent::role(self : IceAgent) -> IceRole {
  self.role
}

///|
pub fn IceAgent::local_credentials(self : IceAgent) -> IceCredentials {
  self.local_credentials
}

///|
pub fn IceAgent::remote_credentials(self : IceAgent) -> IceCredentials? {
  self.remote_credentials
}

///|
pub fn IceAgent::local_candidates(self : IceAgent) -> Array[IceCandidate] {
  self.local_candidates.copy()
}

///|
pub fn IceAgent::remote_candidates(self : IceAgent) -> Array[IceCandidate] {
  self.remote_candidates.copy()
}

///|
pub fn IceAgent::candidate_pairs(self : IceAgent) -> Array[CandidatePair] {
  self.pairs.copy()
}

///|
pub fn IceAgent::selected_pair(self : IceAgent) -> CandidatePair? {
  match self.selected_pair_index {
    Some(index) => Some(self.pairs[index])
    None => None
  }
}

///|
fn validate_transport_candidate(
  candidate : IceCandidate,
  side : String,
) -> Unit raise IceError {
  if candidate.socket_address() is None {
    raise InvalidCandidate(
      "\{side} ICE candidate must have a resolved transport address",
    )
  }
}

///|
fn tcp_pair_compatible(
  local_candidate : IceCandidate,
  remote : IceCandidate,
) -> Bool {
  if local_candidate.protocol != Tcp {
    return true
  }
  guard local_candidate.tcp_type is Some(local_type) &&
    remote.tcp_type is Some(remote_type) else {
    return false
  }
  match (local_type, remote_type) {
    (Active, Passive)
    | (Active, SimultaneousOpen)
    | (Passive, SimultaneousOpen)
    | (SimultaneousOpen, Active)
    | (SimultaneousOpen, Passive)
    | (SimultaneousOpen, SimultaneousOpen) => true
    (Passive, Active) => remote.port != 0
    _ => false
  }
}

///|
fn IceAgent::add_pair(
  self : IceAgent,
  local_candidate : IceCandidate,
  remote : IceCandidate,
) -> Bool {
  if local_candidate.component != remote.component ||
    local_candidate.protocol != remote.protocol ||
    !tcp_pair_compatible(local_candidate, remote) {
    return false
  }
  if self.pairs.any(pair => {
      pair.local_candidate == local_candidate && pair.remote_candidate == remote
    }) {
    return false
  }
  self.pairs.push({
    local_candidate,
    remote_candidate: remote,
    priority: candidate_pair_priority(local_candidate, remote, self.role),
    state: PairWaiting,
    nominated: false,
  })
  true
}

///|
fn IceAgent::activate_trickled_pairs(
  self : IceAgent,
  now : @transport.Instant?,
  added : Bool,
) -> Unit raise IceError {
  if !added || self.state == New || self.state == Closed {
    return
  }
  guard now is Some(now) else {
    raise InvalidState("trickled candidates require the current time")
  }
  if self.state == Failed {
    self.set_connection_state(Checking)
  }
  if self.transactions.is_empty() && self.next_check is None {
    self.send_next_waiting_check(now)
    return
  }
  match self.next_check {
    Some(deadline) if deadline <= now => ()
    _ => self.next_check = Some(now)
  }
}

///|
pub fn IceAgent::add_local_candidate(
  self : IceAgent,
  candidate : IceCandidate,
  now? : @transport.Instant,
) -> Unit raise IceError {
  if self.state == Closed {
    raise InvalidState("cannot add a local candidate after ICE closes")
  }
  validate_transport_candidate(candidate, "local")
  let mut added = false
  if !self.local_candidates.contains(candidate) {
    self.local_candidates.push(candidate)
    for remote in self.remote_candidates {
      if self.add_pair(candidate, remote) {
        added = true
      }
    }
  }
  if added && self.state == New {
    self.pairs.sort_by((left, right) => right.priority.compare(left.priority))
  }
  self.activate_trickled_pairs(now, added)
}

///|
pub fn IceAgent::add_remote_candidate(
  self : IceAgent,
  candidate : IceCandidate,
  now? : @transport.Instant,
) -> Unit raise IceError {
  if self.state == Closed {
    raise InvalidState("cannot add a remote candidate after ICE closes")
  }
  validate_transport_candidate(candidate, "remote")
  let mut added = false
  if !self.remote_candidates.contains(candidate) {
    self.remote_candidates.push(candidate)
    for local_candidate in self.local_candidates {
      if self.add_pair(local_candidate, candidate) {
        added = true
      }
    }
  }
  if added && self.state == New {
    self.pairs.sort_by((left, right) => right.priority.compare(left.priority))
  }
  self.activate_trickled_pairs(now, added)
}

///|
pub fn IceAgent::set_remote_credentials(
  self : IceAgent,
  credentials : IceCredentials,
) -> Unit raise IceError {
  if self.state != New || self.remote_credentials is Some(_) {
    raise InvalidState("remote ICE credentials are already fixed")
  }
  self.remote_credentials = Some(credentials)
}

///|
fn candidate_pair_priority(
  local_candidate : IceCandidate,
  remote : IceCandidate,
  role : IceRole,
) -> UInt64 {
  let (controlling, controlled) = if role == Controlling {
    (local_candidate.priority, remote.priority)
  } else {
    (remote.priority, local_candidate.priority)
  }
  let minimum = if controlling < controlled { controlling } else { controlled }
  let maximum = if controlling > controlled { controlling } else { controlled }
  (minimum.to_uint64() << 32) |
  (maximum.to_uint64() << 1) |
  (if controlling > controlled { 1UL } else { 0UL })
}

///|
fn IceAgent::build_pairs(self : IceAgent) -> Unit {
  self.pairs.clear()
  for local_candidate in self.local_candidates {
    for remote in self.remote_candidates {
      ignore(self.add_pair(local_candidate, remote))
    }
  }
  self.pairs.sort_by((left, right) => right.priority.compare(left.priority))
}

///|
fn IceAgent::set_connection_state(
  self : IceAgent,
  state : IceConnectionState,
) -> Unit {
  if self.state != state {
    self.state = state
    self.events.push(ConnectionStateChanged(state))
  }
}

///|
fn IceAgent::refresh_liveness(
  self : IceAgent,
  now : @transport.Instant,
) -> Unit raise IceError {
  if self.selected_pair_index is None ||
    self.state == Closed ||
    self.state == Failed {
    return
  }
  self.next_keepalive = Some(
    ice_after(now, self.keepalive_interval.as_milliseconds()),
  )
  self.disconnected_deadline = Some(
    ice_after(now, self.disconnected_timeout.as_milliseconds()),
  )
  self.failed_deadline = None
  if self.state == Disconnected {
    self.set_connection_state(Completed)
  }
}

///|
fn IceAgent::send_keepalive(
  self : IceAgent,
  now : @transport.Instant,
) -> Unit raise IceError {
  guard self.selected_pair_index is Some(pair_index) else {
    self.next_keepalive = None
    return
  }
  let has_pending = self.transactions
    .values()
    .any(transaction => {
      let (pending_pair, _, _, _, _, _) = transaction
      pending_pair == pair_index
    })
  if !has_pending {
    let transaction_id = from_stun(() => @stun.TransactionId::random())
    let pair = self.pairs[pair_index]
    let request = self.binding_request(pair, transaction_id)
    let context = pair_context(pair)
    self.outputs.push({ context, payload: request })
    let initial_timeout = if context.protocol == Udp {
      self.initial_rto.as_milliseconds()
    } else {
      self.reliable_timeout.as_milliseconds()
    }
    self.transactions[transaction_id] = (
      pair_index,
      request,
      context,
      0,
      initial_timeout,
      ice_after(now, initial_timeout),
    )
  }
  self.next_keepalive = Some(
    ice_after(now, self.keepalive_interval.as_milliseconds()),
  )
}

///|
pub fn IceAgent::start(
  self : IceAgent,
  now : @transport.Instant,
) -> Unit raise IceError {
  if self.state != New {
    raise InvalidState("ICE agent has already started")
  }
  if self.remote_credentials is None || self.local_candidates.is_empty() {
    raise InvalidState("ICE credentials and local candidates are incomplete")
  }
  self.build_pairs()
  self.set_connection_state(Checking)
  if !self.pairs.is_empty() {
    self.send_next_waiting_check(now)
  }
}

///|
fn pair_context(pair : CandidatePair) -> @transport.TransportContext {
  let local_address = pair.local_candidate.base_socket_address().unwrap()
  let remote = pair.remote_candidate.socket_address().unwrap()
  {
    local_address,
    peer: remote,
    ecn: None,
    protocol: pair.local_candidate.protocol,
  }
}

///|
fn IceAgent::binding_request(
  self : IceAgent,
  pair : CandidatePair,
  transaction_id : @stun.TransactionId,
) -> Bytes raise IceError {
  let remote_credentials = self.remote_credentials.unwrap()
  let attributes : Array[@stun.Attribute] = [
    from_stun(() => {
      @stun.Attribute::username(
        remote_credentials.username_fragment() +
        ":" +
        self.local_credentials.username_fragment(),
      )
    }),
    from_stun(() => @stun.Attribute::priority(pair.local_candidate.priority)),
  ]
  attributes.push(
    if self.role == Controlling {
      from_stun(() => @stun.Attribute::ice_controlling(self.tie_breaker))
    } else {
      from_stun(() => @stun.Attribute::ice_controlled(self.tie_breaker))
    },
  )
  if self.role == Controlling {
    attributes.push(from_stun(() => @stun.Attribute::use_candidate()))
  }
  let request = @stun.Message::new(
    class=Request,
    stun_method=Binding,
    transaction_id~,
    attributes~,
  )
  from_stun(() => {
    request.encode_authenticated(@utf8.encode(remote_credentials.password()))
  })
}

///|
fn IceAgent::send_next_waiting_check(
  self : IceAgent,
  now : @transport.Instant,
) -> Unit raise IceError {
  let mut pair_index = -1
  for index = 0; index < self.pairs.length(); index = index + 1 {
    if self.pairs[index].state == PairWaiting {
      pair_index = index
      break
    }
  }
  if pair_index < 0 {
    self.next_check = None
    return
  }
  let transaction_id = from_stun(() => @stun.TransactionId::random())
  let pair = self.pairs[pair_index]
  let request = self.binding_request(pair, transaction_id)
  let context = pair_context(pair)
  self.outputs.push({ context, payload: request })
  pair.state = PairInProgress
  let initial_timeout = if context.protocol == Udp {
    self.initial_rto.as_milliseconds()
  } else {
    self.reliable_timeout.as_milliseconds()
  }
  self.transactions[transaction_id] = (
    pair_index,
    request,
    context,
    0,
    initial_timeout,
    ice_after(now, initial_timeout),
  )
  let has_waiting = self.pairs.any(pair => pair.state == PairWaiting)
  self.next_check = if has_waiting {
    Some(ice_after(now, self.check_interval.as_milliseconds()))
  } else {
    None
  }
}

///|
pub fn IceAgent::poll_datagram(self : IceAgent) -> @transport.OutboundDatagram? {
  self.outputs.pop()
}

///|
pub fn IceAgent::poll_event(self : IceAgent) -> IceEvent? {
  self.events.pop()
}

///|
pub fn IceAgent::poll_timeout(self : IceAgent) -> @transport.Instant? {
  let mut result = self.next_check
  for transaction in self.transactions.values() {
    let (_, _, _, _, _, next_retry) = transaction
    match result {
      None => result = Some(next_retry)
      Some(current) => if next_retry < current { result = Some(next_retry) }
    }
  }
  for
    deadline in [
      self.next_keepalive,
      self.disconnected_deadline,
      self.failed_deadline,
    ] {
    match (result, deadline) {
      (None, Some(candidate)) => result = Some(candidate)
      (Some(current), Some(candidate)) =>
        if candidate < current {
          result = Some(candidate)
        }
      _ => ()
    }
  }
  result
}

///|
fn IceAgent::maybe_fail(self : IceAgent) -> Unit {
  if self.selected_pair_index is None &&
    self.transactions.is_empty() &&
    self.next_check is None &&
    self.pairs.all(pair => pair.state == PairFailed) {
    self.set_connection_state(Failed)
  }
}

///|
pub fn IceAgent::handle_timeout(
  self : IceAgent,
  now : @transport.Instant,
) -> Unit raise IceError {
  if self.state == Closed || self.state == Failed {
    return
  }
  let due : Array[@stun.TransactionId] = []
  for entry in self.transactions {
    let (transaction_id, transaction) = entry
    let (_, _, _, _, _, next_retry) = transaction
    if next_retry <= now {
      due.push(transaction_id)
    }
  }
  for transaction_id in due {
    match self.transactions.get(transaction_id) {
      Some(transaction) => {
        let (pair_index, request, context, retransmissions, rto_milliseconds, _) = transaction
        if context.protocol == Tcp ||
          retransmissions >= self.max_retransmissions {
          self.pairs[pair_index].state = PairFailed
          self.transactions.remove(transaction_id)
        } else {
          self.outputs.push({ context, payload: request })
          let next_rto = if rto_milliseconds < 8000L {
            rto_milliseconds * 2L
          } else {
            8000L
          }
          self.transactions[transaction_id] = (
            pair_index,
            request,
            context,
            retransmissions + 1,
            next_rto,
            ice_after(now, next_rto),
          )
        }
      }
      None => ()
    }
  }
  match self.next_check {
    Some(deadline) if deadline <= now => self.send_next_waiting_check(now)
    _ => ()
  }
  match self.next_keepalive {
    Some(deadline) =>
      if deadline <= now &&
        (self.state == Completed || self.state == Disconnected) {
        self.send_keepalive(now)
      }
    _ => ()
  }
  match self.disconnected_deadline {
    Some(deadline) if deadline <= now && self.state == Completed => {
      self.disconnected_deadline = None
      self.failed_deadline = Some(
        ice_after(now, self.failed_timeout.as_milliseconds()),
      )
      self.set_connection_state(Disconnected)
    }
    _ => ()
  }
  match self.failed_deadline {
    Some(deadline) if deadline <= now && self.state == Disconnected => {
      self.transactions.clear()
      self.next_check = None
      self.next_keepalive = None
      self.disconnected_deadline = None
      self.failed_deadline = None
      self.set_connection_state(Failed)
    }
    _ => ()
  }
  self.maybe_fail()
}

///|
fn IceAgent::pair_index_for_context(
  self : IceAgent,
  context : @transport.TransportContext,
) -> Int? {
  for index = 0; index < self.pairs.length(); index = index + 1 {
    if pair_context(self.pairs[index]) == context {
      return Some(index)
    }
  }
  None
}

///|
fn IceAgent::add_peer_reflexive_pair(
  self : IceAgent,
  datagram : @transport.InboundDatagram,
  priority : UInt,
) -> Int raise IceError {
  let mut matching_local : IceCandidate? = None
  for candidate in self.local_candidates {
    if candidate.protocol == datagram.context.protocol &&
      candidate.base_socket_address() == Some(datagram.context.local_address) {
      matching_local = Some(candidate)
      break
    }
  }
  guard matching_local is Some(local_candidate) else {
    raise InvalidCandidate(
      "peer-reflexive check arrived on an unknown local candidate",
    )
  }
  let tcp_type : TcpCandidateType? = match local_candidate.tcp_type {
    Some(Passive) => Some(Active)
    Some(Active) => Some(Passive)
    Some(SimultaneousOpen) => Some(SimultaneousOpen)
    None => None
  }
  let remote = IceCandidate::new(
    foundation="prflx",
    component=local_candidate.component,
    protocol=datagram.context.protocol,
    priority~,
    address=IpAddress(datagram.context.peer.address()),
    port=datagram.context.peer.port(),
    candidate_type=PeerReflexive,
    tcp_type?,
  )
  self.add_remote_candidate(remote, now=datagram.now)
  guard self.pair_index_for_context(datagram.context) is Some(pair_index) else {
    raise InvalidCandidate("failed to form a peer-reflexive candidate pair")
  }
  pair_index
}

///|
fn IceAgent::change_role(
  self : IceAgent,
  role : IceRole,
  now : @transport.Instant,
) -> Unit {
  if self.role == role {
    return
  }
  self.role = role
  self.events.push(RoleChanged(role))
  self.transactions.clear()
  for pair in self.pairs {
    if pair.state == PairInProgress {
      pair.state = PairWaiting
    }
  }
  self.next_check = Some(now)
}

///|
fn IceAgent::mark_succeeded(self : IceAgent, pair_index : Int) -> Unit {
  self.pairs[pair_index].state = PairSucceeded
  if self.state == Checking {
    self.set_connection_state(Connected)
  }
}

///|
fn IceAgent::select_pair(
  self : IceAgent,
  pair_index : Int,
  now : @transport.Instant,
) -> Unit raise IceError {
  self.mark_succeeded(pair_index)
  self.pairs[pair_index].nominated = true
  let changed = self.selected_pair_index != Some(pair_index)
  self.selected_pair_index = Some(pair_index)
  if changed {
    self.events.push(SelectedPair(self.pairs[pair_index]))
  }
  self.set_connection_state(Completed)
  self.refresh_liveness(now)
}

///|
fn unique_attribute(
  message : @stun.Message,
  attribute_type : @stun.AttributeType,
) -> @stun.Attribute? raise IceError {
  let mut result : @stun.Attribute? = None
  for attribute in message.attributes() {
    if attribute.attribute_type() == attribute_type {
      if result is Some(_) {
        raise InvalidState("duplicate ICE STUN attribute")
      }
      result = Some(attribute)
    }
  }
  result
}

///|
fn IceAgent::send_error_response(
  self : IceAgent,
  request : @stun.Message,
  context : @transport.TransportContext,
  code : UInt16,
  unknown_attributes? : Array[UInt16] = [],
) -> Unit raise IceError {
  let error = from_stun(() => @stun.ResponseError::with_default_reason(code))
  let response = from_stun(() => @stun.Message::error_response(request, error))
  if !unknown_attributes.is_empty() {
    response.add_attribute(
      from_stun(() => {
        @stun.Attribute::from_unknown_attributes(unknown_attributes)
      }),
    )
  }
  let payload = from_stun(() => {
    response.encode_authenticated(
      @utf8.encode(self.local_credentials.password()),
    )
  })
  self.outputs.push({ context, payload })
}

///|
fn IceAgent::handle_binding_request(
  self : IceAgent,
  datagram : @transport.InboundDatagram,
  message : @stun.Message,
  known_pair_index : Int?,
) -> Unit raise IceError {
  let unknown_attributes = message.unknown_required_attributes()
  if !unknown_attributes.is_empty() {
    self.send_error_response(
      message,
      datagram.context,
      420,
      unknown_attributes~,
    )
    return
  }
  let expected_username = self.local_credentials.username_fragment() +
    ":" +
    self.remote_credentials.unwrap().username_fragment()
  guard unique_attribute(message, Username) is Some(username) else {
    self.send_error_response(message, datagram.context, 400)
    return
  }
  if from_stun(() => username.as_text()) != expected_username {
    self.send_error_response(message, datagram.context, 401)
    return
  }
  from_stun(() => {
    message.verify_integrity(@utf8.encode(self.local_credentials.password()))
  })
  from_stun(() => message.verify_fingerprint())
  guard unique_attribute(message, Priority) is Some(priority_attribute) else {
    self.send_error_response(message, datagram.context, 400)
    return
  }
  let priority = from_stun(() => priority_attribute.as_u32())
  let controlling = unique_attribute(message, IceControlling)
  let controlled = unique_attribute(message, IceControlled)
  if (controlling is Some(_) && controlled is Some(_)) ||
    (controlling is None && controlled is None) {
    self.send_error_response(message, datagram.context, 400)
    return
  }
  if self.role == Controlling {
    match controlling {
      Some(attribute) => {
        let remote_tie_breaker = from_stun(() => attribute.as_u64())
        if remote_tie_breaker >= self.tie_breaker {
          self.change_role(Controlled, datagram.now)
        } else {
          self.send_error_response(message, datagram.context, 487)
          return
        }
      }
      None => ()
    }
  } else {
    match controlled {
      Some(attribute) => {
        let remote_tie_breaker = from_stun(() => attribute.as_u64())
        if self.tie_breaker > remote_tie_breaker {
          self.change_role(Controlling, datagram.now)
        } else {
          self.send_error_response(message, datagram.context, 487)
          return
        }
      }
      None => ()
    }
  }
  let xor_address = from_stun(() => {
    @stun.Attribute::from_xor_address(
      datagram.context.peer,
      message.transaction_id(),
    )
  })
  let response = @stun.Message::new(
    class=SuccessResponse,
    stun_method=Binding,
    transaction_id=message.transaction_id(),
    attributes=[xor_address],
  )
  let payload = from_stun(() => {
    response.encode_authenticated(
      @utf8.encode(self.local_credentials.password()),
    )
  })
  self.outputs.push({ context: datagram.context, payload })
  let pair_index = match known_pair_index {
    Some(index) => index
    None => self.add_peer_reflexive_pair(datagram, priority)
  }
  self.mark_succeeded(pair_index)
  if self.selected_pair_index == Some(pair_index) {
    self.refresh_liveness(datagram.now)
  }
  if self.role == Controlled &&
    unique_attribute(message, UseCandidate) is Some(_) {
    self.select_pair(pair_index, datagram.now)
  }
}

///|
fn IceAgent::handle_binding_response(
  self : IceAgent,
  datagram : @transport.InboundDatagram,
  message : @stun.Message,
) -> Unit raise IceError {
  let transaction_id = message.transaction_id()
  guard self.transactions.get(transaction_id) is Some(transaction) else {
    return
  }
  let (pair_index, _, _, _, _, _) = transaction
  let original_pair = self.pairs[pair_index]
  let original_context = pair_context(original_pair)
  if original_context.local_address != datagram.context.local_address ||
    original_context.protocol != datagram.context.protocol {
    return
  }
  let remote_credentials = self.remote_credentials.unwrap()
  from_stun(() => {
    message.verify_integrity(@utf8.encode(remote_credentials.password()))
  })
  from_stun(() => message.verify_fingerprint())
  self.transactions.remove(transaction_id)
  if message.class() == SuccessResponse {
    let response_pair_index = if original_context.peer == datagram.context.peer {
      pair_index
    } else {
      if datagram.context.protocol != Udp {
        return
      }
      match self.pair_index_for_context(datagram.context) {
        Some(index) => index
        None => {
          let remote = IceCandidate::new(
            foundation="prflx-response",
            component=original_pair.remote_candidate.component,
            protocol=Udp,
            priority=original_pair.remote_candidate.priority,
            address=IpAddress(datagram.context.peer.address()),
            port=datagram.context.peer.port(),
            candidate_type=PeerReflexive,
          )
          if !self.remote_candidates.contains(remote) {
            self.remote_candidates.push(remote)
          }
          ignore(self.add_pair(original_pair.local_candidate, remote))
          guard self.pair_index_for_context(datagram.context) is Some(index) else {
            raise InvalidCandidate(
              "failed to form a response-source peer-reflexive candidate pair",
            )
          }
          index
        }
      }
    }
    if response_pair_index != pair_index {
      self.pairs[pair_index].state = PairFailed
    }
    self.mark_succeeded(response_pair_index)
    if self.role == Controlling {
      self.select_pair(response_pair_index, datagram.now)
    } else if self.selected_pair_index == Some(response_pair_index) {
      self.refresh_liveness(datagram.now)
    }
  } else if message.class() == ErrorResponse {
    let error = unique_attribute(message, ErrorCode)
    if error is Some(attribute) &&
      from_stun(() => attribute.to_error()).code() == 487 {
      self.pairs[pair_index].state = PairWaiting
      self.change_role(
        if self.role == Controlling {
          Controlled
        } else {
          Controlling
        },
        datagram.now,
      )
    } else {
      self.pairs[pair_index].state = PairFailed
    }
  }
  self.maybe_fail()
}

///|
pub fn IceAgent::handle_datagram(
  self : IceAgent,
  datagram : @transport.InboundDatagram,
) -> Unit raise IceError {
  if self.state == Closed {
    raise InvalidState("ICE agent is closed")
  }
  if self.state == New {
    raise InvalidState("ICE agent has not started")
  }
  if !@stun.Message::is_stun(datagram.payload) {
    match self.selected_pair_index {
      Some(index) if pair_context(self.pairs[index]) == datagram.context => {
        self.refresh_liveness(datagram.now)
        self.events.push(ApplicationDatagram(datagram))
      }
      _ => ()
    }
    return
  }
  let message = from_stun(() => @stun.Message::decode(datagram.payload))
  if message.stun_method() != Binding {
    return
  }
  match message.class() {
    Request =>
      self.handle_binding_request(
        datagram,
        message,
        self.pair_index_for_context(datagram.context),
      )
    SuccessResponse | ErrorResponse =>
      self.handle_binding_response(datagram, message)
    Indication => ()
  }
}

///|
pub fn IceAgent::send(self : IceAgent, payload : Bytes) -> Unit raise IceError {
  guard self.selected_pair_index is Some(index) else {
    raise InvalidState("ICE has no selected candidate pair")
  }
  self.outputs.push({ context: pair_context(self.pairs[index]), payload })
}

///|
pub fn IceAgent::close(self : IceAgent) -> Unit {
  if self.state == Closed {
    return
  }
  self.transactions.clear()
  self.outputs.clear()
  self.next_check = None
  self.next_keepalive = None
  self.disconnected_deadline = None
  self.failed_deadline = None
  self.selected_pair_index = None
  self.set_connection_state(Closed)
}
