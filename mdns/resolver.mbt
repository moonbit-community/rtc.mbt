///|
struct PendingQuery {
  query_id : QueryId
  name : String
  next_retry : @transport.Instant
  deadline : @transport.Instant
}

///|
pub struct Resolver {
  mode : Mode
  retry_interval : @transport.Duration
  query_timeout : @transport.Duration
  mut next_query_id : UInt64
  pending : Map[QueryId, PendingQuery]
  cache : Map[String, Resolution]
  registrations : Map[String, Array[@transport.IpAddress]]
  outputs : @queue.Queue[OutboundQuery]
  events : @queue.Queue[MdnsEvent]
}

///|
fn duration_milliseconds(value : Int64) -> @transport.Duration raise MdnsError {
  @transport.Duration::milliseconds(value) catch {
    error => raise Time(error)
  }
}

///|
fn instant_add(
  instant : @transport.Instant,
  duration : @transport.Duration,
) -> @transport.Instant raise MdnsError {
  instant.checked_add(duration) catch {
    error => raise Time(error)
  }
}

///|
fn mdns_destination() -> @transport.SocketAddress {
  @transport.SocketAddress::new(
    address=@transport.IpAddress::v4(224, 0, 0, 251),
    port=5353,
  )
}

///|
pub fn Resolver::new(
  mode? : Mode = QueryOnly,
  retry_interval? : @transport.Duration,
  query_timeout? : @transport.Duration,
) -> Resolver raise MdnsError {
  let retry_interval = match retry_interval {
    Some(value) => value
    None => duration_milliseconds(1000L)
  }
  let query_timeout = match query_timeout {
    Some(value) => value
    None => duration_milliseconds(5000L)
  }
  if retry_interval.as_milliseconds() <= 0 ||
    query_timeout.as_milliseconds() <= 0 {
    raise InvalidPacket("mDNS retry interval and timeout must be positive")
  }
  {
    mode,
    retry_interval,
    query_timeout,
    next_query_id: 1UL,
    pending: Map([]),
    cache: Map([]),
    registrations: Map([]),
    outputs: Queue([]),
    events: Queue([]),
  }
}

///|
pub fn Resolver::mode(self : Resolver) -> Mode {
  self.mode
}

///|
pub fn Resolver::register(
  self : Resolver,
  name : String,
  addresses : Array[@transport.IpAddress],
) -> Unit raise MdnsError {
  if self.mode != QueryAndGather {
    raise UnsupportedMode
  }
  let name = normalize_name(name)
  let unique : Array[@transport.IpAddress] = []
  for address in addresses {
    if !unique.contains(address) {
      unique.push(address)
    }
  }
  if unique.is_empty() {
    raise InvalidPacket("mDNS registration requires at least one address")
  }
  match self.registrations.get(name) {
    Some(existing) if existing != unique => raise NameConflict(name)
    Some(_) => ()
    None => self.registrations[name] = unique
  }
}

///|
pub fn Resolver::unregister(
  self : Resolver,
  name : String,
) -> Unit raise MdnsError {
  self.registrations.remove(normalize_name(name))
}

///|
pub fn Resolver::registered(
  self : Resolver,
  name : String,
) -> Array[@transport.IpAddress]? raise MdnsError {
  match self.registrations.get(normalize_name(name)) {
    Some(addresses) => Some(addresses.copy())
    None => None
  }
}

///|
pub fn Resolver::answer_query(
  self : Resolver,
  payload : Bytes,
  ttl_seconds? : UInt = 120U,
) -> Bytes? raise MdnsError {
  if self.mode != QueryAndGather {
    raise UnsupportedMode
  }
  if ttl_seconds == 0U {
    raise InvalidPacket("mDNS response TTL must be nonzero")
  }
  encode_registered_response(payload, self.registrations, ttl_seconds)
}

///|
fn Resolver::enqueue_query(
  self : Resolver,
  pending : PendingQuery,
) -> Unit raise MdnsError {
  self.outputs.push({
    query_id: pending.query_id,
    destination: mdns_destination(),
    payload: encode_query(pending.name),
  })
}

///|
pub fn Resolver::query(
  self : Resolver,
  name : String,
  now : @transport.Instant,
) -> QueryId raise MdnsError {
  let name = normalize_name(name)
  let query_id = QueryId(self.next_query_id)
  self.next_query_id += 1
  match self.cache.get(name) {
    Some(resolution) if resolution.expires_at > now => {
      self.events.push(Resolved(query_id, resolution))
      return query_id
    }
    Some(_) => self.cache.remove(name)
    None => ()
  }
  let pending = {
    query_id,
    name,
    next_retry: instant_add(now, self.retry_interval),
    deadline: instant_add(now, self.query_timeout),
  }
  self.pending[query_id] = pending
  self.enqueue_query(pending)
  query_id
}

///|
pub fn Resolver::is_pending(self : Resolver, query_id : QueryId) -> Bool {
  self.pending.contains(query_id)
}

///|
pub fn Resolver::pending_count(self : Resolver) -> Int {
  self.pending.length()
}

///|
pub fn Resolver::cancel(self : Resolver, query_id : QueryId) -> Unit {
  if self.pending.contains(query_id) {
    self.pending.remove(query_id)
    self.events.push(Cancelled(query_id))
  }
}

///|
pub fn Resolver::poll_output(self : Resolver) -> OutboundQuery? {
  self.outputs.pop()
}

///|
pub fn Resolver::poll_event(self : Resolver) -> MdnsEvent? {
  self.events.pop()
}

///|
pub fn Resolver::poll_timeout(self : Resolver) -> @transport.Instant? {
  let mut result : @transport.Instant? = None
  for pending in self.pending.values() {
    let deadline = if pending.next_retry < pending.deadline {
      pending.next_retry
    } else {
      pending.deadline
    }
    match result {
      None => result = Some(deadline)
      Some(current) => if deadline < current { result = Some(deadline) }
    }
  }
  result
}

///|
pub fn Resolver::handle_timeout(
  self : Resolver,
  now : @transport.Instant,
) -> Unit raise MdnsError {
  let timed_out : Array[QueryId] = []
  let retries : Array[QueryId] = []
  self.pending.each((query_id, pending) => {
    if pending.deadline <= now {
      timed_out.push(query_id)
    } else if pending.next_retry <= now {
      retries.push(query_id)
    }
  })
  for query_id in timed_out {
    self.pending.remove(query_id)
    self.events.push(TimedOut(query_id))
  }
  for query_id in retries {
    match self.pending.get(query_id) {
      Some(pending) => {
        let updated = {
          query_id: pending.query_id,
          name: pending.name,
          next_retry: instant_add(now, self.retry_interval),
          deadline: pending.deadline,
        }
        self.pending[query_id] = updated
        self.enqueue_query(updated)
      }
      None => ()
    }
  }
}

///|
fn ttl_duration(ttl_seconds : UInt) -> @transport.Duration raise MdnsError {
  duration_milliseconds(ttl_seconds.to_int64() * 1000L)
}

///|
pub fn Resolver::handle_response(
  self : Resolver,
  now : @transport.Instant,
  payload : Bytes,
) -> Unit raise MdnsError {
  let answers = parse_response(payload)
  for answer in answers {
    match self.registrations.get(answer.name) {
      Some(addresses) if !addresses.contains(answer.address) =>
        raise NameConflict(answer.name)
      _ => ()
    }
  }
  let completed : Array[QueryId] = []
  self.pending.each((query_id, pending) => {
    let addresses : Array[@transport.IpAddress] = []
    let mut minimum_ttl = 0xffffffffU
    for answer in answers {
      if answer.name == pending.name {
        if !addresses.contains(answer.address) {
          addresses.push(answer.address)
        }
        if answer.ttl_seconds < minimum_ttl {
          minimum_ttl = answer.ttl_seconds
        }
      }
    }
    if !addresses.is_empty() {
      let resolution = {
        name: pending.name,
        addresses,
        expires_at: instant_add(now, ttl_duration(minimum_ttl)),
      }
      self.cache[pending.name] = resolution
      self.events.push(Resolved(query_id, resolution))
      completed.push(query_id)
    }
  })
  for query_id in completed {
    self.pending.remove(query_id)
  }
}

///|
pub fn Resolver::cached(
  self : Resolver,
  name : String,
  now : @transport.Instant,
) -> Resolution? raise MdnsError {
  let name = normalize_name(name)
  match self.cache.get(name) {
    Some(resolution) if resolution.expires_at > now => Some(resolution)
    Some(_) => {
      self.cache.remove(name)
      None
    }
    None => None
  }
}
