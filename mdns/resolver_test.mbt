///|
fn mdns_response() -> Bytes {
  b"\x00\x00\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00" +
  b"\x04host\x05local\x00\x00\x01\x00\x01" +
  b"\xc0\x0c\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\x00\x02\x01" +
  b"\xc0\x0c\x00\x1c\x80\x01\x00\x00\x00\x78\x00\x10" +
  b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
}

///|
test "QueryOnly resolver emits A and AAAA questions to the mDNS multicast endpoint" {
  let resolver = @mdns.Resolver::new()
  let now = @transport.Instant::from_milliseconds(0)
  let query_id = resolver.query("HOST.local.", now)
  assert_eq(query_id, QueryId(1UL))
  guard resolver.poll_output() is Some(output) else {
    fail("missing outbound mDNS query")
  }
  assert_eq(output.query_id(), query_id)
  assert_eq(
    output.destination(),
    @transport.SocketAddress::new(
      address=@transport.IpAddress::v4(224, 0, 0, 251),
      port=5353,
    ),
  )
  assert_eq(
    output.payload(),
    b"\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00" +
    b"\x04host\x05local\x00\x00\x01\x80\x01" +
    b"\x04host\x05local\x00\x00\x1c\x80\x01",
  )
  assert_eq(
    resolver.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(1000)),
  )
}

///|
test "mDNS responses resolve IPv4 and IPv6 and populate the TTL cache" {
  let resolver = @mdns.Resolver::new()
  let query_id = resolver.query(
    "host.local",
    @transport.Instant::from_milliseconds(0),
  )
  ignore(resolver.poll_output())
  resolver.handle_response(
    @transport.Instant::from_milliseconds(1500),
    mdns_response(),
  )
  guard resolver.poll_event() is Some(Resolved(event_id, resolution)) else {
    fail("missing mDNS resolution event")
  }
  assert_eq(event_id, query_id)
  assert_eq(resolution.name(), "host.local")
  assert_eq(resolution.addresses(), [
    @transport.IpAddress::parse("192.0.2.1"),
    @transport.IpAddress::parse("2001:db8::1"),
  ])
  assert_eq(
    resolution.expires_at(),
    @transport.Instant::from_milliseconds(121500),
  )
  assert_false(resolver.is_pending(query_id))
  let cached_id = resolver.query(
    "HOST.LOCAL",
    @transport.Instant::from_milliseconds(2000),
  )
  assert_eq(resolver.poll_output(), None)
  guard resolver.poll_event() is Some(Resolved(event_id, cached)) else {
    fail("cached query did not resolve synchronously")
  }
  assert_eq(event_id, cached_id)
  assert_eq(cached, resolution)
  ignore(
    resolver.query("host.local", @transport.Instant::from_milliseconds(121500)),
  )
  assert_true(resolver.poll_output() is Some(_))
}

///|
test "mDNS retry and timeout scheduling is deterministic" {
  let resolver = @mdns.Resolver::new(
    retry_interval=@transport.Duration::milliseconds(1000L),
    query_timeout=@transport.Duration::milliseconds(2500L),
  )
  let query_id = resolver.query(
    "missing.local",
    @transport.Instant::from_milliseconds(0),
  )
  ignore(resolver.poll_output())
  resolver.handle_timeout(@transport.Instant::from_milliseconds(999))
  assert_eq(resolver.poll_output(), None)
  resolver.handle_timeout(@transport.Instant::from_milliseconds(1000))
  guard resolver.poll_output() is Some(retry) else { fail("missing retry") }
  assert_eq(retry.query_id(), query_id)
  assert_eq(
    resolver.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(2000)),
  )
  resolver.handle_timeout(@transport.Instant::from_milliseconds(2500))
  guard resolver.poll_event() is Some(TimedOut(event_id)) else {
    fail("missing timeout event")
  }
  assert_eq(event_id, query_id)
  assert_false(resolver.is_pending(query_id))
}

///|
test "mDNS parser rejects forward compression pointers and invalid names" {
  let resolver = @mdns.Resolver::new()
  ignore(
    resolver.query("valid.local", @transport.Instant::from_milliseconds(0)),
  )
  let malformed = b"\x00\x00\x84\x00\x00\x01\x00\x00\x00\x00\x00\x00" +
    b"\xc0\x0c\x00\x01\x00\x01"
  let response_time = @transport.Instant::from_milliseconds(1)
  try resolver.handle_response(response_time, malformed) catch {
    InvalidPacket(_) => ()
    _ => fail("unexpected mDNS error")
  } noraise {
    _ => fail("forward compression pointer was accepted")
  }
  let query_time = @transport.Instant::from_milliseconds(2)
  try resolver.query("not a name.local", query_time) catch {
    InvalidName(_) => ()
    _ => fail("unexpected mDNS error")
  } noraise {
    _ => fail("invalid mDNS name was accepted")
  }
}

///|
test "QueryAndGather registers names, answers queries, and detects conflicts" {
  let address_v4 = @transport.IpAddress::parse("192.0.2.40")
  let address_v6 = @transport.IpAddress::parse("2001:db8::40")
  let responder = @mdns.Resolver::new(mode=QueryAndGather)
  responder.register("Peer-40.local.", [address_v4, address_v6])
  assert_eq(
    responder.registered("peer-40.local"),
    Some([address_v4, address_v6]),
  )
  let querier = @mdns.Resolver::new()
  let query_id = querier.query(
    "peer-40.local",
    @transport.Instant::from_milliseconds(0),
  )
  guard querier.poll_output() is Some(query) else {
    fail("missing mDNS query for registered name")
  }
  guard responder.answer_query(query.payload()) is Some(response) else {
    fail("registered mDNS name did not produce an answer")
  }
  querier.handle_response(@transport.Instant::from_milliseconds(5), response)
  guard querier.poll_event() is Some(Resolved(event_id, resolution)) else {
    fail("generated mDNS response did not resolve")
  }
  assert_eq(event_id, query_id)
  assert_eq(resolution.addresses(), [address_v4, address_v6])

  let conflicting = @mdns.Resolver::new(mode=QueryAndGather)
  conflicting.register("peer-40.local", [
    @transport.IpAddress::parse("198.51.100.40"),
  ])
  guard conflicting.answer_query(query.payload()) is Some(conflict_response) else {
    fail("conflicting registration did not answer")
  }
  let conflict_time = @transport.Instant::from_milliseconds(6)
  let conflict : Result[Unit, @mdns.MdnsError] = try {
    responder.handle_response(conflict_time, conflict_response)
    Ok(())
  } catch {
    error => Err(error)
  }
  assert_eq(conflict, Err(NameConflict("peer-40.local")))
  responder.unregister("peer-40.local")
  assert_eq(responder.registered("peer-40.local"), None)
}

///|
test "QueryOnly resolver rejects local registration and response generation" {
  let resolver = @mdns.Resolver::new()
  let address = @transport.IpAddress::parse("192.0.2.1")
  let registration : Result[Unit, @mdns.MdnsError] = try {
    resolver.register("private.local", [address])
    Ok(())
  } catch {
    error => Err(error)
  }
  assert_eq(registration, Err(UnsupportedMode))
}
