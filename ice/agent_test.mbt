///|
fn test_endpoint(last_octet : Byte, port : UInt16) -> @transport.SocketAddress {
  @transport.SocketAddress::new(
    address=@transport.IpAddress::v4(192, 0, 2, last_octet),
    port~,
  )
}

///|
fn test_credentials(
  username_fragment : String,
  password : String,
) -> @ice.IceCredentials raise @ice.IceError {
  @ice.IceCredentials::new(username_fragment~, password~)
}

///|
fn test_agent(
  local_credentials : @ice.IceCredentials,
  remote_credentials : @ice.IceCredentials,
  local_address : @transport.SocketAddress,
  remote_address : @transport.SocketAddress,
  role : @ice.IceRole,
  tie_breaker : UInt64,
) -> @ice.IceAgent raise @ice.IceError {
  let agent = @ice.IceAgent::new(local_credentials~, role~, tie_breaker~)
  agent.add_local_candidate(
    @ice.IceCandidate::host(foundation="local", local_address),
  )
  agent.add_remote_candidate(
    @ice.IceCandidate::host(foundation="remote", remote_address),
  )
  agent.set_remote_credentials(remote_credentials)
  agent
}

///|
fn as_inbound(
  outbound : @transport.OutboundDatagram,
  now : @transport.Instant,
) -> @transport.InboundDatagram {
  {
    now,
    context: {
      local_address: outbound.context.peer,
      peer: outbound.context.local_address,
      ecn: outbound.context.ecn,
      protocol: outbound.context.protocol,
    },
    payload: outbound.payload,
  }
}

///|
fn application_event(agent : @ice.IceAgent) -> Bytes? {
  let mut received : Bytes? = None
  for index = 0; index < 8; index = index + 1 {
    match agent.poll_event() {
      Some(ApplicationDatagram(datagram)) => received = Some(datagram.payload)
      Some(_) => ()
      None => ()
    }
  }
  received
}

///|
test "STUN binding gathering produces a server-reflexive candidate" {
  let local_address = test_endpoint(5, 4500)
  let server = test_endpoint(6, 3478)
  let mapped = @transport.SocketAddress::new(
    address=@transport.IpAddress::parse("198.51.100.25"),
    port=62000,
  )
  let gatherer = @ice.SrflxGatherer::new(
    local_candidate=@ice.IceCandidate::host(foundation="host", local_address),
    server~,
  )
  let now = @transport.Instant::from_milliseconds(0)
  gatherer.start(now)
  guard gatherer.poll_datagram() is Some(outbound) else {
    fail("srflx gatherer did not emit a STUN binding request")
  }
  let request = @stun.Message::decode(outbound.payload)
  assert_eq(request.class(), Request)
  assert_eq(request.stun_method(), Binding)
  let response = @stun.Message::new(
    class=SuccessResponse,
    stun_method=Binding,
    transaction_id=request.transaction_id(),
    attributes=[
      @stun.Attribute::from_xor_address(mapped, request.transaction_id()),
    ],
  ).encode()
  gatherer.handle_datagram({
    now: @transport.Instant::from_milliseconds(1),
    context: outbound.context,
    payload: response,
  })
  guard gatherer.poll_event() is Some(SrflxStateChanged(SrflxGathering)) else {
    fail("missing srflx gathering state event")
  }
  guard gatherer.poll_event() is Some(ServerReflexiveCandidate(candidate)) else {
    fail("missing server-reflexive candidate")
  }
  assert_eq(candidate.candidate_type(), ServerReflexive)
  assert_eq(candidate.socket_address(), Some(mapped))
  assert_eq(
    candidate.related_address(),
    Some(IpAddress(local_address.address())),
  )
  assert_eq(candidate.related_port(), Some(local_address.port()))
  assert_eq(gatherer.state(), SrflxComplete)
  assert_eq(gatherer.poll_timeout(), None)
}

///|
test "host UDP agents nominate a pair and exchange application datagrams" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(10, 5000)
  let b_address = test_endpoint(20, 6000)
  let a_credentials = test_credentials("a123", "abcdefghijklmnopqrstuv")
  let b_credentials = test_credentials("b123", "zyxwvutsrqponmlkjihgfe")
  let a = test_agent(
    a_credentials,
    b_credentials,
    a_address,
    b_address,
    Controlling,
    100UL,
  )
  let b = test_agent(
    b_credentials,
    a_credentials,
    b_address,
    a_address,
    Controlled,
    200UL,
  )
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(a_check) else {
    fail("controlling agent did not emit a connectivity check")
  }
  guard b.poll_datagram() is Some(b_check) else {
    fail("controlled agent did not emit a connectivity check")
  }
  b.handle_datagram(as_inbound(a_check, now))
  a.handle_datagram(as_inbound(b_check, now))
  guard b.poll_datagram() is Some(b_response) else {
    fail("controlled agent did not answer the connectivity check")
  }
  guard a.poll_datagram() is Some(a_response) else {
    fail("controlling agent did not answer the connectivity check")
  }
  a.handle_datagram(as_inbound(b_response, now))
  b.handle_datagram(as_inbound(a_response, now))
  assert_eq(a.state(), Completed)
  assert_eq(b.state(), Completed)
  guard a.selected_pair() is Some(a_pair) else {
    fail("controlling agent did not select a candidate pair")
  }
  guard b.selected_pair() is Some(b_pair) else {
    fail("controlled agent did not select a candidate pair")
  }
  assert_true(a_pair.is_nominated())
  assert_true(b_pair.is_nominated())
  a.send(b"hello over ICE")
  guard a.poll_datagram() is Some(application) else {
    fail("selected ICE path did not emit application data")
  }
  b.handle_datagram(
    as_inbound(application, @transport.Instant::from_milliseconds(1)),
  )
  assert_eq(application_event(b), Some(b"hello over ICE"))
}

///|
test "controlling agent nominates an authenticated response-source prflx pair" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(30, 7000)
  let advertised_b_address = test_endpoint(31, 7100)
  let response_b_address = test_endpoint(32, 7100)
  let a_credentials = test_credentials("asrc", "abcdefghijklmnopqrstuv")
  let b_credentials = test_credentials("bsrc", "zyxwvutsrqponmlkjihgfe")
  let a = test_agent(
    a_credentials,
    b_credentials,
    a_address,
    advertised_b_address,
    Controlling,
    300UL,
  )
  let b = test_agent(
    b_credentials,
    a_credentials,
    advertised_b_address,
    a_address,
    Controlled,
    400UL,
  )
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(a_check) else {
    fail("controlling agent did not emit a connectivity check")
  }
  ignore(b.poll_datagram())
  b.handle_datagram(as_inbound(a_check, now))
  guard b.poll_datagram() is Some(b_response) else {
    fail("controlled agent did not answer the connectivity check")
  }
  a.handle_datagram({
    now,
    context: {
      local_address: a_address,
      peer: response_b_address,
      ecn: None,
      protocol: Udp,
    },
    payload: b_response.payload,
  })
  assert_eq(a.state(), Completed)
  guard a.selected_pair() is Some(pair) else {
    fail("response-source peer-reflexive pair was not selected")
  }
  assert_eq(pair.remote_candidate().candidate_type(), PeerReflexive)
  assert_eq(pair.remote_candidate().socket_address(), Some(response_b_address))
  a.send(b"response-source path")
  guard a.poll_datagram() is Some(application) else {
    fail("selected response-source path did not emit application data")
  }
  assert_eq(application.context.peer, response_b_address)
}

///|
test "trickled remote candidate starts a checklist after ICE has started" {
  let local_credentials = test_credentials("local1", "abcdefghijklmnopqrstuv")
  let remote_credentials = test_credentials("remote1", "zyxwvutsrqponmlkjihgfe")
  let agent = @ice.IceAgent::new(
    local_credentials~,
    role=Controlling,
    tie_breaker=42UL,
  )
  agent.add_local_candidate(
    @ice.IceCandidate::host(foundation="local", test_endpoint(21, 6100)),
  )
  agent.set_remote_credentials(remote_credentials)
  agent.start(@transport.Instant::from_milliseconds(0))
  assert_eq(agent.state(), Checking)
  assert_eq(agent.poll_datagram(), None)
  assert_eq(agent.poll_timeout(), None)
  let trickle_time = @transport.Instant::from_milliseconds(25)
  agent.add_remote_candidate(
    @ice.IceCandidate::host(foundation="remote", test_endpoint(22, 6200)),
    now=trickle_time,
  )
  assert_true(agent.poll_datagram() is Some(_))
  assert_eq(
    agent.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(525)),
  )
  assert_eq(agent.candidate_pairs().length(), 1)
}

///|
test "authenticated unknown check creates and nominates a prflx candidate" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(23, 6300)
  let b_address = test_endpoint(24, 6400)
  let a_credentials = test_credentials("aprflx", "abcdefghijklmnopqrstuv")
  let b_credentials = test_credentials("bprflx", "zyxwvutsrqponmlkjihgfe")
  let a = test_agent(
    a_credentials,
    b_credentials,
    a_address,
    b_address,
    Controlling,
    100UL,
  )
  let b = @ice.IceAgent::new(
    local_credentials=b_credentials,
    role=Controlled,
    tie_breaker=200UL,
  )
  b.add_local_candidate(@ice.IceCandidate::host(foundation="b", b_address))
  b.set_remote_credentials(a_credentials)
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(check) else {
    fail("controlling agent did not emit a connectivity check")
  }
  b.handle_datagram(as_inbound(check, now))
  guard b.poll_datagram() is Some(response) else {
    fail("controlled agent did not answer the peer-reflexive check")
  }
  a.handle_datagram(as_inbound(response, now))
  assert_eq(a.state(), Completed)
  assert_eq(b.state(), Completed)
  guard b.selected_pair() is Some(pair) else {
    fail("controlled agent did not nominate the peer-reflexive pair")
  }
  assert_eq(pair.remote_candidate().candidate_type(), PeerReflexive)
  assert_true(
    b
    .remote_candidates()
    .any(candidate => {
      candidate.candidate_type() == PeerReflexive &&
      candidate.socket_address() == Some(a_address)
    }),
  )
}

///|
test "role conflict is resolved by the tie breaker and nomination continues" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(30, 7000)
  let b_address = test_endpoint(40, 8000)
  let a_credentials = test_credentials("a456", "0123456789abcdefghijkl")
  let b_credentials = test_credentials("b456", "abcdefghijkl0123456789")
  let a = test_agent(
    a_credentials,
    b_credentials,
    a_address,
    b_address,
    Controlling,
    100UL,
  )
  let b = test_agent(
    b_credentials,
    a_credentials,
    b_address,
    a_address,
    Controlling,
    200UL,
  )
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(a_check) else {
    fail("first agent did not emit a connectivity check")
  }
  guard b.poll_datagram() is Some(b_check) else {
    fail("second agent did not emit a connectivity check")
  }
  b.handle_datagram(as_inbound(a_check, now))
  a.handle_datagram(as_inbound(b_check, now))
  assert_eq(a.role(), Controlled)
  assert_eq(b.role(), Controlling)
  guard b.poll_datagram() is Some(role_conflict) else {
    fail("higher tie breaker did not emit a role-conflict response")
  }
  guard a.poll_datagram() is Some(success) else {
    fail("lower tie breaker did not accept its controlled role")
  }
  a.handle_datagram(as_inbound(role_conflict, now))
  b.handle_datagram(as_inbound(success, now))
  assert_eq(a.state(), Completed)
  assert_eq(b.state(), Completed)
}

///|
test "connectivity checks use exact exponential retransmission deadlines" {
  let local_credentials = test_credentials("a789", "abcdefghijklmnopqrstuv")
  let remote_credentials = test_credentials("b789", "zyxwvutsrqponmlkjihgfe")
  let agent = test_agent(
    local_credentials,
    remote_credentials,
    test_endpoint(50, 9000),
    test_endpoint(60, 10000),
    Controlling,
    300UL,
  )
  agent.start(@transport.Instant::from_milliseconds(0))
  guard agent.poll_datagram() is Some(initial) else {
    fail("missing initial connectivity check")
  }
  assert_eq(
    agent.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(500)),
  )
  agent.handle_timeout(@transport.Instant::from_milliseconds(499))
  assert_eq(agent.poll_datagram(), None)
  agent.handle_timeout(@transport.Instant::from_milliseconds(500))
  guard agent.poll_datagram() is Some(first_retry) else {
    fail("missing first connectivity-check retry")
  }
  assert_eq(first_retry.payload, initial.payload)
  assert_eq(
    agent.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(1500)),
  )
  for index = 0; index < 7; index = index + 1 {
    guard agent.poll_timeout() is Some(deadline) else {
      fail("missing retransmission deadline")
    }
    agent.handle_timeout(deadline)
    ignore(agent.poll_datagram())
  }
  assert_eq(agent.state(), Failed)
  assert_eq(agent.poll_timeout(), None)
}

///|
test "selected ICE pairs keep alive, disconnect, recover, and fail on deadlines" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(61, 10100)
  let b_address = test_endpoint(62, 10200)
  let a_credentials = test_credentials("alivea", "abcdefghijklmnopqrstuv")
  let b_credentials = test_credentials("aliveb", "zyxwvutsrqponmlkjihgfe")
  let a = @ice.IceAgent::new(
    local_credentials=a_credentials,
    role=Controlling,
    tie_breaker=301UL,
    disconnected_timeout=@transport.Duration::milliseconds(10),
    failed_timeout=@transport.Duration::milliseconds(20),
    keepalive_interval=@transport.Duration::milliseconds(5),
  )
  a.add_local_candidate(
    @ice.IceCandidate::host(foundation="alive-a", a_address),
  )
  a.add_remote_candidate(
    @ice.IceCandidate::host(foundation="alive-b", b_address),
  )
  a.set_remote_credentials(b_credentials)
  let b = test_agent(
    b_credentials,
    a_credentials,
    b_address,
    a_address,
    Controlled,
    302UL,
  )
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(initial_check) else {
    fail("controlling agent omitted its initial check")
  }
  ignore(b.poll_datagram())
  b.handle_datagram(as_inbound(initial_check, now))
  guard b.poll_datagram() is Some(initial_response) else {
    fail("controlled agent omitted its initial response")
  }
  a.handle_datagram(as_inbound(initial_response, now))
  assert_eq(a.state(), Completed)
  assert_eq(a.poll_timeout(), Some(@transport.Instant::from_milliseconds(5)))

  a.handle_timeout(@transport.Instant::from_milliseconds(5))
  guard a.poll_datagram() is Some(keepalive) else {
    fail("selected ICE pair omitted its keepalive check")
  }
  b.handle_datagram(
    as_inbound(keepalive, @transport.Instant::from_milliseconds(5)),
  )
  guard b.poll_datagram() is Some(keepalive_response) else {
    fail("selected ICE pair omitted its keepalive response")
  }
  a.handle_datagram(
    as_inbound(keepalive_response, @transport.Instant::from_milliseconds(6)),
  )
  assert_eq(a.poll_timeout(), Some(@transport.Instant::from_milliseconds(11)))

  a.handle_timeout(@transport.Instant::from_milliseconds(16))
  assert_eq(a.state(), Disconnected)
  guard a.poll_datagram() is Some(recovery_check) else {
    fail("disconnected ICE pair stopped probing")
  }
  b.handle_datagram(
    as_inbound(recovery_check, @transport.Instant::from_milliseconds(17)),
  )
  guard b.poll_datagram() is Some(recovery_response) else {
    fail("disconnected ICE pair could not receive a recovery response")
  }
  a.handle_datagram(
    as_inbound(recovery_response, @transport.Instant::from_milliseconds(18)),
  )
  assert_eq(a.state(), Completed)

  a.handle_timeout(@transport.Instant::from_milliseconds(28))
  assert_eq(a.state(), Disconnected)
  ignore(a.poll_datagram())
  a.handle_timeout(@transport.Instant::from_milliseconds(47))
  assert_eq(a.state(), Disconnected)
  a.handle_timeout(@transport.Instant::from_milliseconds(48))
  assert_eq(a.state(), Failed)
  assert_eq(a.poll_timeout(), None)
}

///|
test "ICE TCP active/passive agents nominate one stream without retransmission" {
  let now = @transport.Instant::from_milliseconds(0)
  let client_ip = test_endpoint(90, 0)
  let client_connected = test_endpoint(90, 51000)
  let server_address = test_endpoint(91, 52000)
  let client_credentials = test_credentials(
    "tcpclient", "abcdefghijklmnopqrstuv",
  )
  let server_credentials = test_credentials(
    "tcpserver", "zyxwvutsrqponmlkjihgfe",
  )
  let client = @ice.IceAgent::new(
    local_credentials=client_credentials,
    role=Controlling,
    tie_breaker=600UL,
  )
  client.add_local_candidate(
    @ice.IceCandidate::tcp_host(
      foundation="tcp-active",
      client_ip,
      tcp_type=Active,
    ),
  )
  client.add_remote_candidate(
    @ice.IceCandidate::tcp_host(
      foundation="tcp-passive",
      server_address,
      tcp_type=Passive,
    ),
  )
  client.set_remote_credentials(server_credentials)
  let server = @ice.IceAgent::new(
    local_credentials=server_credentials,
    role=Controlled,
    tie_breaker=700UL,
  )
  server.add_local_candidate(
    @ice.IceCandidate::tcp_host(
      foundation="tcp-passive",
      server_address,
      tcp_type=Passive,
    ),
  )
  server.add_remote_candidate(
    @ice.IceCandidate::tcp_host(
      foundation="tcp-active",
      client_ip,
      tcp_type=Active,
    ),
  )
  server.set_remote_credentials(client_credentials)
  client.start(now)
  server.start(now)
  guard client.poll_datagram() is Some(check) else {
    fail("active ICE TCP candidate did not emit a connectivity check")
  }
  assert_eq(check.context.protocol, Tcp)
  assert_eq(
    client.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(39500)),
  )
  client.handle_timeout(@transport.Instant::from_milliseconds(500))
  assert_eq(client.poll_datagram(), None)
  let server_context : @transport.TransportContext = {
    local_address: server_address,
    peer: client_connected,
    ecn: None,
    protocol: Tcp,
  }
  server.handle_datagram({
    now,
    context: server_context,
    payload: check.payload,
  })
  guard server.poll_datagram() is Some(response) else {
    fail("passive ICE TCP candidate did not answer the check")
  }
  client.handle_datagram({
    now,
    context: check.context,
    payload: response.payload,
  })
  assert_eq(client.state(), Completed)
  assert_eq(server.state(), Completed)
  guard server.selected_pair() is Some(server_pair) else {
    fail("passive ICE TCP candidate did not select a pair")
  }
  assert_eq(server_pair.remote_candidate().candidate_type(), PeerReflexive)
  assert_eq(server_pair.remote_candidate().tcp_type(), Some(Active))
  client.send(b"tcp application")
  guard client.poll_datagram() is Some(application) else {
    fail("selected ICE TCP pair did not emit application data")
  }
  server.handle_datagram({
    now: @transport.Instant::from_milliseconds(1),
    context: server_context,
    payload: application.payload,
  })
  assert_eq(application_event(server), Some(b"tcp application"))
}

///|
test "invalid short-term credentials reject a connectivity check" {
  let now = @transport.Instant::from_milliseconds(0)
  let a_address = test_endpoint(70, 11000)
  let b_address = test_endpoint(80, 12000)
  let a_credentials = test_credentials("aabc", "abcdefghijklmnopqrstuv")
  let b_credentials = test_credentials("babc", "zyxwvutsrqponmlkjihgfe")
  let wrong_b_credentials = test_credentials("babc", "this-password-is-wrong!")
  let a = test_agent(
    a_credentials,
    wrong_b_credentials,
    a_address,
    b_address,
    Controlling,
    400UL,
  )
  let b = test_agent(
    b_credentials,
    a_credentials,
    b_address,
    a_address,
    Controlled,
    500UL,
  )
  a.start(now)
  b.start(now)
  guard a.poll_datagram() is Some(a_check) else {
    fail("missing connectivity check")
  }
  ignore(b.poll_datagram())
  try b.handle_datagram(as_inbound(a_check, now)) catch {
    Stun(IntegrityFailure) => ()
    _ => fail("unexpected ICE authentication error")
  } noraise {
    _ => fail("connectivity check with the wrong password was accepted")
  }
  assert_eq(b.poll_datagram(), None)
}
