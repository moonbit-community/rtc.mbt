///|
test "host UDP candidates parse and marshal with standard priority" {
  let wire = "candidate:1 1 UDP 2130706431 192.0.2.1 5000 typ host generation 0"
  let candidate = IceCandidate::parse(wire)
  assert_eq(candidate.foundation(), "1")
  assert_eq(candidate.component(), 1)
  assert_eq(candidate.protocol(), Udp)
  assert_eq(candidate.priority(), 2130706431U)
  assert_eq(
    candidate.address(),
    IpAddress(@transport.IpAddress::parse("192.0.2.1")),
  )
  assert_eq(candidate.port(), 5000)
  assert_eq(candidate.candidate_type(), Host)
  assert_eq(candidate.extensions(), [("generation", "0")])
  assert_eq(
    candidate.to_sdp_attribute(),
    "candidate:1 1 udp 2130706431 192.0.2.1 5000 typ host generation 0",
  )
  assert_eq(
    IceCandidate::priority_value(
      candidate_type=Host,
      local_preference=65535,
      component=1,
    ),
    2130706431U,
  )
}

///|
test "reflexive, mDNS, IPv6, and TCP candidate forms retain typed fields" {
  let reflexive = IceCandidate::parse(
    "2 1 udp 1694498815 203.0.113.1 62000 typ srflx raddr 0.0.0.0 rport 0 generation 0",
  )
  assert_eq(reflexive.candidate_type(), ServerReflexive)
  assert_eq(
    reflexive.related_address(),
    Some(IpAddress(@transport.IpAddress::parse("0.0.0.0"))),
  )
  assert_eq(reflexive.related_port(), Some(0))
  let mdns = IceCandidate::parse(
    "3 1 udp 2130706431 A1B2C3D4.local 5001 typ host",
  )
  assert_eq(mdns.address(), MdnsName("a1b2c3d4.local"))
  let ipv6 = IceCandidate::parse("4 1 udp 2130706431 2001:db8::1 5002 typ host")
  assert_eq(
    ipv6.address(),
    IpAddress(@transport.IpAddress::parse("2001:db8::1")),
  )
  let tcp = IceCandidate::parse(
    "5 1 tcp 1518280447 192.0.2.2 0 typ host tcptype active",
  )
  assert_eq(tcp.protocol(), Tcp)
  assert_eq(tcp.tcp_type(), Some(Active))
}

///|
test "candidate constructor and parser reject inconsistent forms" {
  for
    invalid in [
      "1 1 udp 1 not-an-address 5000 typ host", "1 1 udp 1 192.0.2.1 5000 typ host tcptype active",
      "1 1 tcp 1 192.0.2.1 5000 typ host", "1 1 udp 1 192.0.2.1 5000 typ srflx raddr 192.0.2.2",
      "1 1 udp 1 192.0.2.1 5000 typ host orphan",
    ] {
    try IceCandidate::parse(invalid) catch {
      InvalidCandidate(_) => ()
      _ => fail("unexpected ICE error")
    } noraise {
      _ => fail("invalid ICE candidate was accepted")
    }
  }
}

///|
test "host candidate convenience constructor uses its socket endpoint" {
  let endpoint = @transport.SocketAddress::new(
    address=@transport.IpAddress::parse("10.0.0.7"),
    port=49152,
  )
  let candidate = IceCandidate::host(foundation="host-v4", endpoint)
  assert_eq(candidate.address(), IpAddress(endpoint.address()))
  assert_eq(candidate.port(), endpoint.port())
  assert_eq(candidate.priority(), 2130706431U)
  assert_eq(candidate.candidate_type(), Host)
}
