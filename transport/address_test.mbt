///|
test "IPv4 is encoded in network byte order" {
  let address = @transport.IpAddress::v4(192, 0, 2, 1)
  inspect(address.to_bytes(), content="b\"\\xc0\\x00\\x02\\x01\"")
}

///|
test "IPv6 requires exactly sixteen bytes" {
  try @transport.IpAddress::v6(b"\x00\x01") catch {
    InvalidIpv6Length(length) => inspect(length, content="2")
    InvalidAddress(_) => fail("unexpected address error")
  } noraise {
    _ => fail("expected an invalid length error")
  }
}

///|
test "IP text parsing and RFC 5952 formatting round-trip" {
  let cases = [
    ("0.0.0.0", "0.0.0.0"),
    ("192.0.2.1", "192.0.2.1"),
    ("::", "::"),
    ("::1", "::1"),
    ("2001:0db8:0000:0000:0001:0000:0000:0001", "2001:db8::1:0:0:1"),
    ("2001:db8::192.0.2.1", "2001:db8::c000:201"),
    ("fe80::dc2b:44ff:fe20:6009", "fe80::dc2b:44ff:fe20:6009"),
  ]
  for item in cases {
    let (input, canonical) = item
    let parsed = @transport.IpAddress::parse(input)
    assert_eq(parsed.to_string(), canonical)
    assert_eq(@transport.IpAddress::parse(canonical), parsed)
  }
}

///|
test "IP parser rejects overflow, repeated compression, and bad hextet counts" {
  for
    invalid in [
      "256.0.0.1", "1.2.3", "2001::db8::1", "2001:db8:1", "1:2:3:4:5:6:7:8::", "gggg::1",
    ] {
    try @transport.IpAddress::parse(invalid) catch {
      InvalidAddress(_) => ()
      InvalidIpv6Length(_) => fail("unexpected address error")
    } noraise {
      _ => fail("invalid IP address was accepted")
    }
  }
}

///|
test "socket address formatting brackets IPv6" {
  assert_eq(
    @transport.SocketAddress::new(
      address=@transport.IpAddress::parse("2001:db8::1"),
      port=3478,
    ).to_string(),
    "[2001:db8::1]:3478",
  )
}
