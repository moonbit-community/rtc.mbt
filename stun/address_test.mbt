///|
test "RFC 5769 XOR-MAPPED-ADDRESS decodes to the documented IPv4 endpoint" {
  let message = Message::decode(rfc5769_ipv4_response())
  let attribute = message.first_attribute(XorMappedAddress)
  guard attribute is Some(attribute) else { fail("missing XOR-MAPPED-ADDRESS") }
  assert_eq(
    attribute.to_xor_address(message.transaction_id()),
    @transport.SocketAddress::new(
      address=@transport.IpAddress::v4(192, 0, 2, 1),
      port=32853,
    ),
  )
}

///|
test "plain and XOR addresses round-trip IPv4 and IPv6" {
  let transaction_id = TransactionId::from_bytes(b"0123456789ab")
  let ipv4 = @transport.SocketAddress::new(
    address=@transport.IpAddress::v4(203, 0, 113, 7),
    port=3478,
  )
  let ipv6 = @transport.SocketAddress::new(
    address=@transport.IpAddress::v6(
      b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x42",
    ),
    port=65535,
  )
  for address in [ipv4, ipv6] {
    let plain = Attribute::from_address(address)
    assert_eq(plain.to_address(), address)
    let xor = Attribute::from_xor_address(address, transaction_id)
    assert_eq(xor.to_xor_address(transaction_id), address)
    let message = Message::new(
      class=SuccessResponse,
      stun_method=Binding,
      transaction_id~,
      attributes=[plain, xor],
    )
    let decoded = Message::decode(message.encode())
    assert_eq(decoded.attributes()[0].to_address(), address)
    assert_eq(decoded.attributes()[1].to_xor_address(transaction_id), address)
  }
}

///|
test "address attributes reject inconsistent families and wrong attribute types" {
  let malformed = Attribute::new(
    attribute_type=MappedAddress,
    value=b"\x00\x02\x00\x50\xc0\x00\x02\x01",
  )
  try malformed.to_address() catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("IPv6 family with IPv4 length was accepted")
  }
  let address = @transport.SocketAddress::new(
    address=@transport.IpAddress::loopback_v4(),
    port=3478,
  )
  try Attribute::from_address(address, attribute_type=MessageIntegrity) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("non-address attribute type was accepted")
  }
}
