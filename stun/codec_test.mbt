///|
fn rfc5769_request() -> Bytes {
  b"\x00\x01\x00\x58\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
  b"\x80\x22\x00\x10\x53\x54\x55\x4e\x20\x74\x65\x73\x74\x20\x63\x6c\x69\x65\x6e\x74" +
  b"\x00\x24\x00\x04\x6e\x00\x01\xff" +
  b"\x80\x29\x00\x08\x93\x2f\xf9\xb1\x51\x26\x3b\x36" +
  b"\x00\x06\x00\x09\x65\x76\x74\x6a\x3a\x68\x36\x76\x59\x20\x20\x20" +
  b"\x00\x08\x00\x14\x9a\xea\xa7\x0c\xbf\xd8\xcb\x56\x78\x1e\xf2\xb5\xb2\xd3\xf2\x49\xc1\xb5\x71\xa2" +
  b"\x80\x28\x00\x04\xe5\x7a\x3b\xcf"
}

///|
fn rfc5769_ipv4_response() -> Bytes {
  b"\x01\x01\x00\x3c\x21\x12\xa4\x42\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae" +
  b"\x80\x22\x00\x0b\x74\x65\x73\x74\x20\x76\x65\x63\x74\x6f\x72\x20" +
  b"\x00\x20\x00\x08\x00\x01\xa1\x47\xe1\x12\xa6\x43" +
  b"\x00\x08\x00\x14\x2b\x91\xf5\x99\xfd\x9e\x90\xc3\x8c\x74\x89\xf9\x2a\xf9\xba\x53\xf0\x6b\xe7\xd7" +
  b"\x80\x28\x00\x04\xc0\x7d\x4c\x96"
}

///|
test "RFC 5769 request decodes, authenticates, and round-trips exactly" {
  let wire = rfc5769_request()
  assert_true(Message::is_stun(wire))
  let message = Message::decode(wire)
  assert_eq(message.class(), Request)
  assert_eq(message.stun_method(), Binding)
  assert_eq(
    message.transaction_id().as_bytes(),
    b"\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae",
  )
  let attributes = message.attributes()
  assert_eq(attributes.length(), 6)
  assert_eq(attributes[0].attribute_type(), Software)
  assert_eq(attributes[0].as_text(), "STUN test client")
  assert_eq(attributes[1].attribute_type(), Priority)
  assert_eq(attributes[1].as_u32(), 0x6e0001ffU)
  assert_eq(attributes[2].attribute_type(), IceControlled)
  assert_eq(attributes[2].as_u64(), 0x932ff9b151263b36UL)
  assert_eq(attributes[3].attribute_type(), Username)
  assert_eq(attributes[3].as_text(), "evtj:h6vY")
  message.verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt")
  message.verify_fingerprint()
  assert_eq(message.encode(), wire)
  assert_eq(message.encode_authenticated(b"VOkJxbRl1RmTxUk/WvJxBt"), wire)
}

///|
test "RFC 5769 IPv4 response authenticates and preserves nonzero padding" {
  let wire = rfc5769_ipv4_response()
  let message = Message::decode(wire)
  assert_eq(message.class(), SuccessResponse)
  assert_eq(message.stun_method(), Binding)
  assert_eq(message.attributes()[0].as_text(), "test vector")
  message.verify_integrity(b"VOkJxbRl1RmTxUk/WvJxBt")
  message.verify_fingerprint()
  assert_eq(message.encode(), wire)
  assert_eq(message.encode_authenticated(b"VOkJxbRl1RmTxUk/WvJxBt"), wire)
}

///|
test "SHA-256 integrity and fingerprint reject modified input" {
  let message = Message::new(
    class=Request,
    stun_method=Binding,
    transaction_id=TransactionId::from_bytes(b"0123456789ab"),
    attributes=[
      Attribute::username("remote:local"),
      Attribute::priority(0x6e0001ffU),
      Attribute::use_candidate(),
    ],
  )
  let wire = message.encode_authenticated(
    b"a short-term credential",
    sha256=true,
  )
  let decoded = Message::decode(wire)
  decoded.verify_integrity(b"a short-term credential", sha256=true)
  decoded.verify_fingerprint()
  try decoded.verify_integrity(b"wrong credential", sha256=true) catch {
    IntegrityFailure => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("wrong credential was accepted")
  }
  let corrupted = wire.to_array()
  corrupted[corrupted.length() - 1] = corrupted[corrupted.length() - 1] ^ 1
  let corrupted = Message::decode(Bytes::from_array(corrupted))
  try corrupted.verify_fingerprint() catch {
    IntegrityFailure => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("corrupt fingerprint was accepted")
  }
}

///|
test "unknown attributes and arbitrary padding survive decoding" {
  let wire = b"\x00\x01\x00\x08\x21\x12\xa4\x42\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x61\x62" +
    b"\x80\x3f\x00\x01\xaa\x01\x02\x03"
  let message = Message::decode(wire)
  assert_eq(message.attributes().length(), 1)
  assert_eq(message.attributes()[0].attribute_type(), UnknownAttribute(0x803f))
  assert_eq(message.encode(), wire)
  let required = Message::new(
    class=Request,
    stun_method=Binding,
    transaction_id=TransactionId::from_bytes(b"0123456789ab"),
    attributes=[
      Attribute::new(attribute_type=UnknownAttribute(0x1234), value=b"abc"),
    ],
  )
  assert_eq(Message::decode(required.encode()).unknown_required_attributes(), [
    0x1234,
  ])
}

///|
test "message type coding covers classes and unknown methods" {
  let transaction_id = TransactionId::from_bytes(b"0123456789ab")
  let cases : Array[(MessageClass, Method)] = [
    (Request, Binding),
    (Indication, Send),
    (SuccessResponse, Allocate),
    (ErrorResponse, Unknown(0xabc)),
  ]
  for item in cases {
    let (class, stun_method) = item
    let original = Message::new(class~, stun_method~, transaction_id~)
    assert_eq(Message::decode(original.encode()), original)
  }
}

///|
test "strict framing rejects truncated, mismatched, and non-STUN packets" {
  assert_false(Message::is_stun(b"not a STUN packet"))
  let truncated = rfc5769_request()[0:19].to_owned()
  try Message::decode(truncated) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("truncated packet was accepted")
  }
  let mismatched = rfc5769_request().to_array()
  mismatched[3] = 0x54
  try Message::decode(Bytes::from_array(mismatched)) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("mismatched body length was accepted")
  }
  let high_bits = rfc5769_request().to_array()
  high_bits[0] = high_bits[0] | 0xc0
  assert_false(Message::is_stun(Bytes::from_array(high_bits)))
  try Message::decode(Bytes::from_array(high_bits)) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("invalid message type was accepted")
  }
}
