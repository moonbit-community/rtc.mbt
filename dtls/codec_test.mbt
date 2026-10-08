///|
test "DTLS records preserve single and coalesced datagram framing" {
  let first = b"\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x12\x00\x01\x01"
  let second = b"\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x13\x00\x01\x01"
  let records = @dtls.decode_records(first + second)
  assert_eq(records.length(), 2)
  assert_eq(records[0].header().content_type(), ChangeCipherSpec)
  assert_eq(records[0].header().version(), Dtls10)
  assert_eq(records[0].header().epoch(), 0)
  assert_eq(records[0].header().sequence_number(), 18UL)
  assert_eq(records[0].payload(), b"\x01")
  assert_eq(records[1].header().sequence_number(), 19UL)
  assert_eq(@dtls.encode_records(records), first + second)
}

///|
test "DTLS record decoder rejects truncation, unsupported versions, and overflow" {
  for
    invalid in [
      b"\x14\xfe", b"\x14\xfe\xff\x00\x00\x00\x00\x00\x00\x00\x12\x00\xff\x01", b"\x14\x03\x03\x00\x00\x00\x00\x00\x00\x00\x12\x00\x01\x01",
    ] {
    try @dtls.decode_records(invalid) catch {
      InvalidRecord(_) | UnsupportedVersion => ()
      _ => fail("unexpected DTLS record error")
    } noraise {
      _ => fail("invalid DTLS record was accepted")
    }
  }
  try
    @dtls.Record::new(
      content_type=ApplicationData,
      epoch=1,
      sequence_number=0x0001000000000000UL,
      payload=b"x",
    )
  catch {
    InvalidRecord(_) => ()
    _ => fail("unexpected DTLS sequence-number error")
  } noraise {
    _ => fail("an overflowing DTLS sequence number was accepted")
  }
}

///|
test "DTLS handshake fragment headers round-trip and retain unknown types" {
  let complete = @dtls.HandshakeFragment::new(
    handshake_type=ClientHello,
    total_length=3,
    message_sequence=7,
    fragment_offset=0,
    body=b"abc",
  )
  assert_eq(
    complete.encode(),
    b"\x01\x00\x00\x03\x00\x07\x00\x00\x00\x00\x00\x03abc",
  )
  let fragments = @dtls.decode_handshakes(
    complete.encode() + b"\xfa\x00\x00\x04\x00\x08\x00\x00\x01\x00\x00\x02xy",
  )
  assert_eq(fragments.length(), 2)
  assert_true(fragments[0].is_complete())
  assert_eq(fragments[1].handshake_type(), UnknownHandshake(0xfa))
  assert_eq(fragments[1].total_length(), 4)
  assert_eq(fragments[1].fragment_offset(), 1)
  assert_eq(fragments[1].body(), b"xy")
}

///|
test "DTLS handshake decoder validates fragment bounds and exact framing" {
  for
    invalid in [
      b"\x01\x00\x00\x01", b"\x01\x00\x00\x02\x00\x00\x00\x00\x02\x00\x00\x01x",
      b"\x01\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x04abcd",
    ] {
    try @dtls.decode_handshakes(invalid) catch {
      InvalidHandshake(_) => ()
      _ => fail("unexpected DTLS handshake error")
    } noraise {
      _ => fail("invalid DTLS handshake fragment was accepted")
    }
  }
}
