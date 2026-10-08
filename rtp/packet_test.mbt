///|
test "RTP fixed header packet round-trips" {
  let wire = b"\x80\xe0\x12\x34\x01\x02\x03\x04\xaa\xbb\xcc\xddabc"
  let packet = @rtp.Packet::unmarshal(wire)
  assert_true(packet.marker())
  assert_eq(packet.payload_type(), 96)
  assert_eq(packet.sequence_number(), 0x1234)
  assert_eq(packet.timestamp(), 0x01020304U)
  assert_eq(packet.ssrc(), 0xaabbccddU)
  assert_eq(packet.payload(), b"abc")
  assert_eq(packet.marshal(), wire)
}

///|
test "RTP one-byte header extensions and CSRC values round-trip" {
  let wire = b"\x92\x61\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03" +
    b"\x00\x00\x00\x04\x00\x00\x00\x05" +
    b"\xbe\xde\x00\x02\x12\xaa\xbb\xcc\x30\xdd\x00\x00payload"
  let packet = @rtp.Packet::unmarshal(wire)
  assert_eq(packet.csrc(), [4U, 5U])
  assert_eq(packet.extensions(), [
    @rtp.HeaderExtension::new(id=1, payload=b"\xaa\xbb\xcc"),
    @rtp.HeaderExtension::new(id=3, payload=b"\xdd"),
  ])
  assert_eq(packet.marshal(), wire)
}

///|
test "RTP two-byte header extensions round-trip" {
  let packet = @rtp.Packet::new(
    payload_type=111,
    sequence_number=7,
    timestamp=8U,
    ssrc=9U,
    extensions=[
      @rtp.HeaderExtension::new(id=20, payload=b"\xaa\xbb"),
      @rtp.HeaderExtension::new(id=21, payload=b""),
    ],
    payload=b"opus",
  )
  let wire = packet.marshal()
  assert_eq(wire[12:16], b"\x10\x00\x00\x02")
  assert_eq(@rtp.Packet::unmarshal(wire), packet)
}

///|
test "RTP padding is validated and removed" {
  let padded = b"\xa0\x60\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03" +
    b"\x11\x22\x00\x00\x03"
  let packet = @rtp.Packet::unmarshal(padded)
  assert_eq(packet.payload(), b"\x11\x22")
  ignore(
    @rtp.Packet::unmarshal(
      b"\xa0\x60\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x11\x00",
    ),
  ) catch {
    InvalidPacket(_) => return
    _ => fail("unexpected RTP error")
  }
  fail("zero-length RTP padding was accepted")
}

///|
test "RTP parser rejects malformed packets without panicking" {
  let malformed = [
    b"", b"\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", b"\x81\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", b"\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x12\x34\x00\x01",
    b"\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xbe\xde\x00\x01\x1f",
  ]
  for wire in malformed {
    ignore(@rtp.Packet::unmarshal(wire)) catch {
      InvalidPacket(_) | InvalidExtension(_) => continue
      _ => fail("unexpected RTP error")
    }
    fail("malformed RTP packet was accepted")
  }
}
