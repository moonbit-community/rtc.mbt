///|
test "Opus and G7xx payloaders preserve encoded audio" {
  assert_eq(packetize_payload(Opus, b"opus", 1), [b"opus"])
  let chunks = packetize_payload(G711, b"abcdefghij", 4)
  assert_eq(chunks, [b"abcd", b"efgh", b"ij"])
  assert_eq(depacketize_payload(G711, chunks), b"abcdefghij")
}

///|
test "VP8 and VP9 payload descriptors survive MTU fragmentation" {
  let frame = b"0123456789abcdefghijklmnopqrstuvwxyz"
  let vp8_codec : PayloadCodec = Vp8
  let vp9_codec : PayloadCodec = Vp9
  let vp8 = packetize_payload(Vp8, frame, 8)
  assert_true(vp8.length() > 1)
  assert_true(vp8_codec.is_partition_head(vp8[0]))
  assert_false(vp8_codec.is_partition_head(vp8[1]))
  assert_eq(depacketize_payload(Vp8, vp8), frame)

  let vp9 = packetize_payload(Vp9, frame, 8)
  assert_true(vp9.length() > 1)
  assert_true(vp9_codec.is_partition_head(vp9[0]))
  assert_false(vp9_codec.is_partition_head(vp9[1]))
  assert_eq(depacketize_payload(Vp9, vp9), frame)
}

///|
test "VP8 and VP9 depacketizers parse optional descriptor fields" {
  let vp8 = b"\x80\xf0\x80\x23\x07\xa5payload"
  assert_eq(depacketize_payload(Vp8, [vp8]), b"payload")
  let vp9 = b"\xf0\x80\x23\x29\x09\x02payload"
  assert_eq(depacketize_payload(Vp9, [vp9]), b"payload")
}

///|
test "H264 packetizer emits STAP-A and FU-A with Annex-B output" {
  let access_unit = b"\x00\x00\x00\x01\x67\x42\x00\x1f" +
    b"\x00\x00\x00\x01\x68\xce\x06\xe2" +
    b"\x00\x00\x00\x01\x65abcdefghijklmno"
  let payloads = packetize_payload(H264, access_unit, 14)
  assert_true(payloads.length() >= 3)
  assert_eq(payloads[0][0] & 0x1f, 24)
  assert_eq(payloads[1][0] & 0x1f, 28)
  assert_true((payloads[1][1] & 0x80) != 0)
  assert_true((payloads[payloads.length() - 1][1] & 0x40) != 0)
  assert_eq(depacketize_payload(H264, payloads), access_unit)
}

///|
test "H265 packetizer emits aggregation and fragmentation units" {
  let access_unit = b"\x00\x00\x00\x01\x40\x01abc" +
    b"\x00\x00\x00\x01\x42\x01def" +
    b"\x00\x00\x00\x01\x26\x01abcdefghijklmnop"
  let payloads = packetize_payload(H265, access_unit, 16)
  assert_true(payloads.length() >= 3)
  assert_eq((payloads[0][0] >> 1) & 0x3f, 48)
  assert_eq((payloads[1][0] >> 1) & 0x3f, 49)
  assert_true((payloads[1][2] & 0x80) != 0)
  assert_true((payloads[payloads.length() - 1][2] & 0x40) != 0)
  assert_eq(depacketize_payload(H265, payloads), access_unit)
}

///|
test "AV1 packetizer fragments low-overhead OBUs and restores size fields" {
  let temporal_delimiter_and_frame = b"\x12\x00\x32\x0aabcdefghij"
  let av1_codec : PayloadCodec = Av1
  let payloads = packetize_payload(Av1, temporal_delimiter_and_frame, 6)
  assert_true(payloads.length() > 1)
  assert_true(av1_codec.is_partition_head(payloads[0]))
  assert_true(av1_codec.is_partition_head(payloads[1]))
  assert_false(av1_codec.is_partition_head(payloads[2]))
  assert_eq(depacketize_payload(Av1, payloads), b"\x32\x0aabcdefghij")
}

///|
test "Packetizer accounts for RTP headers, advances sequence and timestamp" {
  let extension = HeaderExtension::new(id=1, payload=b"\x01\x02\x03")
  let packetizer = Packetizer::new(
    mtu=24,
    payload_type=96,
    ssrc=0x11223344U,
    clock_rate=90000U,
    codec=Vp8,
    sequence_number=65535,
    timestamp=0xfffffff0U,
    include_vp8_picture_id=true,
  )
  let packets = packetizer.packetize(b"0123456789", 3000U, extensions=[
    extension,
  ])
  assert_true(packets.length() > 1)
  assert_eq(packets[0].sequence_number(), 65535)
  assert_eq(packets[1].sequence_number(), 0)
  assert_false(packets[0].marker())
  assert_true(packets[packets.length() - 1].marker())
  for packet in packets {
    assert_true(packet.marshal_size() <= 24)
    assert_eq(packet.timestamp(), 0xfffffff0U)
  }
  assert_eq(packetizer.timestamp(), 0x00000ba8U)
}

///|
test "codec depacketizers reject truncated payload descriptors" {
  let malformed : Array[(PayloadCodec, Array[Bytes])] = [
    (Vp8, [b"\x80"]),
    (Vp9, [b"\x80"]),
    (H264, [b"\x7c\x05x"]),
    (H265, [b"\x62\x01\x01x"]),
    (Av1, [b"\x10"]),
  ]
  for entry in malformed {
    let (codec, payloads) = entry
    ignore(depacketize_payload(codec, payloads)) catch {
      InvalidPacket(_) => continue
      _ => fail("unexpected codec error")
    }
    fail("malformed codec payload was accepted")
  }
}
