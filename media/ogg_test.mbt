///|
test "Ogg Opus writer and reader round-trip headers, tags, and packets" {
  let tags = OpusTags::new(vendor="moonbit-community/rtc", comments=[
    UserComment::new(key="TITLE", value="Sans-I/O"),
    UserComment::new(key="ENCODER", value="rtc.mbt"),
  ])
  let writer = OggWriter::new(
    sample_rate=48000U,
    channels=2,
    pre_skip=312,
    serial=0x12345678U,
    tags~,
  )
  writer.write_opus_packet(b"\xf8\xff\xfe", 960UL)
  writer.write_opus_packet(b"\x01\x02\x03\x04", 1920UL)
  writer.close()
  writer.close()
  let wire = writer.bytes()
  assert_eq(wire[0:4], b"OggS")

  let reader = OggReader::new(wire)
  assert_eq(reader.header().version(), 1)
  assert_eq(reader.header().channels(), 2)
  assert_eq(reader.header().pre_skip(), 312)
  assert_eq(reader.header().sample_rate(), 48000U)
  assert_eq(reader.tags(), tags)
  let first = reader.next_packet().unwrap()
  assert_eq(first.data(), b"\xf8\xff\xfe")
  assert_eq(first.granule_position(), 960UL)
  assert_false(first.is_end_of_stream())
  let second = reader.next_packet().unwrap()
  assert_eq(second.data(), b"\x01\x02\x03\x04")
  assert_eq(second.granule_position(), 1920UL)
  assert_eq(reader.next_packet(), None)
  assert_eq(reader.bytes_read(), wire.length())
}

///|
test "Ogg lacing handles exact 255-byte packet boundaries" {
  let payload = Bytes::from_array(Array::make(510, 0x55))
  let writer = OggWriter::new(sample_rate=48000U, channels=1)
  writer.write_opus_packet(payload, 480UL)
  writer.close()
  let reader = OggReader::new(writer.bytes())
  assert_eq(reader.next_packet().unwrap().data(), payload)
  assert_eq(reader.next_packet(), None)
}

///|
test "Ogg reader detects CRC corruption" {
  let writer = OggWriter::new(sample_rate=48000U, channels=1)
  writer.write_opus_packet(b"encoded opus", 960UL)
  writer.close()
  let original = writer.bytes()
  let corrupted = original.to_array()
  corrupted[corrupted.length() - 30] = corrupted[corrupted.length() - 30] ^ 0x01
  let reader = OggReader::new(Bytes::from_array(corrupted))
  ignore(reader.next_packet()) catch {
    InvalidMedia(_) => return
    _ => fail("unexpected Ogg checksum error")
  }
  fail("corrupted Ogg page was accepted")
}

///|
test "Ogg RTP writer derives monotonic granule positions" {
  let writer = OggWriter::new(sample_rate=48000U, channels=1, pre_skip=100)
  writer.write_rtp(sample_test_packet(1, 1000U, true, b"one"))
  writer.write_rtp(sample_test_packet(2, 1960U, true, b"two"))
  writer.close()
  let reader = OggReader::new(writer.bytes())
  assert_eq(reader.next_packet().unwrap().granule_position(), 100UL)
  assert_eq(reader.next_packet().unwrap().granule_position(), 1060UL)
}
