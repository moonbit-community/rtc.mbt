///|
fn h26x_test_packet(
  sequence : UInt16,
  timestamp : UInt,
  marker : Bool,
  payload : Bytes,
) -> @rtp.Packet raise @rtp.RtpError {
  @rtp.Packet::new(
    marker~,
    payload_type=102,
    sequence_number=sequence,
    timestamp~,
    ssrc=9U,
    payload~,
  )
}

///|
test "H26x writer and reader round-trip fragmented H264" {
  let access_unit = b"\x00\x00\x00\x01\x67\x42\x00\x1f" +
    b"\x00\x00\x00\x01\x68\xce\x06\xe2" +
    b"\x00\x00\x00\x01\x65abcdefghijklmnop"
  let payloads = @rtp.packetize_payload(H264, access_unit, 14)
  let writer = H26xWriter::new(Avc)
  for index = 0; index < payloads.length(); index = index + 1 {
    writer.write_rtp(
      h26x_test_packet(
        index.to_uint16(),
        90U,
        index + 1 == payloads.length(),
        payloads[index],
      ),
    )
  }
  assert_eq(writer.bytes(), access_unit)

  let reader = H26xReader::new(codec=Avc, data=writer.bytes())
  assert_eq(reader.next_nal().unwrap().unit_type(), 7)
  assert_eq(reader.next_nal().unwrap().unit_type(), 8)
  assert_eq(reader.next_nal().unwrap().unit_type(), 5)
  assert_eq(reader.next_nal(), None)
  reader.reset()
  assert_eq(reader.next_nal().unwrap().unit_type(), 7)
}

///|
test "H26x writer and reader round-trip H265 aggregation and FU" {
  let access_unit = b"\x00\x00\x00\x01\x40\x01vps" +
    b"\x00\x00\x00\x01\x42\x01sps" +
    b"\x00\x00\x00\x01\x26\x01abcdefghijklmnop"
  let payloads = @rtp.packetize_payload(H265, access_unit, 16)
  let writer = H26xWriter::new(Hevc)
  writer.write_payloads(payloads)
  assert_eq(writer.bytes(), access_unit)
  let reader = H26xReader::new(codec=Hevc, data=writer.bytes())
  let vps = reader.next_nal().unwrap()
  assert_eq(vps.unit_type(), 32)
  assert_eq(vps.layer_id(), 0)
  assert_eq(vps.temporal_id_plus_one(), 1)
  assert_eq(reader.next_nal().unwrap().unit_type(), 33)
  assert_eq(reader.next_nal().unwrap().unit_type(), 19)
}

///|
test "H26x writer discards incomplete timestamp groups on close" {
  let writer = H26xWriter::new(Avc)
  writer.write_rtp(h26x_test_packet(1, 1U, false, b"\x7c\x85fragment"))
  writer.close()
  writer.close()
  assert_eq(writer.bytes(), b"")
  assert_eq(writer.dropped_incomplete_samples(), 1U)
  writer.write_payloads([b"\x65frame"]) catch {
    InvalidMedia(_) => return
    _ => fail("unexpected H26x writer error")
  }
  fail("closed H26x writer accepted data")
}
