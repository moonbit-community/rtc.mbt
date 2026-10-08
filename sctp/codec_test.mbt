///|
fn upstream_init_packet() -> Bytes {
  b"\x13\x88\x13\x88\x00\x00\x00\x00\x81\x46\x9d\xfc\x01\x00\x00\x56" +
  b"\x55\xb9\x64\xa5\x00\x02\x00\x00\x04\x00\x08\x00\xe8\x6d\x10\x30" +
  b"\xc0\x00\x00\x04\x80\x08\x00\x09\xc0\x0f\xc1\x80\x82\x00\x00\x00" +
  b"\x80\x02\x00\x24\x9f\xeb\xbb\x5c\x50\xc9\xbf\x75\x9c\xb1\x2c\x57" +
  b"\x4f\xa4\x5a\x51\xba\x60\x17\x78\x27\x94\x5c\x31\xe6\x5d\x5b\x09" +
  b"\x47\xe2\x22\x06\x80\x04\x00\x06\x00\x01\x00\x00\x80\x03\x00\x06" +
  b"\x80\xc1\x00\x00"
}

///|
test "pinned rtc-sctp INIT fixture validates CRC32C and round-trips" {
  let wire = upstream_init_packet()
  let packet = @sctp.Packet::decode(wire)
  assert_eq(packet.source_port(), 5000)
  assert_eq(packet.destination_port(), 5000)
  assert_eq(packet.verification_tag(), 0U)
  guard packet.chunks() is [InitChunkValue(init)] else {
    fail("fixture did not decode as one INIT chunk")
  }
  assert_false(init.is_acknowledgement())
  assert_eq(init.initiate_tag(), 0x55b964a5U)
  assert_eq(init.advertised_receiver_window(), 131072U)
  assert_eq(init.outbound_streams(), 1024)
  assert_eq(init.inbound_streams(), 2048)
  assert_eq(init.initial_tsn(), 0xe86d1030U)
  assert_eq(init.parameters().length(), 5)
  assert_eq(packet.encode(), wire)
}

///|
test "SCTP DATA, SACK, and RE-CONFIG chunks survive bundled framing" {
  let packet = @sctp.Packet::new(
    source_port=5000,
    destination_port=5000,
    verification_tag=0x10203040U,
    chunks=[
      DataChunkValue(
        @sctp.DataChunk::new(
          tsn=100U,
          stream=StreamId(7),
          stream_sequence=9,
          protocol_id=53U,
          user_data=b"hello",
        ),
      ),
      SackChunkValue(
        @sctp.SackChunk::new(
          cumulative_tsn_ack=99U,
          gap_ack_blocks=[{ start: 2, end: 3, }],
          duplicate_tsns=[98U],
        ),
      ),
      ReconfigChunk([
        OutgoingResetRequest(
          request_sequence=100U,
          response_sequence=99U,
          sender_last_tsn=100U,
          streams=[StreamId(7)],
        ),
        ReconfigResponse(request_sequence=88U, result=1U),
      ]),
      ForwardTsnChunk(
        @sctp.ForwardTsn::new(new_cumulative_tsn=105U, streams=[
          @sctp.ForwardTsnStream::new(stream=StreamId(7), sequence=9),
          @sctp.ForwardTsnStream::new(stream=StreamId(8), sequence=4),
        ]),
      ),
    ],
  )
  let wire = packet.encode()
  assert_eq(@sctp.Packet::decode(wire), packet)
  guard @sctp.Packet::decode(wire).chunks()[0] is DataChunkValue(data) else {
    fail("missing DATA chunk")
  }
  assert_true(data.is_beginning())
  assert_true(data.is_ending())
  assert_eq(data.protocol_id(), 53U)
  assert_eq(data.user_data(), b"hello")
}

///|
test "SCTP decoder rejects checksum, chunk bounds, and nonzero padding" {
  let corrupted = upstream_init_packet().to_array()
  corrupted[20] = corrupted[20] ^ 1
  try @sctp.Packet::decode(Bytes::from_array(corrupted)) catch {
    ChecksumMismatch => ()
    _ => fail("unexpected SCTP checksum error")
  } noraise {
    _ => fail("corrupt SCTP packet was accepted")
  }
  let truncated = upstream_init_packet()[0:upstream_init_packet().length() - 1].to_owned()
  try @sctp.Packet::decode(truncated) catch {
    ChecksumMismatch | InvalidPacket(_) => ()
    _ => fail("unexpected truncated SCTP error")
  } noraise {
    _ => fail("truncated SCTP packet was accepted")
  }
  let padded = @sctp.Packet::new(
      source_port=5000,
      destination_port=5000,
      verification_tag=1U,
      chunks=[CookieEchoChunk(b"x")],
    )
    .encode()
    .to_array()
  padded[padded.length() - 1] = 1
  try @sctp.Packet::decode(Bytes::from_array(padded)) catch {
    ChecksumMismatch | InvalidPacket(_) => ()
    _ => fail("unexpected SCTP padding error")
  } noraise {
    _ => fail("nonzero SCTP padding was accepted")
  }
}

///|
test "SCTP common-header checksum byte order matches the upstream fixture" {
  let wire = b"\x13\x88\x13\x88\x00\x00\x00\x00\x06\xa9\x00\xe1"
  let packet = @sctp.Packet::decode(wire)
  assert_true(packet.chunks().is_empty())
  assert_eq(packet.encode(), wire)
}
