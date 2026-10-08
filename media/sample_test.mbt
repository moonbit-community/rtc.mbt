///|
fn sample_test_packet(
  sequence : UInt16,
  timestamp : UInt,
  marker : Bool,
  payload : Bytes,
) -> @rtp.Packet raise @rtp.RtpError {
  @rtp.Packet::new(
    marker~,
    payload_type=96,
    sequence_number=sequence,
    timestamp~,
    ssrc=1U,
    payload~,
  )
}

///|
test "SampleBuilder reorders fragmented video and computes duration" {
  let frame = b"abcdefghijklmnopqrstuvwxyz"
  let payloads = @rtp.packetize_payload(Vp8, frame, 10)
  assert_true(payloads.length() > 1)
  let builder = @media.SampleBuilder::new(
    max_late=10,
    codec=Vp8,
    sample_rate=90000U,
    generated_at=@transport.WallTime::from_unix_nanoseconds(123L),
  )
  builder.push(sample_test_packet(101, 9000U, false, payloads[1]))
  builder.push(sample_test_packet(100, 9000U, false, payloads[0]))
  for index = 2; index < payloads.length(); index = index + 1 {
    builder.push(
      sample_test_packet(
        (100 + index).to_uint16(),
        9000U,
        index + 1 == payloads.length(),
        payloads[index],
      ),
    )
  }
  assert_eq(builder.pop(), None)
  builder.push(
    sample_test_packet(
      (100 + payloads.length()).to_uint16(),
      12000U,
      true,
      b"\x10next",
    ),
  )
  let sample = builder.pop().unwrap()
  assert_eq(sample.data(), frame)
  assert_eq(sample.packet_timestamp(), 9000U)
  assert_eq(sample.duration().as_milliseconds(), 33L)
  assert_eq(sample.timestamp().as_unix_nanoseconds(), 123L)
}

///|
test "SampleBuilder reports packet loss before the next valid sample" {
  let builder = @media.SampleBuilder::new(
    max_late=1,
    codec=Vp8,
    sample_rate=90000U,
  )
  builder.push(sample_test_packet(10, 100U, false, b"\x00tail"))
  builder.push(sample_test_packet(11, 200U, true, b"\x10frame"))
  builder.push(sample_test_packet(12, 300U, true, b"\x10next"))
  let sample = builder.pop().unwrap()
  assert_eq(sample.data(), b"frame")
  assert_eq(sample.prev_dropped_packets(), 1)
}

///|
test "SampleBuilder handles sequence rollover and flushes the last sample" {
  let builder = @media.SampleBuilder::new(
    max_late=4,
    codec=G711,
    sample_rate=8000U,
  )
  builder.push(sample_test_packet(65535, 0U, true, b"first"))
  builder.push(sample_test_packet(0, 160U, true, b"second"))
  let first = builder.pop().unwrap()
  assert_eq(first.data(), b"first")
  assert_eq(first.duration().as_milliseconds(), 20L)
  builder.flush()
  let second = builder.pop().unwrap()
  assert_eq(second.data(), b"second")
  assert_eq(second.duration().as_milliseconds(), 0L)
}
