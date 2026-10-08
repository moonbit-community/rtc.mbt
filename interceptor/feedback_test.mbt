///|
fn interceptor_test_rtp(
  sequence : UInt16,
  timestamp : UInt,
  ssrc : UInt,
  payload_type : Byte,
  payload : Bytes,
  extensions? : Array[@rtp.HeaderExtension] = [],
) -> @rtp.Packet raise @rtp.RtpError {
  @rtp.Packet::new(
    payload_type~,
    sequence_number=sequence,
    timestamp~,
    ssrc~,
    extensions~,
    payload~,
  )
}

///|
test "interceptor pipeline composes duplication and filtering stages" {
  let pipeline = @interceptor.Pipeline::new()
  pipeline.add(
    @interceptor.Stage::new(name="duplicate", handler=(_context, packet) => {
      [packet, packet]
    }),
  )
  pipeline.add(
    @interceptor.Stage::new(name="rtp-only", handler=(_context, packet) => {
      match packet {
        Rtp(_) => [packet]
        Rtcp(_) => []
      }
    }),
  )
  let packet = interceptor_test_rtp(1, 2U, 3U, 96, b"data")
  let output = pipeline.process(
    @interceptor.Context::new(direction=Inbound, stream_id="video"),
    Rtp(packet),
  )
  assert_eq(output, [Rtp(packet), Rtp(packet)])
  assert_eq(pipeline.length(), 2)
}

///|
test "NACK generator tracks gaps, late arrivals, and retry bounds" {
  let generator = @interceptor.NackGenerator::new(
    sender_ssrc=1U,
    media_ssrc=2U,
    max_retries=2,
  )
  generator.observe(interceptor_test_rtp(100, 0U, 2U, 96, b"a"))
  generator.observe(interceptor_test_rtp(104, 0U, 2U, 96, b"b"))
  assert_eq(generator.missing_sequences(), [101, 102, 103])
  generator.observe(interceptor_test_rtp(102, 0U, 2U, 96, b"late"))
  assert_eq(generator.missing_sequences(), [101, 103])
  let first = generator.poll_feedback().unwrap()
  assert_eq(first.nacks.length(), 1)
  assert_eq(first.nacks[0].lost_sequence_numbers(), [101, 103])
  assert_eq(
    @rtcp.Packet::unmarshal(first.marshal()).as_transport_layer_nack(),
    first,
  )
  ignore(generator.poll_feedback().unwrap())
  assert_eq(generator.poll_feedback(), None)
}

///|
test "sender and receiver report generators follow RFC3550 counters" {
  let sender = @interceptor.SenderReportGenerator::new(9U)
  sender.observe(interceptor_test_rtp(1, 10U, 9U, 111, b"abc"))
  sender.observe(interceptor_test_rtp(2, 20U, 9U, 111, b"defgh"))
  let sender_report = sender.report(0x0102030405060708UL)
  assert_eq(sender_report.packet_count, 2U)
  assert_eq(sender_report.octet_count, 8U)
  assert_eq(sender_report.rtp_timestamp, 20U)

  let receiver = @interceptor.ReceiverReportGenerator::new(
    sender_ssrc=10U,
    media_ssrc=9U,
    clock_rate=90000U,
  )
  receiver.observe(interceptor_test_rtp(65534, 100U, 9U, 96, b"a"), 100U)
  receiver.observe(interceptor_test_rtp(65535, 200U, 9U, 96, b"b"), 202U)
  receiver.observe(interceptor_test_rtp(1, 400U, 9U, 96, b"d"), 405U)
  receiver.observe_sender_report(sender_report, 500L)
  let report = receiver.report(1500L)
  assert_eq(report.reports.length(), 1)
  let block = report.reports[0]
  assert_eq(block.extended_sequence_number(), 65537U)
  assert_eq(block.cumulative_lost(), 1)
  assert_eq(block.fraction_lost(), 64)
  assert_eq(block.delay_since_last_sender_report(), 65536U)
  assert_eq(
    @rtcp.Packet::unmarshal(report.marshal()).as_receiver_report(),
    report,
  )
}

///|
test "TWCC recorder emits received deltas and loss statuses" {
  let recorder = @interceptor.TwccRecorder::new(
    sender_ssrc=1U,
    media_ssrc=2U,
    extension_id=3,
  )
  fn packet(sequence : UInt16) -> @rtp.Packet raise @rtp.RtpError {
    interceptor_test_rtp(sequence, 0U, 2U, 96, b"x", extensions=[
      @rtp.HeaderExtension::new(
        id=3,
        payload=@rtp.TransportCcExtension::new(transport_sequence=sequence).marshal(),
      ),
    ])
  }

  recorder.observe(packet(10), 64000L)
  recorder.observe(packet(11), 64250L)
  recorder.observe(packet(13), 65000L)
  let feedback = recorder.poll_feedback().unwrap()
  assert_eq(feedback.base_sequence_number, 10)
  assert_eq(feedback.reference_time, 1U)
  assert_eq(feedback.statuses, [
    PacketReceivedSmallDelta(0),
    PacketReceivedSmallDelta(250),
    PacketNotReceived,
    PacketReceivedSmallDelta(750),
  ])
  assert_eq(
    @rtcp.Packet::unmarshal(feedback.marshal()).as_transport_wide_cc(),
    feedback,
  )
  assert_eq(recorder.poll_feedback(), None)
}

///|
test "TWCC recorder shares one transport sequence across extension ids" {
  let recorder = @interceptor.TwccRecorder::new(
    sender_ssrc=1U,
    media_ssrc=0U,
    extension_id=3,
  )
  fn packet(
    rtp_sequence : UInt16,
    transport_sequence : UInt16,
    ssrc : UInt,
    extension_id : Byte,
  ) -> @rtp.Packet raise @rtp.RtpError {
    interceptor_test_rtp(rtp_sequence, 0U, ssrc, 96, b"x", extensions=[
      @rtp.HeaderExtension::new(
        id=extension_id,
        payload=@rtp.TransportCcExtension::new(transport_sequence~).marshal(),
      ),
    ])
  }

  recorder.observe_with_extension_id(packet(1, 20, 10U, 3), 64000L, 3)
  recorder.observe_with_extension_id(packet(2, 22, 11U, 7), 64500L, 7)
  let feedback = recorder.poll_feedback().unwrap()
  assert_eq(feedback.media_ssrc, 0U)
  assert_eq(feedback.base_sequence_number, 20)
  assert_eq(feedback.statuses, [
    PacketReceivedSmallDelta(0),
    PacketNotReceived,
    PacketReceivedSmallDelta(500),
  ])
}

///|
test "RTX sender and receiver restore original RTP packets once" {
  let sender = @interceptor.RtxSender::new(
    media_ssrc=100U,
    rtx_ssrc=200U,
    rtx_payload_type=97,
    sequence_number=500,
  )
  let original = interceptor_test_rtp(42, 9000U, 100U, 96, b"encoded frame")
  sender.remember(original)
  let nack = @rtcp.TransportLayerNackPacket::new(
    sender_ssrc=300U,
    media_ssrc=100U,
    nacks=[@rtcp.NackPair::new(packet_id=42)],
  )
  let retransmissions = sender.retransmit(nack)
  assert_eq(retransmissions.length(), 1)
  let rtx = retransmissions[0]
  assert_eq(rtx.sequence_number(), 500)
  assert_eq(rtx.ssrc(), 200U)
  assert_eq(rtx.payload_type(), 97)
  assert_eq(rtx.payload()[0:2], b"\x00\x2a")

  let receiver = @interceptor.RtxReceiver::new(
    media_ssrc=100U,
    media_payload_type=96,
    rtx_ssrc=200U,
    rtx_payload_type=97,
  )
  assert_eq(receiver.recover(rtx), Some(original))
  assert_eq(receiver.recover(rtx), None)
}
