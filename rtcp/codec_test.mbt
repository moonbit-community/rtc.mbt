///|
test "RTCP sender and receiver reports round-trip signed loss" {
  let report = @rtcp.ReceptionReport::new(
    ssrc=0x10203040U,
    fraction_lost=7,
    cumulative_lost=-23,
    extended_sequence_number=0x00010002U,
    jitter=99U,
    last_sender_report=0x55667788U,
    delay_since_last_sender_report=0x01020304U,
  )
  let sender = @rtcp.SenderReportPacket::new(
    sender_ssrc=0xaabbccddU,
    ntp_timestamp=0x0102030405060708UL,
    rtp_timestamp=0x11223344U,
    packet_count=123U,
    octet_count=456U,
    reports=[report],
    profile_extensions=b"\xde\xad\xbe\xef",
  )
  let sender_packet = sender.to_packet()
  assert_eq(sender_packet.header().packet_type(), 200)
  assert_eq(
    @rtcp.Packet::unmarshal(sender_packet.marshal()).as_sender_report(),
    sender,
  )

  let receiver = @rtcp.ReceiverReportPacket::new(sender_ssrc=0x12345678U, reports=[
    report,
  ])
  assert_eq(
    @rtcp.Packet::unmarshal(receiver.marshal()).as_receiver_report(),
    receiver,
  )
}

///|
test "RTCP SDES, BYE, and APP packets form a compound packet" {
  let sdes = @rtcp.SourceDescriptionPacket::new(chunks=[
    @rtcp.SourceDescriptionChunk::new(source=0x01020304U, items=[
      @rtcp.SourceDescriptionItem::new(item_type=Cname, value=b"moon@rtc"),
      @rtcp.SourceDescriptionItem::new(item_type=Tool, value=b"rtc.mbt"),
    ]),
  ])
  let bye = @rtcp.GoodbyePacket::new(
    sources=[0x01020304U, 0xaabbccddU],
    reason=b"finished",
  )
  let app = @rtcp.ApplicationDefinedPacket::new(
    subtype=3,
    ssrc=0x99887766U,
    name=b"TEST",
    data=b"\x01\x02\x03\x04",
  )
  let compound = @rtcp.encode_compound([
    sdes.to_packet(),
    app.to_packet(),
    bye.to_packet(),
  ])
  guard @rtcp.decode_compound(compound)
    is [decoded_sdes, decoded_app, decoded_bye] else {
    fail("RTCP compound packet did not preserve its packet count")
  }
  assert_eq(decoded_sdes.as_source_description(), sdes)
  assert_eq(decoded_app.as_application_defined(), app)
  assert_eq(decoded_bye.as_goodbye(), bye)
}

///|
test "RTCP NACK expands bitmasks and feedback packets round-trip" {
  let nack = @rtcp.TransportLayerNackPacket::new(
    sender_ssrc=1U,
    media_ssrc=2U,
    nacks=[@rtcp.NackPair::new(packet_id=100, lost_packets=0x0005)],
  )
  assert_eq(nack.nacks[0].lost_sequence_numbers(), [100, 101, 103])
  assert_eq(
    @rtcp.Packet::unmarshal(nack.marshal()).as_transport_layer_nack(),
    nack,
  )

  let pli = @rtcp.PictureLossIndicationPacket::new(
    sender_ssrc=3U,
    media_ssrc=4U,
  )
  assert_eq(
    @rtcp.Packet::unmarshal(pli.marshal()).as_picture_loss_indication(),
    pli,
  )

  let fir = @rtcp.FullIntraRequestPacket::new(sender_ssrc=5U, entries=[
    { ssrc: 6U, sequence_number: 7, },
    { ssrc: 8U, sequence_number: 9, },
  ])
  assert_eq(@rtcp.Packet::unmarshal(fir.marshal()).as_full_intra_request(), fir)
}

///|
test "RTCP transport-wide congestion feedback handles run and vector chunks" {
  let feedback = @rtcp.TransportWideCcPacket::new(
    sender_ssrc=1U,
    media_ssrc=2U,
    base_sequence_number=10,
    reference_time=0x010203U,
    feedback_packet_count=4,
    statuses=[
      PacketNotReceived,
      PacketNotReceived,
      PacketReceivedSmallDelta(250),
      PacketReceivedSmallDelta(63750),
      PacketReceivedLargeDelta(-250),
      PacketReceivedWithoutDelta,
    ],
  )
  assert_eq(
    @rtcp.Packet::unmarshal(feedback.marshal()).as_transport_wide_cc(),
    feedback,
  )

  let vector_wire = b"\x8f\xcd\x00\x06" +
    b"\x00\x00\x00\x01\x00\x00\x00\x02" +
    b"\x00\x0a\x00\x07\x00\x00\x01\x02" +
    b"\xc6\xd2\x04\xff\xfe\x01\x00\x02"
  let vector = @rtcp.Packet::unmarshal(vector_wire).as_transport_wide_cc()
  assert_eq(vector.statuses, [
    PacketNotReceived,
    PacketReceivedSmallDelta(1000),
    PacketReceivedLargeDelta(-500),
    PacketReceivedWithoutDelta,
    PacketReceivedSmallDelta(250),
    PacketNotReceived,
    PacketReceivedLargeDelta(500),
  ])
  assert_eq(vector.reference_time, 1U)
  assert_eq(vector.feedback_packet_count, 2)
}

///|
test "RTCP REMB and extended report blocks round-trip" {
  let remb = @rtcp.ReceiverEstimatedMaximumBitratePacket::new(
    sender_ssrc=0x10203040U,
    bitrate=250000UL,
    ssrcs=[0x11223344U, 0x55667788U],
  )
  assert_eq(
    @rtcp.Packet::unmarshal(remb.marshal()).as_receiver_estimated_maximum_bitrate(),
    remb,
  )
  let xr = @rtcp.ExtendedReportPacket::new(sender_ssrc=0x12345678U, blocks=[
    @rtcp.ExtendedReportBlock::new(
      block_type=4,
      type_specific=1,
      payload=b"\x01\x02\x03\x04\x05\x06\x07\x08",
    ),
    @rtcp.ExtendedReportBlock::new(block_type=200, payload=b""),
  ])
  assert_eq(@rtcp.Packet::unmarshal(xr.marshal()).as_extended_report(), xr)
}

///|
test "RTCP parser rejects truncation, invalid lengths, and interior padding" {
  let malformed = [
    b"", b"\x40\xc8\x00\x06", b"\x80\xc8\x00\x06\x00\x00\x00\x00", b"\xa0\xc9\x00\x01\x00\x00\x00\x00",
  ]
  for wire in malformed {
    ignore(@rtcp.decode_compound(wire)) catch {
      InvalidPacket(_) | InvalidCompoundPacket(_) => continue
      _ => fail("unexpected RTCP error")
    }
    fail("malformed RTCP packet was accepted")
  }
  let padded = Bytes::from_array([0xa0, 201, 0, 2, 0, 0, 0, 1, 0, 0, 0, 4])
  let receiver = @rtcp.ReceiverReportPacket::new(sender_ssrc=2U).marshal()
  ignore(@rtcp.decode_compound(padded + receiver)) catch {
    InvalidCompoundPacket(_) => return
    _ => fail("unexpected RTCP error")
  }
  fail("interior RTCP padding was accepted")
}
