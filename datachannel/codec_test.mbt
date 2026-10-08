///|
test "DCEP OPEN matches the pinned rtc-datachannel fixture" {
  let message = @datachannel.DcepMessage::Open(
    @datachannel.DcepOpen::new(
      channel_type=ReliableChannel,
      priority=3893,
      reliability_parameter=16715573U,
      label="label",
      protocol="protocol",
    ),
  )
  let fixture = b"\x03\x00\x0f\x35\x00\xff\x0f\x35\x00\x05\x00\x08labelprotocol"
  assert_eq(message.encode(), fixture)
  assert_eq(@datachannel.DcepMessage::decode(fixture), message)
}

///|
test "all DCEP channel types and ACK round-trip" {
  let types : Array[@datachannel.ChannelType] = [
    ReliableChannel,
    ReliableUnorderedChannel,
    PartialReliableRetransmitChannel,
    PartialReliableRetransmitUnorderedChannel,
    PartialReliableTimedChannel,
    PartialReliableTimedUnorderedChannel,
  ]
  for channel_type in types {
    let message = @datachannel.DcepMessage::Open(
      @datachannel.DcepOpen::new(
        channel_type~,
        priority=512,
        reliability_parameter=17U,
        label="moon🌙",
        protocol="json",
      ),
    )
    assert_eq(@datachannel.DcepMessage::decode(message.encode()), message)
  }
  assert_eq(@datachannel.DcepMessage::decode(b"\x02"), Acknowledgement)
}

///|
test "DCEP codec rejects truncation, trailing ACK data, and malformed UTF-8" {
  let malformed = [
    b"", b"\x02\x00", b"\x03\x00", b"\x03\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    b"\x03\x00\x01\x00\x00\x00\x00\x00\x00\x01\x00\x00\xff",
  ]
  for value in malformed {
    try @datachannel.DcepMessage::decode(value) catch {
      ProtocolViolation(_) => ()
      _ => fail("unexpected DCEP error")
    } noraise {
      _ => fail("malformed DCEP input was accepted")
    }
  }
}

///|
test "WebRTC PPID mapping is strict" {
  assert_eq(@datachannel.PayloadProtocolIdentifier::from_code(50U), Dcep)
  assert_eq(
    @datachannel.PayloadProtocolIdentifier::from_code(51U),
    StringPayload,
  )
  assert_eq(
    @datachannel.PayloadProtocolIdentifier::from_code(53U),
    BinaryPayload,
  )
  assert_eq(
    @datachannel.PayloadProtocolIdentifier::from_code(56U),
    StringEmptyPayload,
  )
  assert_eq(
    @datachannel.PayloadProtocolIdentifier::from_code(57U),
    BinaryEmptyPayload,
  )
  for unsupported in [0U, 52U, 54U, 58U] {
    try @datachannel.PayloadProtocolIdentifier::from_code(unsupported) catch {
      ProtocolViolation(_) => ()
      _ => fail("unexpected PPID error")
    } noraise {
      _ => fail("unsupported PPID was accepted")
    }
  }
}
