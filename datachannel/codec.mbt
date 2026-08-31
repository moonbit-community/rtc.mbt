///|
fn dc_writer(capacity : Int) -> @codec.Writer raise DataChannelError {
  @codec.Writer::new(capacity~) catch {
    _ => raise ProtocolViolation("invalid DCEP output length")
  }
}

///|
fn dc_read_u8(
  reader : @codec.Reader,
  context : String,
) -> Byte raise DataChannelError {
  reader.read_u8() catch {
    _ => raise ProtocolViolation("truncated \{context}")
  }
}

///|
fn dc_read_u16(
  reader : @codec.Reader,
  context : String,
) -> UInt16 raise DataChannelError {
  reader.read_u16_be() catch {
    _ => raise ProtocolViolation("truncated \{context}")
  }
}

///|
fn dc_read_u32(
  reader : @codec.Reader,
  context : String,
) -> UInt raise DataChannelError {
  reader.read_u32_be() catch {
    _ => raise ProtocolViolation("truncated \{context}")
  }
}

///|
fn dc_read_bytes(
  reader : @codec.Reader,
  length : Int,
  context : String,
) -> Bytes raise DataChannelError {
  reader.read_bytes(length) catch {
    _ => raise ProtocolViolation("truncated \{context}")
  }
}

///|
fn channel_type_code(channel_type : ChannelType) -> Byte {
  match channel_type {
    ReliableChannel => 0x00
    ReliableUnorderedChannel => 0x80
    PartialReliableRetransmitChannel => 0x01
    PartialReliableRetransmitUnorderedChannel => 0x81
    PartialReliableTimedChannel => 0x02
    PartialReliableTimedUnorderedChannel => 0x82
  }
}

///|
fn decode_channel_type(value : Byte) -> ChannelType raise DataChannelError {
  match value {
    0x00 => ReliableChannel
    0x80 => ReliableUnorderedChannel
    0x01 => PartialReliableRetransmitChannel
    0x81 => PartialReliableRetransmitUnorderedChannel
    0x02 => PartialReliableTimedChannel
    0x82 => PartialReliableTimedUnorderedChannel
    _ =>
      raise ProtocolViolation(
        "unsupported DCEP channel type \{value.to_uint()}",
      )
  }
}

///|
pub fn DcepMessage::encode(self : DcepMessage) -> Bytes raise DataChannelError {
  match self {
    Acknowledgement => b"\x02"
    Open(open) => {
      let label = @utf8.encode(open.label)
      let protocol = @utf8.encode(open.protocol)
      if label.length() > 65535 || protocol.length() > 65535 {
        raise InvalidConfiguration(
          "DCEP label and protocol must each fit in 65535 UTF-8 bytes",
        )
      }
      let writer = dc_writer(12 + label.length() + protocol.length())
      writer.write_u8(0x03)
      writer.write_u8(channel_type_code(open.channel_type))
      writer.write_u16_be(open.priority)
      writer.write_u32_be(open.reliability_parameter)
      writer.write_u16_be(label.length().to_uint16())
      writer.write_u16_be(protocol.length().to_uint16())
      writer.write_bytes(label)
      writer.write_bytes(protocol)
      writer.finish()
    }
  }
}

///|
pub fn DcepMessage::decode(data : Bytes) -> DcepMessage raise DataChannelError {
  let reader = @codec.Reader::new(data)
  let message_type = dc_read_u8(reader, "DCEP message type")
  match message_type {
    0x02 => {
      if reader.remaining() != 0 {
        raise ProtocolViolation("DCEP ACK contains trailing bytes")
      }
      Acknowledgement
    }
    0x03 => {
      let channel_type = decode_channel_type(
        dc_read_u8(reader, "DCEP channel type"),
      )
      let priority = dc_read_u16(reader, "DCEP priority")
      let reliability_parameter = dc_read_u32(
        reader, "DCEP reliability parameter",
      )
      let label_length = dc_read_u16(reader, "DCEP label length").to_int()
      let protocol_length = dc_read_u16(reader, "DCEP protocol length").to_int()
      if reader.remaining() != label_length + protocol_length {
        raise ProtocolViolation("DCEP OPEN length does not match its vectors")
      }
      let label = @utf8.decode(
        dc_read_bytes(reader, label_length, "DCEP label"),
      ) catch {
        _ => raise ProtocolViolation("DCEP label is not valid UTF-8")
      }
      let protocol = @utf8.decode(
        dc_read_bytes(reader, protocol_length, "DCEP protocol"),
      ) catch {
        _ => raise ProtocolViolation("DCEP protocol is not valid UTF-8")
      }
      Open({ channel_type, priority, reliability_parameter, label, protocol, })
    }
    _ =>
      raise ProtocolViolation(
        "unsupported DCEP message type \{message_type.to_uint()}",
      )
  }
}

///|
pub fn PayloadProtocolIdentifier::from_code(
  code : UInt,
) -> PayloadProtocolIdentifier raise DataChannelError {
  match code {
    50U => Dcep
    51U => StringPayload
    53U => BinaryPayload
    56U => StringEmptyPayload
    57U => BinaryEmptyPayload
    52U | 54U =>
      raise ProtocolViolation("deprecated partial WebRTC PPID is unsupported")
    _ => raise ProtocolViolation("unsupported WebRTC PPID \{code}")
  }
}
