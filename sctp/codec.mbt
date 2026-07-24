///|
fn sctp_writer(capacity : Int) -> @codec.Writer raise SctpError {
  @codec.Writer::new(capacity~) catch {
    InvalidLength(length) =>
      raise InvalidPacket("invalid SCTP writer length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket(
        "unexpected SCTP writer truncation \{needed}/\{remaining}",
      )
  }
}

///|
fn sctp_read_u8(
  reader : @codec.Reader,
  context : String,
) -> Byte raise SctpError {
  reader.read_u8() catch {
    InvalidLength(length) =>
      raise InvalidPacket("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn sctp_read_u16(
  reader : @codec.Reader,
  context : String,
) -> UInt16 raise SctpError {
  reader.read_u16_be() catch {
    InvalidLength(length) =>
      raise InvalidPacket("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn sctp_read_u32(
  reader : @codec.Reader,
  context : String,
) -> UInt raise SctpError {
  reader.read_u32_be() catch {
    InvalidLength(length) =>
      raise InvalidPacket("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn sctp_read_bytes(
  reader : @codec.Reader,
  length : Int,
  context : String,
) -> Bytes raise SctpError {
  reader.read_bytes(length) catch {
    InvalidLength(invalid_length) =>
      raise InvalidPacket("\{context}: invalid length \{invalid_length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn padding_length(length : Int) -> Int {
  (4 - length % 4) % 4
}

///|
fn crc32c(data : Bytes) -> UInt {
  let mut checksum = 0xffffffffU
  for index = 0; index < data.length(); index = index + 1 {
    let byte : Byte = if index >= 8 && index < 12 { 0 } else { data[index] }
    checksum = checksum ^ byte.to_uint()
    for bit = 0; bit < 8; bit = bit + 1 {
      checksum = if (checksum & 1U) != 0U {
        (checksum >> 1) ^ 0x82f63b78U
      } else {
        checksum >> 1
      }
    }
  }
  checksum ^ 0xffffffffU
}

///|
fn parameter_type_value(parameter : Parameter) -> (UInt16, Bytes) {
  match parameter {
    StateCookieParameter(value) => (7, value)
    SupportedExtensionsParameter(value) => (0x8008, value)
    ForwardTsnSupportedParameter => (0xc000, b"")
    UnknownParameter(parameter_type, value) => (parameter_type, value)
  }
}

///|
fn encode_parameter(parameter : Parameter) -> Bytes raise SctpError {
  let (parameter_type, value) = parameter_type_value(parameter)
  if value.length() > 0xfffb {
    raise InvalidPacket("SCTP parameter exceeds 65535 bytes")
  }
  let writer = sctp_writer(4 + value.length())
  writer.write_u16_be(parameter_type)
  writer.write_u16_be((4 + value.length()).to_uint16())
  writer.write_bytes(value)
  writer.finish()
}

///|
fn decode_parameter(reader : @codec.Reader) -> Parameter raise SctpError {
  let parameter_type = sctp_read_u16(reader, "SCTP parameter type")
  let length = sctp_read_u16(reader, "SCTP parameter length").to_int()
  if length < 4 {
    raise InvalidPacket("SCTP parameter length is smaller than its header")
  }
  let value = sctp_read_bytes(reader, length - 4, "SCTP parameter value")
  match parameter_type {
    7 => StateCookieParameter(value)
    0x8008 => SupportedExtensionsParameter(value)
    0xc000 => {
      if !value.is_empty() {
        raise InvalidPacket("Forward-TSN-Supported parameter must be empty")
      }
      ForwardTsnSupportedParameter
    }
    _ => UnknownParameter(parameter_type, value)
  }
}

///|
fn encode_init(init : InitChunk) -> Bytes raise SctpError {
  let writer = sctp_writer(64)
  writer.write_u32_be(init.initiate_tag)
  writer.write_u32_be(init.advertised_receiver_window)
  writer.write_u16_be(init.outbound_streams)
  writer.write_u16_be(init.inbound_streams)
  writer.write_u32_be(init.initial_tsn)
  for index = 0; index < init.parameters.length(); index = index + 1 {
    let parameter = encode_parameter(init.parameters[index])
    writer.write_bytes(parameter)
    if index + 1 < init.parameters.length() {
      for padding = 0
          padding < padding_length(parameter.length())
          padding = padding + 1 {
        writer.write_u8(0)
      }
    }
  }
  writer.finish()
}

///|
fn decode_init(
  acknowledgement : Bool,
  flags : Byte,
  value : Bytes,
) -> InitChunk raise SctpError {
  if flags != 0 || value.length() < 16 {
    raise InvalidPacket("malformed SCTP INIT chunk")
  }
  let reader = @codec.Reader::new(value)
  let initiate_tag = sctp_read_u32(reader, "SCTP initiate tag")
  let advertised_receiver_window = sctp_read_u32(reader, "SCTP receiver window")
  let outbound_streams = sctp_read_u16(reader, "SCTP outbound streams")
  let inbound_streams = sctp_read_u16(reader, "SCTP inbound streams")
  let initial_tsn = sctp_read_u32(reader, "SCTP initial TSN")
  let parameters : Array[Parameter] = []
  while reader.remaining() > 0 {
    if reader.remaining() < 4 {
      raise InvalidPacket("truncated SCTP INIT parameter header")
    }
    let before = reader.position()
    parameters.push(decode_parameter(reader))
    let consumed = reader.position() - before
    let padding = padding_length(consumed)
    if padding > reader.remaining() {
      if reader.remaining() == 0 {
        break
      }
      raise InvalidPacket("truncated SCTP INIT parameter padding")
    }
    let padding_bytes = sctp_read_bytes(
      reader, padding, "SCTP INIT parameter padding",
    )
    for byte in padding_bytes {
      if byte != 0 {
        raise InvalidPacket("SCTP parameter padding must be zero")
      }
    }
  }
  InitChunk::new(
    acknowledgement~,
    initiate_tag~,
    advertised_receiver_window~,
    outbound_streams~,
    inbound_streams~,
    initial_tsn~,
    parameters~,
  )
}

///|
fn encode_data(data : DataChunk) -> (Byte, Bytes) raise SctpError {
  if data.user_data.length() > 0xffef {
    raise InvalidPacket("SCTP DATA chunk exceeds 65535 bytes")
  }
  let mut flags : Byte = 0
  if data.ending {
    flags = flags | 1
  }
  if data.beginning {
    flags = flags | 2
  }
  if data.unordered {
    flags = flags | 4
  }
  if data.immediate_sack {
    flags = flags | 8
  }
  let writer = sctp_writer(12 + data.user_data.length())
  writer.write_u32_be(data.tsn)
  let StreamId(stream) = data.stream
  writer.write_u16_be(stream)
  writer.write_u16_be(data.stream_sequence)
  writer.write_u32_be(data.protocol_id)
  writer.write_bytes(data.user_data)
  (flags, writer.finish())
}

///|
fn decode_data(flags : Byte, value : Bytes) -> DataChunk raise SctpError {
  if (flags & 0xf0) != 0 || value.length() < 12 {
    raise InvalidPacket("malformed SCTP DATA chunk")
  }
  let reader = @codec.Reader::new(value)
  let tsn = sctp_read_u32(reader, "SCTP DATA TSN")
  let stream = StreamId(sctp_read_u16(reader, "SCTP DATA stream"))
  let stream_sequence = sctp_read_u16(reader, "SCTP DATA stream sequence")
  let protocol_id = sctp_read_u32(reader, "SCTP DATA protocol ID")
  let user_data = sctp_read_bytes(
    reader,
    reader.remaining(),
    "SCTP DATA payload",
  )
  DataChunk::new(
    unordered=(flags & 4) != 0,
    beginning=(flags & 2) != 0,
    ending=(flags & 1) != 0,
    immediate_sack=(flags & 8) != 0,
    tsn~,
    stream~,
    stream_sequence~,
    protocol_id~,
    user_data~,
  )
}

///|
fn encode_sack(sack : SackChunk) -> Bytes raise SctpError {
  if sack.gap_ack_blocks.length() > 0xffff ||
    sack.duplicate_tsns.length() > 0xffff {
    raise InvalidPacket("SCTP SACK contains too many entries")
  }
  let writer = sctp_writer(
    12 + sack.gap_ack_blocks.length() * 4 + sack.duplicate_tsns.length() * 4,
  )
  writer.write_u32_be(sack.cumulative_tsn_ack)
  writer.write_u32_be(sack.advertised_receiver_window)
  writer.write_u16_be(sack.gap_ack_blocks.length().to_uint16())
  writer.write_u16_be(sack.duplicate_tsns.length().to_uint16())
  for gap in sack.gap_ack_blocks {
    writer.write_u16_be(gap.start)
    writer.write_u16_be(gap.end)
  }
  for duplicate in sack.duplicate_tsns {
    writer.write_u32_be(duplicate)
  }
  writer.finish()
}

///|
fn decode_sack(flags : Byte, value : Bytes) -> SackChunk raise SctpError {
  if flags != 0 || value.length() < 12 {
    raise InvalidPacket("malformed SCTP SACK chunk")
  }
  let reader = @codec.Reader::new(value)
  let cumulative_tsn_ack = sctp_read_u32(reader, "SCTP cumulative TSN")
  let advertised_receiver_window = sctp_read_u32(reader, "SCTP receiver window")
  let gap_count = sctp_read_u16(reader, "SCTP gap count").to_int()
  let duplicate_count = sctp_read_u16(reader, "SCTP duplicate count").to_int()
  if reader.remaining() != gap_count * 4 + duplicate_count * 4 {
    raise InvalidPacket("SCTP SACK entry count does not match its length")
  }
  let gap_ack_blocks : Array[GapAckBlock] = []
  for index = 0; index < gap_count; index = index + 1 {
    let start = sctp_read_u16(reader, "SCTP gap start")
    let end = sctp_read_u16(reader, "SCTP gap end")
    if start == 0 || end < start {
      raise InvalidPacket("invalid SCTP gap acknowledgement block")
    }
    gap_ack_blocks.push({ start, end })
  }
  let duplicate_tsns : Array[UInt] = []
  for index = 0; index < duplicate_count; index = index + 1 {
    duplicate_tsns.push(sctp_read_u32(reader, "SCTP duplicate TSN"))
  }
  SackChunk::new(
    cumulative_tsn_ack~,
    advertised_receiver_window~,
    gap_ack_blocks~,
    duplicate_tsns~,
  )
}

///|
fn encode_reconfig_parameter(
  parameter : ReconfigParameter,
) -> Bytes raise SctpError {
  let (parameter_type, value) : (UInt16, Bytes) = match parameter {
    OutgoingResetRequest(
      request_sequence~,
      response_sequence~,
      sender_last_tsn~,
      streams~
    ) => {
      let writer = sctp_writer(12 + streams.length() * 2)
      writer.write_u32_be(request_sequence)
      writer.write_u32_be(response_sequence)
      writer.write_u32_be(sender_last_tsn)
      for stream in streams {
        let StreamId(value) = stream
        writer.write_u16_be(value)
      }
      (13, writer.finish())
    }
    ReconfigResponse(request_sequence~, result~) => {
      let writer = sctp_writer(8)
      writer.write_u32_be(request_sequence)
      writer.write_u32_be(result)
      (16, writer.finish())
    }
    UnknownReconfigParameter(parameter_type, value) => (parameter_type, value)
  }
  if value.length() > 0xfffb {
    raise InvalidPacket("SCTP reconfiguration parameter is too large")
  }
  let writer = sctp_writer(4 + value.length())
  writer.write_u16_be(parameter_type)
  writer.write_u16_be((4 + value.length()).to_uint16())
  writer.write_bytes(value)
  writer.finish()
}

///|
fn decode_reconfig_parameter(
  reader : @codec.Reader,
) -> ReconfigParameter raise SctpError {
  let parameter_type = sctp_read_u16(
    reader, "SCTP reconfiguration parameter type",
  )
  let length = sctp_read_u16(reader, "SCTP reconfiguration parameter length").to_int()
  if length < 4 {
    raise InvalidPacket("invalid SCTP reconfiguration parameter length")
  }
  let value = sctp_read_bytes(
    reader,
    length - 4,
    "SCTP reconfiguration parameter",
  )
  match parameter_type {
    13 => {
      if value.length() < 12 || (value.length() - 12) % 2 != 0 {
        raise InvalidPacket("malformed outgoing stream reset request")
      }
      let value_reader = @codec.Reader::new(value)
      let request_sequence = sctp_read_u32(
        value_reader, "stream reset request sequence",
      )
      let response_sequence = sctp_read_u32(
        value_reader, "stream reset response sequence",
      )
      let sender_last_tsn = sctp_read_u32(
        value_reader, "stream reset sender TSN",
      )
      let streams : Array[StreamId] = []
      while value_reader.remaining() > 0 {
        streams.push(
          StreamId(sctp_read_u16(value_reader, "stream reset stream ID")),
        )
      }
      OutgoingResetRequest(
        request_sequence~,
        response_sequence~,
        sender_last_tsn~,
        streams~,
      )
    }
    16 => {
      if value.length() != 8 && value.length() != 16 {
        raise InvalidPacket("malformed stream reconfiguration response")
      }
      let value_reader = @codec.Reader::new(value)
      let request_sequence = sctp_read_u32(
        value_reader, "stream reset response sequence",
      )
      let result = sctp_read_u32(value_reader, "stream reset result")
      ReconfigResponse(request_sequence~, result~)
    }
    _ => UnknownReconfigParameter(parameter_type, value)
  }
}

///|
fn encode_reconfig(
  parameters : Array[ReconfigParameter],
) -> Bytes raise SctpError {
  if parameters.is_empty() || parameters.length() > 2 {
    raise InvalidPacket("SCTP RE-CONFIG must contain one or two parameters")
  }
  let writer = sctp_writer(64)
  for index = 0; index < parameters.length(); index = index + 1 {
    let parameter = encode_reconfig_parameter(parameters[index])
    writer.write_bytes(parameter)
    if index + 1 < parameters.length() {
      for padding = 0
          padding < padding_length(parameter.length())
          padding = padding + 1 {
        writer.write_u8(0)
      }
    }
  }
  writer.finish()
}

///|
fn decode_reconfig(
  flags : Byte,
  value : Bytes,
) -> Array[ReconfigParameter] raise SctpError {
  if flags != 0 || value.is_empty() {
    raise InvalidPacket("malformed SCTP RE-CONFIG chunk")
  }
  let reader = @codec.Reader::new(value)
  let parameters : Array[ReconfigParameter] = []
  while reader.remaining() > 0 {
    if parameters.length() >= 2 || reader.remaining() < 4 {
      raise InvalidPacket("invalid SCTP RE-CONFIG parameter count")
    }
    let before = reader.position()
    parameters.push(decode_reconfig_parameter(reader))
    let consumed = reader.position() - before
    let padding = padding_length(consumed)
    if padding <= reader.remaining() {
      let bytes = sctp_read_bytes(reader, padding, "SCTP RE-CONFIG padding")
      for byte in bytes {
        if byte != 0 {
          raise InvalidPacket("SCTP parameter padding must be zero")
        }
      }
    }
  }
  parameters
}

///|
fn encode_forward_tsn(forward : ForwardTsn) -> Bytes raise SctpError {
  let writer = sctp_writer(4 + forward.streams.length() * 4)
  writer.write_u32_be(forward.new_cumulative_tsn)
  for stream in forward.streams {
    writer.write_u16_be(stream.stream.value())
    writer.write_u16_be(stream.sequence)
  }
  writer.finish()
}

///|
fn decode_forward_tsn(
  flags : Byte,
  value : Bytes,
) -> ForwardTsn raise SctpError {
  if flags != 0 || value.length() < 4 || (value.length() - 4) % 4 != 0 {
    raise InvalidPacket("malformed SCTP FORWARD-TSN chunk")
  }
  let reader = @codec.Reader::new(value)
  let new_cumulative_tsn = sctp_read_u32(
    reader, "SCTP FORWARD-TSN cumulative TSN",
  )
  let streams : Array[ForwardTsnStream] = []
  while reader.remaining() > 0 {
    streams.push(
      ForwardTsnStream::new(
        stream=StreamId(
          sctp_read_u16(reader, "SCTP FORWARD-TSN stream identifier"),
        ),
        sequence=sctp_read_u16(reader, "SCTP FORWARD-TSN stream sequence"),
      ),
    )
  }
  ForwardTsn::new(new_cumulative_tsn~, streams~)
}

///|
fn chunk_wire_fields(chunk : Chunk) -> (Byte, Byte, Bytes) raise SctpError {
  match chunk {
    InitChunkValue(init) =>
      (if init.acknowledgement { 2 } else { 1 }, 0, encode_init(init))
    DataChunkValue(data) => {
      let (flags, value) = encode_data(data)
      (0, flags, value)
    }
    SackChunkValue(sack) => (3, 0, encode_sack(sack))
    HeartbeatChunk(value) => (4, 0, value)
    HeartbeatAckChunk(value) => (5, 0, value)
    AbortChunk(value) => (6, 0, value)
    ShutdownChunk(cumulative_tsn_ack) => {
      let writer = sctp_writer(4)
      writer.write_u32_be(cumulative_tsn_ack)
      (7, 0, writer.finish())
    }
    ShutdownAckChunk => (8, 0, b"")
    ErrorChunk(value) => (9, 0, value)
    CookieEchoChunk(value) => (10, 0, value)
    CookieAckChunk => (11, 0, b"")
    ShutdownCompleteChunk => (14, 0, b"")
    ReconfigChunk(parameters) => (130, 0, encode_reconfig(parameters))
    ForwardTsnChunk(forward) => (192, 0, encode_forward_tsn(forward))
    UnknownChunk(chunk_type, flags, value) => (chunk_type, flags, value)
  }
}

///|
fn encode_chunk(chunk : Chunk) -> Bytes raise SctpError {
  let (chunk_type, flags, value) = chunk_wire_fields(chunk)
  if value.length() > 0xfffb {
    raise InvalidPacket("SCTP chunk exceeds 65535 bytes")
  }
  let writer = sctp_writer(4 + value.length())
  writer.write_u8(chunk_type)
  writer.write_u8(flags)
  writer.write_u16_be((4 + value.length()).to_uint16())
  writer.write_bytes(value)
  writer.finish()
}

///|
fn decode_chunk(
  chunk_type : Byte,
  flags : Byte,
  value : Bytes,
) -> Chunk raise SctpError {
  match chunk_type {
    0 => DataChunkValue(decode_data(flags, value))
    1 => InitChunkValue(decode_init(false, flags, value))
    2 => InitChunkValue(decode_init(true, flags, value))
    3 => SackChunkValue(decode_sack(flags, value))
    4 => HeartbeatChunk(value)
    5 => HeartbeatAckChunk(value)
    6 => AbortChunk(value)
    7 => {
      if flags != 0 || value.length() != 4 {
        raise InvalidPacket("malformed SCTP SHUTDOWN chunk")
      }
      let reader = @codec.Reader::new(value)
      ShutdownChunk(sctp_read_u32(reader, "SCTP shutdown TSN"))
    }
    8 => {
      if flags != 0 || !value.is_empty() {
        raise InvalidPacket("malformed SCTP SHUTDOWN-ACK chunk")
      }
      ShutdownAckChunk
    }
    9 => ErrorChunk(value)
    10 => CookieEchoChunk(value)
    11 => {
      if flags != 0 || !value.is_empty() {
        raise InvalidPacket("malformed SCTP COOKIE-ACK chunk")
      }
      CookieAckChunk
    }
    14 => {
      if !value.is_empty() {
        raise InvalidPacket("malformed SCTP SHUTDOWN-COMPLETE chunk")
      }
      ShutdownCompleteChunk
    }
    130 => ReconfigChunk(decode_reconfig(flags, value))
    192 => ForwardTsnChunk(decode_forward_tsn(flags, value))
    _ => UnknownChunk(chunk_type, flags, value)
  }
}

///|
pub fn Packet::encode(self : Packet) -> Bytes raise SctpError {
  if self.source_port == 0 || self.destination_port == 0 {
    raise InvalidPacket("SCTP ports must be nonzero")
  }
  if self.chunks.any(chunk => {
      match chunk {
        InitChunkValue(init) => !init.acknowledgement
        _ => false
      }
    }) &&
    (self.chunks.length() != 1 || self.verification_tag != 0U) {
    raise InvalidPacket(
      "SCTP INIT must be unbundled with a zero verification tag",
    )
  }
  let writer = sctp_writer(256)
  writer.write_u16_be(self.source_port)
  writer.write_u16_be(self.destination_port)
  writer.write_u32_be(self.verification_tag)
  writer.write_u32_be(0)
  for chunk in self.chunks {
    let encoded = encode_chunk(chunk)
    writer.write_bytes(encoded)
    for padding = 0
        padding < padding_length(encoded.length())
        padding = padding + 1 {
      writer.write_u8(0)
    }
  }
  let bytes = writer.finish().to_array()
  let checksum = crc32c(Bytes::from_array(bytes))
  bytes[8] = checksum.to_byte()
  bytes[9] = (checksum >> 8).to_byte()
  bytes[10] = (checksum >> 16).to_byte()
  bytes[11] = (checksum >> 24).to_byte()
  Bytes::from_array(bytes)
}

///|
pub fn Packet::decode(raw : Bytes) -> Packet raise SctpError {
  if raw.length() < 12 {
    raise InvalidPacket("SCTP packet is shorter than its common header")
  }
  let their_checksum = raw[8].to_uint() |
    (raw[9].to_uint() << 8) |
    (raw[10].to_uint() << 16) |
    (raw[11].to_uint() << 24)
  if their_checksum != crc32c(raw) {
    raise ChecksumMismatch
  }
  let reader = @codec.Reader::new(raw)
  let source_port = sctp_read_u16(reader, "SCTP source port")
  let destination_port = sctp_read_u16(reader, "SCTP destination port")
  let verification_tag = sctp_read_u32(reader, "SCTP verification tag")
  ignore(sctp_read_u32(reader, "SCTP checksum"))
  if source_port == 0 || destination_port == 0 {
    raise InvalidPacket("SCTP ports must be nonzero")
  }
  let chunks : Array[Chunk] = []
  while reader.remaining() > 0 {
    if reader.remaining() < 4 {
      raise InvalidPacket("truncated SCTP chunk header")
    }
    let chunk_type = sctp_read_u8(reader, "SCTP chunk type")
    let flags = sctp_read_u8(reader, "SCTP chunk flags")
    let length = sctp_read_u16(reader, "SCTP chunk length").to_int()
    if length < 4 {
      raise InvalidPacket("SCTP chunk length is smaller than its header")
    }
    let value = sctp_read_bytes(reader, length - 4, "SCTP chunk value")
    chunks.push(decode_chunk(chunk_type, flags, value))
    let padding = padding_length(length)
    let padding_bytes = sctp_read_bytes(reader, padding, "SCTP chunk padding")
    for byte in padding_bytes {
      if byte != 0 {
        raise InvalidPacket("SCTP chunk padding must be zero")
      }
    }
  }
  if chunks.any(chunk => {
      match chunk {
        InitChunkValue(init) => !init.acknowledgement
        _ => false
      }
    }) &&
    (chunks.length() != 1 || verification_tag != 0U) {
    raise InvalidPacket(
      "SCTP INIT must be unbundled with a zero verification tag",
    )
  }
  { source_port, destination_port, verification_tag, chunks }
}
