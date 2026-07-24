///|
const RECORD_HEADER_LENGTH : Int = 13

///|
const HANDSHAKE_HEADER_LENGTH : Int = 12

///|
fn dtls_writer(
  capacity : Int,
  context : String,
) -> @codec.Writer raise DtlsError {
  @codec.Writer::new(capacity~) catch {
    InvalidLength(length) =>
      raise InvalidRecord("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidRecord(
        "\{context}: unexpected truncation \{needed}/\{remaining}",
      )
  }
}

///|
fn read_u8(reader : @codec.Reader, context : String) -> Byte raise DtlsError {
  reader.read_u8() catch {
    InvalidLength(length) =>
      raise InvalidRecord("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidRecord("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn read_u16(reader : @codec.Reader, context : String) -> UInt16 raise DtlsError {
  reader.read_u16_be() catch {
    InvalidLength(length) =>
      raise InvalidRecord("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidRecord("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn read_u24(reader : @codec.Reader, context : String) -> UInt raise DtlsError {
  reader.read_u24_be() catch {
    InvalidLength(length) =>
      raise InvalidHandshake("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidHandshake(
        "\{context}: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn read_u32(reader : @codec.Reader, context : String) -> UInt raise DtlsError {
  reader.read_u32_be() catch {
    InvalidLength(length) =>
      raise InvalidRecord("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidRecord("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn read_bytes(
  reader : @codec.Reader,
  length : Int,
  context : String,
) -> Bytes raise DtlsError {
  reader.read_bytes(length) catch {
    InvalidLength(invalid_length) =>
      raise InvalidRecord("\{context}: invalid length \{invalid_length}")
    Truncated(needed~, remaining~) =>
      raise InvalidRecord("\{context}: need \{needed} bytes, have \{remaining}")
  }
}

///|
fn ContentType::from_code(code : Byte) -> ContentType raise DtlsError {
  match code {
    20 => ChangeCipherSpec
    21 => Alert
    22 => Handshake
    23 => ApplicationData
    _ => raise InvalidRecord("unknown DTLS content type \{code}")
  }
}

///|
fn ProtocolVersion::from_bytes(
  major : Byte,
  minor : Byte,
) -> ProtocolVersion raise DtlsError {
  match (major, minor) {
    (0xfe, 0xff) => Dtls10
    (0xfe, 0xfd) => Dtls12
    _ => raise UnsupportedVersion
  }
}

///|
fn HandshakeType::from_code(code : Byte) -> HandshakeType {
  match code {
    0 => HelloRequest
    1 => ClientHello
    2 => ServerHello
    3 => HelloVerifyRequest
    11 => Certificate
    12 => ServerKeyExchange
    13 => CertificateRequest
    14 => ServerHelloDone
    15 => CertificateVerify
    16 => ClientKeyExchange
    20 => Finished
    _ => UnknownHandshake(code)
  }
}

///|
fn RecordHeader::encode_into(
  self : RecordHeader,
  writer : @codec.Writer,
) -> Unit {
  writer.write_u8(self.content_type.code())
  writer.write_u8(self.version.major())
  writer.write_u8(self.version.minor())
  writer.write_u16_be(self.epoch)
  writer.write_u16_be((self.sequence_number >> 32).to_uint16())
  writer.write_u32_be(self.sequence_number.to_uint())
  writer.write_u16_be(self.content_length)
}

///|
pub fn Record::encode(self : Record) -> Bytes raise DtlsError {
  if self.payload.length() != self.header.content_length.to_int() {
    raise InvalidRecord("DTLS record header length does not match payload")
  }
  let writer = dtls_writer(
    RECORD_HEADER_LENGTH + self.payload.length(),
    "DTLS record",
  )
  self.header.encode_into(writer)
  writer.write_bytes(self.payload)
  writer.finish()
}

///|
fn decode_record(reader : @codec.Reader) -> Record raise DtlsError {
  let content_type = ContentType::from_code(
    read_u8(reader, "DTLS record content type"),
  )
  let major = read_u8(reader, "DTLS record version")
  let minor = read_u8(reader, "DTLS record version")
  let version = ProtocolVersion::from_bytes(major, minor)
  let epoch = read_u16(reader, "DTLS record epoch")
  let sequence_number = (
      read_u16(reader, "DTLS record sequence").to_uint64() << 32
    ) |
    read_u32(reader, "DTLS record sequence").to_uint64()
  let content_length = read_u16(reader, "DTLS record length")
  let payload = read_bytes(
    reader,
    content_length.to_int(),
    "DTLS record payload",
  )
  {
    header: RecordHeader::new(
      content_type~,
      version~,
      epoch~,
      sequence_number~,
      content_length~,
    ),
    payload,
  }
}

///|
pub fn decode_records(datagram : Bytes) -> Array[Record] raise DtlsError {
  if datagram.is_empty() {
    raise InvalidRecord("empty DTLS datagram")
  }
  let reader = @codec.Reader::new(datagram)
  let records : Array[Record] = []
  while reader.remaining() > 0 {
    if reader.remaining() < RECORD_HEADER_LENGTH {
      raise InvalidRecord("truncated DTLS record header")
    }
    records.push(decode_record(reader))
  }
  records
}

///|
pub fn encode_records(records : Array[Record]) -> Bytes raise DtlsError {
  if records.is_empty() {
    raise InvalidRecord("cannot encode an empty DTLS datagram")
  }
  let encoded : Array[Bytes] = []
  let mut total_length = 0
  for record in records {
    let bytes = record.encode()
    total_length += bytes.length()
    encoded.push(bytes)
  }
  let writer = dtls_writer(total_length, "DTLS datagram")
  for bytes in encoded {
    writer.write_bytes(bytes)
  }
  writer.finish()
}

///|
pub fn HandshakeFragment::encode(
  self : HandshakeFragment,
) -> Bytes raise DtlsError {
  let writer = dtls_writer(
    HANDSHAKE_HEADER_LENGTH + self.body.length(),
    "DTLS handshake",
  )
  writer.write_u8(self.handshake_type.code())
  writer.write_u24_be(self.total_length)
  writer.write_u16_be(self.message_sequence)
  writer.write_u24_be(self.fragment_offset)
  writer.write_u24_be(self.body.length().reinterpret_as_uint())
  writer.write_bytes(self.body)
  writer.finish()
}

///|
fn decode_handshake(
  reader : @codec.Reader,
) -> HandshakeFragment raise DtlsError {
  let handshake_type = HandshakeType::from_code(
    read_u8(reader, "DTLS handshake type"),
  )
  let total_length = read_u24(reader, "DTLS handshake length")
  let message_sequence = read_u16(reader, "DTLS handshake sequence")
  let fragment_offset = read_u24(reader, "DTLS handshake fragment offset")
  let fragment_length = read_u24(reader, "DTLS handshake fragment length")
  let body = read_bytes(
    reader,
    fragment_length.reinterpret_as_int(),
    "DTLS handshake fragment",
  ) catch {
    InvalidRecord(message) => raise InvalidHandshake(message)
    error => raise error
  }
  HandshakeFragment::new(
    handshake_type~,
    total_length~,
    message_sequence~,
    fragment_offset~,
    body~,
  )
}

///|
pub fn decode_handshakes(
  payload : Bytes,
) -> Array[HandshakeFragment] raise DtlsError {
  if payload.is_empty() {
    raise InvalidHandshake("empty DTLS handshake record")
  }
  let reader = @codec.Reader::new(payload)
  let handshakes : Array[HandshakeFragment] = []
  while reader.remaining() > 0 {
    if reader.remaining() < HANDSHAKE_HEADER_LENGTH {
      raise InvalidHandshake("truncated DTLS handshake header")
    }
    handshakes.push(decode_handshake(reader))
  }
  handshakes
}
