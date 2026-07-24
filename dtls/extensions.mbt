///|
const EXT_SUPPORTED_GROUPS : UInt16 = 10

///|
const EXT_EC_POINT_FORMATS : UInt16 = 11

///|
const EXT_SIGNATURE_ALGORITHMS : UInt16 = 13

///|
const EXT_USE_SRTP : UInt16 = 14

///|
const EXT_EXTENDED_MASTER_SECRET : UInt16 = 23

///|
const EXT_RENEGOTIATION_INFO : UInt16 = 0xff01

///|
pub struct HelloExtensions {
  supported_groups : Array[UInt16]
  point_formats : Array[Byte]
  signature_algorithms : Array[UInt16]
  srtp_profiles : Array[UInt16]
  extended_master_secret : Bool
  renegotiation_info : Bool
  unknown : Array[(UInt16, Bytes)]
} derive(Debug, Eq)

///|
pub fn HelloExtensions::webrtc(
  srtp_profiles? : Array[SrtpProtectionProfile] = [],
) -> HelloExtensions {
  {
    supported_groups: [23, 29, 24],
    point_formats: [0],
    signature_algorithms: [0x0403, 0x0401],
    srtp_profiles: srtp_profiles.map(profile => profile.code()),
    extended_master_secret: true,
    renegotiation_info: true,
    unknown: [],
  }
}

///|
fn HelloExtensions::server(selected_srtp_profile : UInt16?) -> HelloExtensions {
  {
    supported_groups: [],
    point_formats: [0],
    signature_algorithms: [],
    srtp_profiles: match selected_srtp_profile {
      Some(profile) => [profile]
      None => []
    },
    extended_master_secret: true,
    renegotiation_info: true,
    unknown: [],
  }
}

///|
pub fn HelloExtensions::supports_group(
  self : HelloExtensions,
  group : UInt16,
) -> Bool {
  self.supported_groups.contains(group)
}

///|
pub fn HelloExtensions::signature_algorithms(
  self : HelloExtensions,
) -> Array[UInt16] {
  self.signature_algorithms.copy()
}

///|
pub fn HelloExtensions::srtp_profile_codes(
  self : HelloExtensions,
) -> Array[UInt16] {
  self.srtp_profiles.copy()
}

///|
pub fn HelloExtensions::uses_extended_master_secret(
  self : HelloExtensions,
) -> Bool {
  self.extended_master_secret
}

///|
fn hs_read_u8(reader : @codec.Reader, context : String) -> Byte raise DtlsError {
  reader.read_u8() catch {
    InvalidLength(length) =>
      raise InvalidHandshake("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidHandshake(
        "\{context}: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn hs_read_u16(
  reader : @codec.Reader,
  context : String,
) -> UInt16 raise DtlsError {
  reader.read_u16_be() catch {
    InvalidLength(length) =>
      raise InvalidHandshake("\{context}: invalid length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidHandshake(
        "\{context}: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn hs_read_u24(
  reader : @codec.Reader,
  context : String,
) -> UInt raise DtlsError {
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
fn hs_read_bytes(
  reader : @codec.Reader,
  length : Int,
  context : String,
) -> Bytes raise DtlsError {
  reader.read_bytes(length) catch {
    InvalidLength(invalid_length) =>
      raise InvalidHandshake("\{context}: invalid length \{invalid_length}")
    Truncated(needed~, remaining~) =>
      raise InvalidHandshake(
        "\{context}: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn write_extension(
  writer : @codec.Writer,
  extension_type : UInt16,
  value : Bytes,
) -> Unit raise DtlsError {
  if value.length() > 0xffff {
    raise InvalidHandshake("DTLS extension exceeds 65535 bytes")
  }
  writer.write_u16_be(extension_type)
  writer.write_u16_be(value.length().to_uint16())
  writer.write_bytes(value)
}

///|
fn u16_vector(values : Array[UInt16]) -> Bytes raise DtlsError {
  if values.length() > 0x7fff {
    raise InvalidHandshake("16-bit vector contains too many values")
  }
  let writer = dtls_writer(2 + values.length() * 2, "DTLS extension")
  writer.write_u16_be((values.length() * 2).to_uint16())
  for value in values {
    writer.write_u16_be(value)
  }
  writer.finish()
}

///|
fn HelloExtensions::encode(self : HelloExtensions) -> Bytes raise DtlsError {
  let body = dtls_writer(128, "DTLS extensions")
  if !self.supported_groups.is_empty() {
    write_extension(
      body,
      EXT_SUPPORTED_GROUPS,
      u16_vector(self.supported_groups),
    )
  }
  if !self.point_formats.is_empty() {
    if self.point_formats.length() > 0xff {
      raise InvalidHandshake("too many EC point formats")
    }
    let value = [self.point_formats.length().to_byte()]
    for point_format in self.point_formats {
      value.push(point_format)
    }
    write_extension(body, EXT_EC_POINT_FORMATS, Bytes::from_array(value))
  }
  if !self.signature_algorithms.is_empty() {
    write_extension(
      body,
      EXT_SIGNATURE_ALGORITHMS,
      u16_vector(self.signature_algorithms),
    )
  }
  if !self.srtp_profiles.is_empty() {
    let value = u16_vector(self.srtp_profiles).to_array()
    value.push(0)
    write_extension(body, EXT_USE_SRTP, Bytes::from_array(value))
  }
  if self.extended_master_secret {
    write_extension(body, EXT_EXTENDED_MASTER_SECRET, b"")
  }
  if self.renegotiation_info {
    write_extension(body, EXT_RENEGOTIATION_INFO, b"\x00")
  }
  for extension in self.unknown {
    let (extension_type, value) = extension
    write_extension(body, extension_type, value)
  }
  let body = body.finish()
  if body.length() > 0xffff {
    raise InvalidHandshake("DTLS extension block exceeds 65535 bytes")
  }
  let writer = dtls_writer(body.length() + 2, "DTLS extensions")
  writer.write_u16_be(body.length().to_uint16())
  writer.write_bytes(body)
  writer.finish()
}

///|
fn parse_u16_vector(
  value : Bytes,
  context : String,
) -> Array[UInt16] raise DtlsError {
  let reader = @codec.Reader::new(value)
  let byte_length = hs_read_u16(reader, context).to_int()
  if byte_length % 2 != 0 || byte_length != reader.remaining() {
    raise InvalidHandshake("\{context}: malformed 16-bit vector")
  }
  let values : Array[UInt16] = []
  while reader.remaining() > 0 {
    values.push(hs_read_u16(reader, context))
  }
  values
}

///|
fn parse_use_srtp(value : Bytes) -> Array[UInt16] raise DtlsError {
  let reader = @codec.Reader::new(value)
  let profile_bytes = hs_read_u16(reader, "use_srtp profiles").to_int()
  if profile_bytes == 0 ||
    profile_bytes % 2 != 0 ||
    reader.remaining() < profile_bytes + 1 {
    raise InvalidHandshake("malformed use_srtp profile vector")
  }
  let profiles : Array[UInt16] = []
  for offset = 0; offset < profile_bytes; offset = offset + 2 {
    profiles.push(hs_read_u16(reader, "use_srtp profile"))
  }
  let mki_length = hs_read_u8(reader, "use_srtp MKI").to_int()
  ignore(hs_read_bytes(reader, mki_length, "use_srtp MKI"))
  if reader.remaining() != 0 || mki_length != 0 {
    raise InvalidHandshake("WebRTC use_srtp requires an empty MKI")
  }
  profiles
}

///|
fn HelloExtensions::decode(encoded : Bytes) -> HelloExtensions raise DtlsError {
  let reader = @codec.Reader::new(encoded)
  let declared_length = hs_read_u16(reader, "DTLS extensions").to_int()
  if declared_length != reader.remaining() {
    raise InvalidHandshake("DTLS extension block length mismatch")
  }
  let mut supported_groups : Array[UInt16] = []
  let mut point_formats : Array[Byte] = []
  let mut signature_algorithms : Array[UInt16] = []
  let mut srtp_profiles : Array[UInt16] = []
  let mut extended_master_secret = false
  let mut renegotiation_info = false
  let unknown : Array[(UInt16, Bytes)] = []
  let seen : Map[UInt16, Bool] = Map([])
  while reader.remaining() > 0 {
    let extension_type = hs_read_u16(reader, "DTLS extension type")
    let length = hs_read_u16(reader, "DTLS extension length").to_int()
    let value = hs_read_bytes(reader, length, "DTLS extension value")
    if seen.contains(extension_type) {
      raise InvalidHandshake("duplicate DTLS extension \{extension_type}")
    }
    seen[extension_type] = true
    match extension_type {
      EXT_SUPPORTED_GROUPS =>
        supported_groups = parse_u16_vector(value, "supported_groups")
      EXT_EC_POINT_FORMATS => {
        let value_reader = @codec.Reader::new(value)
        let count = hs_read_u8(value_reader, "EC point formats").to_int()
        if count != value_reader.remaining() {
          raise InvalidHandshake("malformed EC point-format vector")
        }
        point_formats = hs_read_bytes(value_reader, count, "EC point formats").to_array()
      }
      EXT_SIGNATURE_ALGORITHMS =>
        signature_algorithms = parse_u16_vector(value, "signature_algorithms")
      EXT_USE_SRTP => srtp_profiles = parse_use_srtp(value)
      EXT_EXTENDED_MASTER_SECRET => {
        if !value.is_empty() {
          raise InvalidHandshake(
            "extended_master_secret extension must be empty",
          )
        }
        extended_master_secret = true
      }
      EXT_RENEGOTIATION_INFO => {
        if value != b"\x00" {
          raise InvalidHandshake("initial renegotiation_info must be empty")
        }
        renegotiation_info = true
      }
      _ => unknown.push((extension_type, value))
    }
  }
  {
    supported_groups,
    point_formats,
    signature_algorithms,
    srtp_profiles,
    extended_master_secret,
    renegotiation_info,
    unknown,
  }
}
