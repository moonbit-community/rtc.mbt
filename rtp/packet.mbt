///|
const RTP_FIXED_HEADER_LENGTH : Int = 12

///|
fn rtp_read_u16(data : Bytes, offset : Int) -> UInt16 raise RtpError {
  if offset < 0 || offset + 2 > data.length() {
    raise InvalidPacket("truncated RTP 16-bit field")
  }
  ((data[offset].to_uint() << 8) | data[offset + 1].to_uint()).to_uint16()
}

///|
fn rtp_read_u32(data : Bytes, offset : Int) -> UInt raise RtpError {
  if offset < 0 || offset + 4 > data.length() {
    raise InvalidPacket("truncated RTP 32-bit field")
  }
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn rtp_write_u16(output : Array[Byte], value : UInt16) -> Unit {
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn rtp_write_u32(output : Array[Byte], value : UInt) -> Unit {
  output.push((value >> 24).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn one_byte_extensions(extensions : Array[HeaderExtension]) -> Bool {
  extensions.all(extension => {
    extension.id >= 1 &&
    extension.id <= 14 &&
    extension.payload.length() >= 1 &&
    extension.payload.length() <= 16
  })
}

///|
fn encode_extensions(
  extensions : Array[HeaderExtension],
) -> (UInt16, Bytes) raise RtpError {
  if extensions.is_empty() {
    return (0, b"")
  }
  let body : Array[Byte] = []
  let use_one_byte = one_byte_extensions(extensions)
  let profile : UInt16 = if use_one_byte { 0xbede } else { 0x1000 }
  if use_one_byte {
    for extension in extensions {
      body.push(
        ((extension.id.to_uint() << 4) |
        (extension.payload.length() - 1).reinterpret_as_uint()).to_byte(),
      )
      for byte in extension.payload {
        body.push(byte)
      }
    }
  } else {
    for extension in extensions {
      if extension.id == 0 {
        raise InvalidExtension("RTP extension id zero is reserved")
      }
      if extension.payload.length() > 255 {
        raise InvalidExtension("RTP extension payload exceeds 255 bytes")
      }
      body.push(extension.id)
      body.push(extension.payload.length().to_byte())
      for byte in extension.payload {
        body.push(byte)
      }
    }
  }
  while body.length() % 4 != 0 {
    body.push(0)
  }
  (profile, Bytes::from_array(body))
}

///|
fn decode_one_byte_extensions(
  body : Bytes,
) -> Array[HeaderExtension] raise RtpError {
  let extensions : Array[HeaderExtension] = []
  let mut offset = 0
  while offset < body.length() {
    let descriptor = body[offset]
    offset += 1
    if descriptor == 0 {
      continue
    }
    let id = descriptor >> 4
    if id == 15 {
      for byte in body[offset:] {
        if byte != 0 {
          raise InvalidExtension(
            "non-padding data follows the reserved RTP extension id",
          )
        }
      }
      break
    }
    let length = (descriptor & 0x0f).to_int() + 1
    if offset + length > body.length() {
      raise InvalidExtension("truncated one-byte RTP header extension")
    }
    extensions.push({ id, payload: body[offset:offset + length].to_owned(), })
    offset += length
  }
  extensions
}

///|
fn decode_two_byte_extensions(
  body : Bytes,
) -> Array[HeaderExtension] raise RtpError {
  let extensions : Array[HeaderExtension] = []
  let mut offset = 0
  while offset < body.length() {
    let id = body[offset]
    offset += 1
    if id == 0 {
      continue
    }
    if offset >= body.length() {
      raise InvalidExtension("truncated two-byte RTP extension header")
    }
    let length = body[offset].to_int()
    offset += 1
    if offset + length > body.length() {
      raise InvalidExtension("truncated two-byte RTP extension payload")
    }
    extensions.push({ id, payload: body[offset:offset + length].to_owned(), })
    offset += length
  }
  extensions
}

///|
pub fn Packet::unmarshal(data : Bytes) -> Packet raise RtpError {
  if data.length() < RTP_FIXED_HEADER_LENGTH {
    raise InvalidPacket("RTP packet is shorter than its fixed header")
  }
  let first = data[0]
  if first >> 6 != 2 {
    raise InvalidPacket("unsupported RTP version")
  }
  let padding = (first & 0x20) != 0
  let has_extensions = (first & 0x10) != 0
  let csrc_count = (first & 0x0f).to_int()
  let header_without_extensions = RTP_FIXED_HEADER_LENGTH + csrc_count * 4
  if header_without_extensions > data.length() {
    raise InvalidPacket("truncated RTP CSRC list")
  }
  let second = data[1]
  let marker = (second & 0x80) != 0
  let payload_type = second & 0x7f
  let sequence_number = rtp_read_u16(data, 2)
  let timestamp = rtp_read_u32(data, 4)
  let ssrc = rtp_read_u32(data, 8)
  let csrc : Array[UInt] = []
  let mut offset = RTP_FIXED_HEADER_LENGTH
  for index = 0; index < csrc_count; index = index + 1 {
    csrc.push(rtp_read_u32(data, offset))
    offset += 4
  }
  let extensions : Array[HeaderExtension] = []
  if has_extensions {
    if offset + 4 > data.length() {
      raise InvalidExtension("truncated RTP extension preamble")
    }
    let profile = rtp_read_u16(data, offset)
    let word_count = rtp_read_u16(data, offset + 2).to_int()
    offset += 4
    let extension_length = word_count * 4
    if offset + extension_length > data.length() {
      raise InvalidExtension("RTP extension length exceeds packet")
    }
    let body = data[offset:offset + extension_length].to_owned()
    let decoded = if profile == 0xbede {
      decode_one_byte_extensions(body)
    } else if (profile & 0xfff0) == 0x1000 {
      decode_two_byte_extensions(body)
    } else {
      raise InvalidExtension("unsupported RTP extension profile \{profile}")
    }
    for extension in decoded {
      extensions.push(extension)
    }
    offset += extension_length
  }
  let mut payload_end = data.length()
  if padding {
    if payload_end == offset {
      raise InvalidPacket("RTP padding flag is set without payload")
    }
    let padding_length = data[payload_end - 1].to_int()
    if padding_length == 0 || padding_length > payload_end - offset {
      raise InvalidPacket("invalid RTP padding length")
    }
    payload_end -= padding_length
  }
  Packet::new(
    marker~,
    payload_type~,
    sequence_number~,
    timestamp~,
    ssrc~,
    csrc~,
    extensions~,
    payload=data[offset:payload_end].to_owned(),
  )
}

///|
pub fn Packet::decode(data : Bytes) -> Packet raise RtpError {
  Packet::unmarshal(data)
}

///|
pub fn Packet::marshal(self : Packet) -> Bytes raise RtpError {
  if self.payload_type > 127 {
    raise InvalidPacket("RTP payload type must fit in seven bits")
  }
  if self.csrc.length() > 15 {
    raise InvalidPacket("RTP header contains more than 15 CSRC entries")
  }
  let (profile, extension_body) = encode_extensions(self.extensions)
  let extension_length = if self.extensions.is_empty() {
    0
  } else {
    4 + extension_body.length()
  }
  let total_length = RTP_FIXED_HEADER_LENGTH +
    self.csrc.length() * 4 +
    extension_length +
    self.payload.length()
  if total_length > 0xffff {
    raise PayloadTooLarge(self.payload.length())
  }
  let output : Array[Byte] = Array(capacity=total_length)
  output.push(
    (0x80 |
    (if self.extensions.is_empty() { 0 } else { 0x10 }) |
    self.csrc.length()).to_byte(),
  )
  output.push(
    ((if self.marker { 0x80 } else { 0 }) | self.payload_type.to_int()).to_byte(),
  )
  rtp_write_u16(output, self.sequence_number)
  rtp_write_u32(output, self.timestamp)
  rtp_write_u32(output, self.ssrc)
  for source in self.csrc {
    rtp_write_u32(output, source)
  }
  if !self.extensions.is_empty() {
    rtp_write_u16(output, profile)
    rtp_write_u16(output, (extension_body.length() / 4).to_uint16())
    for byte in extension_body {
      output.push(byte)
    }
  }
  for byte in self.payload {
    output.push(byte)
  }
  Bytes::from_array(output)
}

///|
pub fn Packet::encode(self : Packet) -> Bytes raise RtpError {
  self.marshal()
}

///|
pub fn Packet::header_size(self : Packet) -> Int raise RtpError {
  let (_, extension_body) = encode_extensions(self.extensions)
  RTP_FIXED_HEADER_LENGTH +
  self.csrc.length() * 4 +
  (if self.extensions.is_empty() { 0 } else { 4 + extension_body.length() })
}

///|
pub fn Packet::marshal_size(self : Packet) -> Int raise RtpError {
  self.header_size() + self.payload.length()
}
