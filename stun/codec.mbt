///|
const MAGIC_COOKIE : UInt = 0x2112a442U

///|
const HEADER_LENGTH : Int = 20

///|
fn Method::code(self : Method) -> UInt16 {
  match self {
    Binding => 0x001
    Allocate => 0x003
    Refresh => 0x004
    Send => 0x006
    Data => 0x007
    CreatePermission => 0x008
    ChannelBind => 0x009
    Unknown(code) => code
  }
}

///|
fn Method::from_code(code : UInt16) -> Method {
  match code.to_uint() {
    0x001U => Binding
    0x003U => Allocate
    0x004U => Refresh
    0x006U => Send
    0x007U => Data
    0x008U => CreatePermission
    0x009U => ChannelBind
    _ => Unknown(code)
  }
}

///|
fn MessageClass::code(self : MessageClass) -> UInt {
  match self {
    Request => 0U
    Indication => 1U
    SuccessResponse => 2U
    ErrorResponse => 3U
  }
}

///|
fn MessageClass::from_code(code : UInt) -> MessageClass {
  match code {
    0U => Request
    1U => Indication
    2U => SuccessResponse
    _ => ErrorResponse
  }
}

///|
fn encode_message_type(stun_method : Method, class : MessageClass) -> UInt16 {
  let method_code = stun_method.code().to_uint()
  let class_code = class.code()
  ((method_code & 0x000fU) |
  ((method_code & 0x0070U) << 1) |
  ((method_code & 0x0f80U) << 2) |
  ((class_code & 0x01U) << 4) |
  ((class_code & 0x02U) << 7)).to_uint16()
}

///|
fn decode_message_type(
  encoded : UInt16,
) -> (Method, MessageClass) raise StunError {
  let encoded = encoded.to_uint()
  if (encoded & 0xc000U) != 0U {
    raise InvalidMessage("the two most-significant STUN type bits must be zero")
  }
  let method_code = ((encoded & 0x000fU) |
  ((encoded & 0x00e0U) >> 1) |
  ((encoded & 0x3e00U) >> 2)).to_uint16()
  let class_code = ((encoded >> 4) & 0x01U) | ((encoded >> 7) & 0x02U)
  (Method::from_code(method_code), MessageClass::from_code(class_code))
}

///|
fn read_u16(reader : @codec.Reader) -> UInt16 raise StunError {
  reader.read_u16_be() catch {
    InvalidLength(length) =>
      raise InvalidMessage("invalid codec length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidMessage(
        "truncated STUN message: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn read_u32(reader : @codec.Reader) -> UInt raise StunError {
  reader.read_u32_be() catch {
    InvalidLength(length) =>
      raise InvalidMessage("invalid codec length \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidMessage(
        "truncated STUN message: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn read_bytes(reader : @codec.Reader, length : Int) -> Bytes raise StunError {
  reader.read_bytes(length) catch {
    InvalidLength(invalid_length) =>
      raise InvalidMessage("invalid codec length \{invalid_length}")
    Truncated(needed~, remaining~) =>
      raise InvalidMessage(
        "truncated STUN message: need \{needed} bytes, have \{remaining}",
      )
  }
}

///|
fn new_writer(capacity : Int) -> @codec.Writer raise StunError {
  @codec.Writer::new(capacity~) catch {
    InvalidLength(length) =>
      raise InvalidMessage("invalid codec capacity \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidMessage(
        "unexpected codec truncation: need \{needed}, have \{remaining}",
      )
  }
}

///|
fn Attribute::wire_length(self : Attribute) -> Int raise StunError {
  validate_attribute(self.attribute_type, self.value)
  let expected_padding = padding_length(self.value.length())
  if self.padding.length() != expected_padding {
    raise InvalidMessage("attribute padding has invalid length")
  }
  4 + self.value.length() + self.padding.length()
}

///|
fn Message::body_length(
  self : Message,
  attribute_count : Int,
) -> Int raise StunError {
  if attribute_count < 0 || attribute_count > self.attributes.length() {
    raise InvalidMessage("attribute count is out of bounds")
  }
  let mut result = 0
  for index = 0; index < attribute_count; index = index + 1 {
    result += self.attributes[index].wire_length()
    if result > 0xffff {
      raise InvalidMessage("STUN message body exceeds 65535 bytes")
    }
  }
  result
}

///|
fn Message::encode_prefix(
  self : Message,
  attribute_count : Int,
  declared_body_length : Int,
) -> Bytes raise StunError {
  if declared_body_length < 0 ||
    declared_body_length > 0xffff ||
    declared_body_length % 4 != 0 {
    raise InvalidMessage("invalid declared STUN body length")
  }
  let actual_body_length = self.body_length(attribute_count)
  let writer = new_writer(HEADER_LENGTH + actual_body_length)
  writer.write_u16_be(encode_message_type(self.stun_method, self.class))
  writer.write_u16_be(declared_body_length.to_uint16())
  writer.write_u32_be(MAGIC_COOKIE)
  writer.write_bytes(self.transaction_id.as_bytes())
  for index = 0; index < attribute_count; index = index + 1 {
    let attribute = self.attributes[index]
    writer.write_u16_be(attribute.attribute_type.code())
    writer.write_u16_be(attribute.value.length().to_uint16())
    writer.write_bytes(attribute.value)
    writer.write_bytes(attribute.padding)
  }
  writer.finish()
}

///|
pub fn Message::encode(self : Message) -> Bytes raise StunError {
  let body_length = self.body_length(self.attributes.length())
  self.encode_prefix(self.attributes.length(), body_length)
}

///|
pub fn Message::is_stun(data : Bytes) -> Bool {
  if data.length() < HEADER_LENGTH || (data[0].to_uint() & 0xc0U) != 0U {
    return false
  }
  let body_length = ((data[2].to_uint() << 8) | data[3].to_uint()).reinterpret_as_int()
  if body_length % 4 != 0 || data.length() != HEADER_LENGTH + body_length {
    return false
  }
  let cookie = (data[4].to_uint() << 24) |
    (data[5].to_uint() << 16) |
    (data[6].to_uint() << 8) |
    data[7].to_uint()
  cookie == MAGIC_COOKIE
}

///|
pub fn Message::decode(data : Bytes) -> Message raise StunError {
  if data.length() < HEADER_LENGTH {
    raise InvalidMessage("STUN message is shorter than its 20-byte header")
  }
  let reader = @codec.Reader::new(data)
  let encoded_type = read_u16(reader)
  let body_length = read_u16(reader).to_int()
  let cookie = read_u32(reader)
  let transaction_id = TransactionId::from_bytes(read_bytes(reader, 12))
  let (stun_method, class) = decode_message_type(encoded_type)
  if cookie != MAGIC_COOKIE {
    raise InvalidMessage("invalid STUN magic cookie")
  }
  if body_length % 4 != 0 {
    raise InvalidMessage("STUN body length must be a multiple of four")
  }
  if data.length() != HEADER_LENGTH + body_length {
    raise InvalidMessage("STUN body length does not match the datagram length")
  }
  let attributes : Array[Attribute] = []
  while reader.remaining() > 0 {
    if reader.remaining() < 4 {
      raise InvalidMessage("truncated STUN attribute header")
    }
    let attribute_type = AttributeType::from_code(read_u16(reader))
    let value_length = read_u16(reader).to_int()
    let value = read_bytes(reader, value_length)
    let padding = read_bytes(reader, padding_length(value_length))
    attributes.push(Attribute::from_wire(attribute_type, value, padding))
  }
  Message::new(class~, stun_method~, transaction_id~, attributes~)
}
