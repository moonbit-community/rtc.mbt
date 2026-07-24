///|
fn is_plain_address_type(attribute_type : AttributeType) -> Bool {
  match attribute_type {
    MappedAddress
    | AlternateServer
    | SourceAddress
    | ChangedAddress
    | ResponseOrigin
    | OtherAddress => true
    _ => false
  }
}

///|
fn is_xor_address_type(attribute_type : AttributeType) -> Bool {
  match attribute_type {
    XorMappedAddress | XorPeerAddress | XorRelayedAddress => true
    _ => false
  }
}

///|
fn encode_address_value(
  address : @transport.SocketAddress,
) -> Bytes raise StunError {
  let ip = address.address().to_bytes()
  let family : Byte = match ip.length() {
    4 => 1
    16 => 2
    length => raise InvalidMessage("invalid IP address length \{length}")
  }
  let port = address.port()
  let result : Array[Byte] = [0, family, (port >> 8).to_byte(), port.to_byte()]
  for byte in ip {
    result.push(byte)
  }
  Bytes::from_array(result)
}

///|
fn decode_ip(value : Bytes) -> @transport.IpAddress raise StunError {
  if value.length() != 8 && value.length() != 20 {
    raise InvalidMessage("STUN address must contain 8 or 20 bytes")
  }
  if value[0] != 0 {
    raise InvalidMessage("reserved STUN address byte must be zero")
  }
  match value[1] {
    1 if value.length() == 8 =>
      @transport.IpAddress::v4(value[4], value[5], value[6], value[7])
    2 if value.length() == 20 =>
      @transport.IpAddress::v6(value[4:20].to_owned()) catch {
        InvalidIpv6Length(length) =>
          raise InvalidMessage("invalid IPv6 address length \{length}")
        InvalidAddress(message) => raise InvalidMessage(message)
      }
    family =>
      raise InvalidMessage(
        "address family \{family} does not match its encoded length",
      )
  }
}

///|
fn decode_address_value(
  value : Bytes,
) -> @transport.SocketAddress raise StunError {
  let address = decode_ip(value)
  let port = (value[2].to_uint16() << 8) | value[3].to_uint16()
  @transport.SocketAddress::new(address~, port~)
}

///|
pub fn Attribute::from_address(
  address : @transport.SocketAddress,
  attribute_type? : AttributeType = MappedAddress,
) -> Attribute raise StunError {
  if !is_plain_address_type(attribute_type) {
    raise InvalidMessage("attribute type is not a plain STUN address")
  }
  Attribute::new(attribute_type~, value=encode_address_value(address))
}

///|
pub fn Attribute::to_address(
  self : Attribute,
) -> @transport.SocketAddress raise StunError {
  if !is_plain_address_type(self.attribute_type) {
    raise InvalidMessage("attribute type is not a plain STUN address")
  }
  decode_address_value(self.value)
}

///|
fn xor_address_value(
  value : Bytes,
  transaction_id : TransactionId,
) -> Bytes raise StunError {
  if value.length() != 8 && value.length() != 20 {
    raise InvalidMessage("STUN XOR address must contain 8 or 20 bytes")
  }
  let result = value.to_array()
  result[2] = result[2] ^ 0x21
  result[3] = result[3] ^ 0x12
  let mask : Array[Byte] = [0x21, 0x12, 0xa4, 0x42]
  for byte in transaction_id.as_bytes() {
    mask.push(byte)
  }
  for index = 4; index < result.length(); index = index + 1 {
    result[index] = result[index] ^ mask[index - 4]
  }
  Bytes::from_array(result)
}

///|
pub fn Attribute::from_xor_address(
  address : @transport.SocketAddress,
  transaction_id : TransactionId,
  attribute_type? : AttributeType = XorMappedAddress,
) -> Attribute raise StunError {
  if !is_xor_address_type(attribute_type) {
    raise InvalidMessage("attribute type is not a STUN XOR address")
  }
  Attribute::new(
    attribute_type~,
    value=xor_address_value(encode_address_value(address), transaction_id),
  )
}

///|
pub fn Attribute::to_xor_address(
  self : Attribute,
  transaction_id : TransactionId,
) -> @transport.SocketAddress raise StunError {
  if !is_xor_address_type(self.attribute_type) {
    raise InvalidMessage("attribute type is not a STUN XOR address")
  }
  decode_address_value(xor_address_value(self.value, transaction_id))
}
