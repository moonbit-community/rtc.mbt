///|
pub struct ResponseError {
  code : UInt16
  reason : String
} derive(Debug, Eq)

///|
pub fn ResponseError::new(
  code~ : UInt16,
  reason~ : String,
) -> ResponseError raise StunError {
  if code < 300 || code > 699 {
    raise InvalidMessage("STUN error code must be between 300 and 699")
  }
  let reason_length = @utf8.encode(reason).length()
  if reason_length > 763 {
    raise InvalidMessage("STUN error reason exceeds 763 bytes")
  }
  { code, reason, }
}

///|
pub fn ResponseError::code(self : ResponseError) -> UInt16 {
  self.code
}

///|
pub fn ResponseError::reason(self : ResponseError) -> String {
  self.reason
}

///|
pub fn ResponseError::with_default_reason(
  code : UInt16,
) -> ResponseError raise StunError {
  let reason = match code.to_uint() {
    300U => "Try Alternate"
    400U => "Bad Request"
    401U => "Unauthorized"
    403U => "Forbidden"
    420U => "Unknown Attribute"
    437U => "Allocation Mismatch"
    438U => "Stale Nonce"
    440U => "Address Family not Supported"
    441U => "Wrong Credentials"
    442U => "Unsupported Transport Protocol"
    443U => "Peer Address Family Mismatch"
    446U => "Connection Already Exists"
    447U => "Connection Timeout or Failure"
    486U => "Allocation Quota Reached"
    487U => "Role Conflict"
    500U => "Server Error"
    508U => "Insufficient Capacity"
    _ => raise InvalidMessage("STUN error code has no default reason")
  }
  ResponseError::new(code~, reason~)
}

///|
pub fn Attribute::from_error(
  error : ResponseError,
) -> Attribute raise StunError {
  let code = error.code.to_uint()
  let reason = @utf8.encode(error.reason)
  let value : Array[Byte] = [
    0,
    0,
    (code / 100U).to_byte(),
    (code % 100U).to_byte(),
  ]
  for byte in reason {
    value.push(byte)
  }
  Attribute::new(attribute_type=ErrorCode, value=Bytes::from_array(value))
}

///|
pub fn Attribute::to_error(self : Attribute) -> ResponseError raise StunError {
  if self.attribute_type != ErrorCode || self.value.length() < 4 {
    raise InvalidMessage("attribute does not contain a STUN error")
  }
  if self.value[0] != 0 || self.value[1] != 0 {
    raise InvalidMessage("STUN error reserved bits must be zero")
  }
  let class = self.value[2].to_uint()
  let number = self.value[3].to_uint()
  if class < 3U || class > 6U || number > 99U {
    raise InvalidMessage("invalid STUN error code")
  }
  let reason = @utf8.decode(self.value[4:].to_owned()) catch {
    Malformed(_) => raise InvalidMessage("STUN error reason is not valid UTF-8")
  }
  ResponseError::new(code=(class * 100U + number).to_uint16(), reason~)
}

///|
pub fn Attribute::from_unknown_attributes(
  types : Array[UInt16],
) -> Attribute raise StunError {
  let value : Array[Byte] = []
  for attribute_type in types {
    value.push((attribute_type >> 8).to_byte())
    value.push(attribute_type.to_byte())
  }
  Attribute::new(
    attribute_type=UnknownAttributes,
    value=Bytes::from_array(value),
  )
}

///|
pub fn Attribute::to_unknown_attributes(
  self : Attribute,
) -> Array[UInt16] raise StunError {
  if self.attribute_type != UnknownAttributes || self.value.length() % 2 != 0 {
    raise InvalidMessage("attribute does not contain unknown attribute types")
  }
  let result : Array[UInt16] = []
  for index = 0; index < self.value.length(); index = index + 2 {
    result.push(
      (self.value[index].to_uint16() << 8) | self.value[index + 1].to_uint16(),
    )
  }
  result
}

///|
pub fn Attribute::lifetime(seconds : UInt) -> Attribute raise StunError {
  Attribute::new(attribute_type=Lifetime, value=u32_bytes(seconds))
}

///|
pub fn Attribute::channel_number(channel : UInt16) -> Attribute raise StunError {
  if channel < 0x4000 || channel > 0x7fff {
    raise InvalidMessage("TURN channel number must be in 0x4000..0x7fff")
  }
  Attribute::new(
    attribute_type=ChannelNumber,
    value=Bytes::from_array([(channel >> 8).to_byte(), channel.to_byte(), 0, 0]),
  )
}

///|
pub fn Attribute::network_cost(
  network_id : UInt16,
  cost : UInt16,
) -> Attribute raise StunError {
  Attribute::new(
    attribute_type=NetworkCost,
    value=Bytes::from_array([
      (network_id >> 8).to_byte(),
      network_id.to_byte(),
      (cost >> 8).to_byte(),
      cost.to_byte(),
    ]),
  )
}

///|
pub fn Attribute::as_network_cost(
  self : Attribute,
) -> (UInt16, UInt16) raise StunError {
  if self.attribute_type != NetworkCost || self.value.length() != 4 {
    raise InvalidMessage("attribute does not contain ICE network cost")
  }
  (
    (self.value[0].to_uint16() << 8) | self.value[1].to_uint16(),
    (self.value[2].to_uint16() << 8) | self.value[3].to_uint16(),
  )
}

///|
pub fn Message::error_response(
  request : Message,
  error : ResponseError,
) -> Message raise StunError {
  Message::new(
    class=ErrorResponse,
    stun_method=request.stun_method,
    transaction_id=request.transaction_id,
    attributes=[Attribute::from_error(error)],
  )
}
