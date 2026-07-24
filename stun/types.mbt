///|
pub(all) suberror StunError {
  InvalidMessage(String)
  IntegrityFailure
  UnknownRequiredAttribute(UInt16)
  TransactionTimedOut
  AgentClosed
  TransactionAlreadyExists
  TransactionNotFound
  CryptoUnavailable(String)
} derive(Debug, Eq)

///|
pub(all) enum MessageClass {
  Request
  Indication
  SuccessResponse
  ErrorResponse
} derive(Debug, Eq)

///|
pub(all) enum Method {
  Binding
  Allocate
  Refresh
  Send
  Data
  CreatePermission
  ChannelBind
  Unknown(UInt16)
} derive(Debug, Eq)

///|
pub(all) enum AttributeType {
  MappedAddress
  ChangeRequest
  SourceAddress
  ChangedAddress
  Username
  MessageIntegrity
  ErrorCode
  UnknownAttributes
  ChannelNumber
  Lifetime
  XorPeerAddress
  DataAttribute
  Realm
  Nonce
  XorRelayedAddress
  RequestedAddressFamily
  EvenPort
  RequestedTransport
  DontFragment
  MessageIntegritySha256
  PasswordAlgorithm
  Userhash
  XorMappedAddress
  ReservationToken
  Priority
  UseCandidate
  PaddingAttribute
  ResponsePort
  ConnectionId
  PasswordAlgorithms
  AlternateDomain
  Software
  AlternateServer
  CacheTimeout
  Fingerprint
  IceControlled
  IceControlling
  ResponseOrigin
  OtherAddress
  Origin
  NetworkCost
  UnknownAttribute(UInt16)
} derive(Debug, Eq)

///|
pub fn AttributeType::from_code(code : UInt16) -> AttributeType {
  match code.to_uint() {
    0x0001U => MappedAddress
    0x0003U => ChangeRequest
    0x0004U => SourceAddress
    0x0005U => ChangedAddress
    0x0006U => Username
    0x0008U => MessageIntegrity
    0x0009U => ErrorCode
    0x000aU => UnknownAttributes
    0x000cU => ChannelNumber
    0x000dU => Lifetime
    0x0012U => XorPeerAddress
    0x0013U => DataAttribute
    0x0014U => Realm
    0x0015U => Nonce
    0x0016U => XorRelayedAddress
    0x0017U => RequestedAddressFamily
    0x0018U => EvenPort
    0x0019U => RequestedTransport
    0x001aU => DontFragment
    0x001cU => MessageIntegritySha256
    0x001dU => PasswordAlgorithm
    0x001eU => Userhash
    0x0020U => XorMappedAddress
    0x0022U => ReservationToken
    0x0024U => Priority
    0x0025U => UseCandidate
    0x0026U => PaddingAttribute
    0x0027U => ResponsePort
    0x002aU => ConnectionId
    0x8002U => PasswordAlgorithms
    0x8003U => AlternateDomain
    0x8022U => Software
    0x8023U => AlternateServer
    0x8027U => CacheTimeout
    0x8028U => Fingerprint
    0x8029U => IceControlled
    0x802aU => IceControlling
    0x802bU => ResponseOrigin
    0x802cU => OtherAddress
    0x802fU => Origin
    0xc057U => NetworkCost
    _ => UnknownAttribute(code)
  }
}

///|
pub fn AttributeType::code(self : AttributeType) -> UInt16 {
  match self {
    MappedAddress => 0x0001
    ChangeRequest => 0x0003
    SourceAddress => 0x0004
    ChangedAddress => 0x0005
    Username => 0x0006
    MessageIntegrity => 0x0008
    ErrorCode => 0x0009
    UnknownAttributes => 0x000a
    ChannelNumber => 0x000c
    Lifetime => 0x000d
    XorPeerAddress => 0x0012
    DataAttribute => 0x0013
    Realm => 0x0014
    Nonce => 0x0015
    XorRelayedAddress => 0x0016
    RequestedAddressFamily => 0x0017
    EvenPort => 0x0018
    RequestedTransport => 0x0019
    DontFragment => 0x001a
    MessageIntegritySha256 => 0x001c
    PasswordAlgorithm => 0x001d
    Userhash => 0x001e
    XorMappedAddress => 0x0020
    ReservationToken => 0x0022
    Priority => 0x0024
    UseCandidate => 0x0025
    PaddingAttribute => 0x0026
    ResponsePort => 0x0027
    ConnectionId => 0x002a
    PasswordAlgorithms => 0x8002
    AlternateDomain => 0x8003
    Software => 0x8022
    AlternateServer => 0x8023
    CacheTimeout => 0x8027
    Fingerprint => 0x8028
    IceControlled => 0x8029
    IceControlling => 0x802a
    ResponseOrigin => 0x802b
    OtherAddress => 0x802c
    Origin => 0x802f
    NetworkCost => 0xc057
    UnknownAttribute(code) => code
  }
}

///|
pub fn AttributeType::is_comprehension_required(self : AttributeType) -> Bool {
  self.code().to_uint() < 0x8000U
}

///|
pub struct Attribute {
  attribute_type : AttributeType
  value : Bytes
  padding : Bytes
} derive(Debug, Eq)

///|
fn padding_length(value_length : Int) -> Int {
  (4 - value_length % 4) % 4
}

///|
fn validate_attribute(
  attribute_type : AttributeType,
  value : Bytes,
) -> Unit raise StunError {
  let length = value.length()
  if length > 0xffff {
    raise InvalidMessage("attribute value exceeds 65535 bytes")
  }
  match attribute_type {
    MessageIntegrity if length != 20 =>
      raise InvalidMessage("MESSAGE-INTEGRITY must contain 20 bytes")
    MessageIntegritySha256 if length < 16 || length > 32 =>
      raise InvalidMessage(
        "MESSAGE-INTEGRITY-SHA256 must contain 16 through 32 bytes",
      )
    Priority if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    Fingerprint if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    Lifetime if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    RequestedTransport if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    ChangeRequest if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    RequestedAddressFamily if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    CacheTimeout if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    ConnectionId if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    NetworkCost if length != 4 =>
      raise InvalidMessage("32-bit STUN attribute has invalid length \{length}")
    IceControlled | IceControlling | ReservationToken if length != 8 =>
      raise InvalidMessage("64-bit STUN attribute has invalid length \{length}")
    UseCandidate | DontFragment if length != 0 =>
      raise InvalidMessage("flag STUN attribute must be empty")
    ChannelNumber if length != 4 =>
      raise InvalidMessage("CHANNEL-NUMBER must contain 4 bytes")
    ResponsePort if length != 2 =>
      raise InvalidMessage("RESPONSE-PORT must contain 2 bytes")
    EvenPort if length != 1 =>
      raise InvalidMessage("EVEN-PORT must contain 1 byte")
    UnknownAttributes if length % 2 != 0 =>
      raise InvalidMessage("UNKNOWN-ATTRIBUTES must contain 16-bit values")
    ErrorCode if length < 4 =>
      raise InvalidMessage("ERROR-CODE must contain at least 4 bytes")
    MappedAddress
    | XorMappedAddress
    | XorPeerAddress
    | XorRelayedAddress
    | AlternateServer
    | SourceAddress
    | ChangedAddress
    | ResponseOrigin
    | OtherAddress if length != 8 && length != 20 =>
      raise InvalidMessage("STUN address attribute must contain 8 or 20 bytes")
    _ => ()
  }
}

///|
pub fn Attribute::new(
  attribute_type~ : AttributeType,
  value~ : Bytes,
) -> Attribute raise StunError {
  validate_attribute(attribute_type, value)
  {
    attribute_type,
    value,
    padding: Bytes::make(padding_length(value.length()), 0),
  }
}

///|
fn Attribute::from_wire(
  attribute_type : AttributeType,
  value : Bytes,
  padding : Bytes,
) -> Attribute raise StunError {
  validate_attribute(attribute_type, value)
  if padding.length() != padding_length(value.length()) {
    raise InvalidMessage("attribute padding has invalid length")
  }
  { attribute_type, value, padding }
}

///|
pub fn Attribute::attribute_type(self : Attribute) -> AttributeType {
  self.attribute_type
}

///|
pub fn Attribute::value(self : Attribute) -> Bytes {
  self.value
}

///|
pub fn Attribute::username(value : String) -> Attribute raise StunError {
  text_attribute(Username, value, 513)
}

///|
pub fn Attribute::software(value : String) -> Attribute raise StunError {
  text_attribute(Software, value, 763)
}

///|
pub fn Attribute::realm(value : String) -> Attribute raise StunError {
  text_attribute(Realm, value, 763)
}

///|
pub fn Attribute::nonce(value : String) -> Attribute raise StunError {
  text_attribute(Nonce, value, 763)
}

///|
fn text_attribute(
  attribute_type : AttributeType,
  value : String,
  maximum_length : Int,
) -> Attribute raise StunError {
  let value = @utf8.encode(value)
  if value.length() > maximum_length {
    raise InvalidMessage("text STUN attribute exceeds \{maximum_length} bytes")
  }
  Attribute::new(attribute_type~, value~)
}

///|
pub fn Attribute::priority(value : UInt) -> Attribute raise StunError {
  Attribute::new(
    attribute_type=Priority,
    value=Bytes::from_array([
      (value >> 24).to_byte(),
      (value >> 16).to_byte(),
      (value >> 8).to_byte(),
      value.to_byte(),
    ]),
  )
}

///|
fn u64_attribute(
  attribute_type : AttributeType,
  value : UInt64,
) -> Attribute raise StunError {
  Attribute::new(
    attribute_type~,
    value=Bytes::from_array([
      (value >> 56).to_byte(),
      (value >> 48).to_byte(),
      (value >> 40).to_byte(),
      (value >> 32).to_byte(),
      (value >> 24).to_byte(),
      (value >> 16).to_byte(),
      (value >> 8).to_byte(),
      value.to_byte(),
    ]),
  )
}

///|
pub fn Attribute::ice_controlled(value : UInt64) -> Attribute raise StunError {
  u64_attribute(IceControlled, value)
}

///|
pub fn Attribute::ice_controlling(value : UInt64) -> Attribute raise StunError {
  u64_attribute(IceControlling, value)
}

///|
pub fn Attribute::use_candidate() -> Attribute raise StunError {
  Attribute::new(attribute_type=UseCandidate, value=b"")
}

///|
pub fn Attribute::as_text(self : Attribute) -> String raise StunError {
  match self.attribute_type {
    Username | Software | Realm | Nonce | Origin | AlternateDomain =>
      @utf8.decode(self.value) catch {
        Malformed(_) =>
          raise InvalidMessage("text STUN attribute is not valid UTF-8")
      }
    _ => raise InvalidMessage("attribute does not contain text")
  }
}

///|
pub fn Attribute::as_u32(self : Attribute) -> UInt raise StunError {
  if self.value.length() != 4 {
    raise InvalidMessage("attribute does not contain a 32-bit value")
  }
  (self.value[0].to_uint() << 24) |
  (self.value[1].to_uint() << 16) |
  (self.value[2].to_uint() << 8) |
  self.value[3].to_uint()
}

///|
pub fn Attribute::as_u64(self : Attribute) -> UInt64 raise StunError {
  if self.value.length() != 8 {
    raise InvalidMessage("attribute does not contain a 64-bit value")
  }
  (self.value[0].to_uint64() << 56) |
  (self.value[1].to_uint64() << 48) |
  (self.value[2].to_uint64() << 40) |
  (self.value[3].to_uint64() << 32) |
  (self.value[4].to_uint64() << 24) |
  (self.value[5].to_uint64() << 16) |
  (self.value[6].to_uint64() << 8) |
  self.value[7].to_uint64()
}

///|
pub struct TransactionId(Bytes) derive(Debug, Eq, Hash)

///|
pub fn TransactionId::from_bytes(
  value : Bytes,
) -> TransactionId raise StunError {
  if value.length() != 12 {
    raise InvalidMessage("transaction id must contain 12 bytes")
  }
  TransactionId(value)
}

///|
pub fn TransactionId::as_bytes(self : TransactionId) -> Bytes {
  self.0
}

///|
pub struct Message {
  class : MessageClass
  stun_method : Method
  transaction_id : TransactionId
  attributes : Array[Attribute]
} derive(Debug, Eq)

///|
pub fn Message::new(
  class~ : MessageClass,
  stun_method~ : Method,
  transaction_id~ : TransactionId,
  attributes? : Array[Attribute] = [],
) -> Message {
  { class, stun_method, transaction_id, attributes: attributes.copy() }
}

///|
pub fn Message::class(self : Message) -> MessageClass {
  self.class
}

///|
pub fn Message::stun_method(self : Message) -> Method {
  self.stun_method
}

///|
pub fn Message::transaction_id(self : Message) -> TransactionId {
  self.transaction_id
}

///|
pub fn Message::attributes(self : Message) -> Array[Attribute] {
  self.attributes.copy()
}

///|
pub fn Message::add_attribute(self : Message, attribute : Attribute) -> Unit {
  self.attributes.push(attribute)
}

///|
pub fn Message::first_attribute(
  self : Message,
  attribute_type : AttributeType,
) -> Attribute? {
  for attribute in self.attributes {
    if attribute.attribute_type == attribute_type {
      return Some(attribute)
    }
  }
  None
}

///|
pub fn Message::unknown_required_attributes(self : Message) -> Array[UInt16] {
  let result : Array[UInt16] = []
  for attribute in self.attributes {
    match attribute.attribute_type {
      UnknownAttribute(code) if code.to_uint() < 0x8000U => result.push(code)
      _ => ()
    }
  }
  result
}
