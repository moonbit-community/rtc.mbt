///|
const FINGERPRINT_XOR : UInt = 0x5354554eU

///|
let default_provider : Lazy[Result[@crypto.Provider, String]] = Lazy(() => {
  Ok(@crypto.Provider::open()) catch {
    CryptoUnavailable(message) => Err(message)
    InvalidLength(length) => Err("OpenSSL rejected length \{length}")
    OperationFailed(message) => Err(message)
  }
})

///|
fn crypto_provider() -> @crypto.Provider raise StunError {
  match default_provider.force() {
    Ok(provider) => provider
    Err(message) => raise CryptoUnavailable(message)
  }
}

///|
pub fn TransactionId::random() -> TransactionId raise StunError {
  let provider = crypto_provider()
  let bytes = provider.random_bytes(12) catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
  TransactionId::from_bytes(bytes)
}

///|
fn hmac(
  algorithm : @crypto.DigestAlgorithm,
  key : Bytes,
  data : Bytes,
) -> Bytes raise StunError {
  let provider = crypto_provider()
  let secret = @crypto.Secret::from_bytes(key)
  provider.hmac(algorithm, secret, data) catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
}

///|
fn crc32(data : Bytes) -> UInt {
  let mut checksum = 0xffffffffU
  for byte in data {
    checksum = checksum ^ byte.to_uint()
    for bit_index = 0; bit_index < 8; bit_index = bit_index + 1 {
      checksum = if (checksum & 1U) == 1U {
        (checksum >> 1) ^ 0xedb88320U
      } else {
        checksum >> 1
      }
    }
  }
  checksum ^ 0xffffffffU
}

///|
fn u32_bytes(value : UInt) -> Bytes {
  Bytes::from_array([
    (value >> 24).to_byte(),
    (value >> 16).to_byte(),
    (value >> 8).to_byte(),
    value.to_byte(),
  ])
}

///|
fn Message::without_authentication_attributes(self : Message) -> Message {
  let attributes : Array[Attribute] = []
  for attribute in self.attributes {
    match attribute.attribute_type {
      MessageIntegrity | MessageIntegritySha256 | Fingerprint => ()
      _ => attributes.push(attribute)
    }
  }
  Message::new(
    class=self.class,
    stun_method=self.stun_method,
    transaction_id=self.transaction_id,
    attributes~,
  )
}

///|
pub fn Message::encode_authenticated(
  self : Message,
  key : Bytes,
  sha256? : Bool = false,
  fingerprint? : Bool = true,
) -> Bytes raise StunError {
  let authenticated = self.without_authentication_attributes()
  let digest_length = if sha256 { 32 } else { 20 }
  let base_length = authenticated.body_length(authenticated.attributes.length())
  let declared_length = base_length + 4 + digest_length
  let hmac_input = authenticated.encode_prefix(
    authenticated.attributes.length(),
    declared_length,
  )
  let digest = hmac(if sha256 { Sha256 } else { Sha1 }, key, hmac_input)
  authenticated.add_attribute(
    Attribute::new(
      attribute_type=if sha256 {
        MessageIntegritySha256
      } else {
        MessageIntegrity
      },
      value=digest,
    ),
  )
  if fingerprint {
    let body_length = authenticated.body_length(
      authenticated.attributes.length(),
    )
    let fingerprint_input = authenticated.encode_prefix(
      authenticated.attributes.length(),
      body_length + 8,
    )
    authenticated.add_attribute(
      Attribute::new(
        attribute_type=Fingerprint,
        value=u32_bytes(crc32(fingerprint_input) ^ FINGERPRINT_XOR),
      ),
    )
  }
  authenticated.encode()
}

///|
fn Message::integrity_index(
  self : Message,
  expected_type : AttributeType,
) -> Int raise StunError {
  let mut result = -1
  for index = 0; index < self.attributes.length(); index = index + 1 {
    if self.attributes[index].attribute_type == expected_type {
      if result >= 0 {
        raise IntegrityFailure
      }
      result = index
    }
  }
  if result < 0 {
    raise IntegrityFailure
  }
  result
}

///|
fn Message::validate_attributes_after_integrity(
  self : Message,
  index : Int,
  sha256 : Bool,
) -> Unit raise StunError {
  for following = index + 1
      following < self.attributes.length()
      following = following + 1 {
    let attribute_type = self.attributes[following].attribute_type
    match attribute_type {
      Fingerprint if following == self.attributes.length() - 1 => ()
      MessageIntegrity if sha256 => ()
      _ => raise IntegrityFailure
    }
  }
}

///|
pub fn Message::verify_integrity(
  self : Message,
  key : Bytes,
  sha256? : Bool = false,
) -> Unit raise StunError {
  let expected_type = if sha256 {
    MessageIntegritySha256
  } else {
    MessageIntegrity
  }
  let index = self.integrity_index(expected_type)
  self.validate_attributes_after_integrity(index, sha256)
  let attribute = self.attributes[index]
  let digest_length = attribute.value.length()
  if (!sha256 && digest_length != 20) ||
    (
      sha256 &&
      (digest_length < 16 || digest_length > 32 || digest_length % 4 != 0)
    ) {
    raise IntegrityFailure
  }
  let declared_length = self.body_length(index) + attribute.wire_length()
  let hmac_input = self.encode_prefix(index, declared_length)
  let expected = hmac(if sha256 { Sha256 } else { Sha1 }, key, hmac_input)
  let expected = expected[0:digest_length].to_owned()
  if !crypto_provider().constant_time_equal(expected, attribute.value) {
    raise IntegrityFailure
  }
}

///|
pub fn Message::verify_fingerprint(self : Message) -> Unit raise StunError {
  let index = self.integrity_index(Fingerprint)
  if index != self.attributes.length() - 1 {
    raise IntegrityFailure
  }
  let attribute = self.attributes[index]
  if attribute.value.length() != 4 {
    raise IntegrityFailure
  }
  let fingerprint_input = self.encode_prefix(
    index,
    self.body_length(self.attributes.length()),
  )
  let expected = crc32(fingerprint_input) ^ FINGERPRINT_XOR
  if attribute.as_u32() != expected {
    raise IntegrityFailure
  }
}
