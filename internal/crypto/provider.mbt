///|
pub(all) suberror CryptoError {
  CryptoUnavailable(String)
  InvalidLength(Int)
  OperationFailed(String)
} derive(Debug, Eq)

///|
pub(all) enum DigestAlgorithm {
  Sha1
  Sha256
  Sha384
  Sha512
} derive(Debug, Eq)

///|
pub(all) enum AeadAlgorithm {
  Aes128Gcm
  Aes256Gcm
  Aes128Ccm
  Aes256Ccm
  Chacha20Poly1305
} derive(Debug, Eq)

///|
fn AeadAlgorithm::code(self : AeadAlgorithm) -> Int {
  match self {
    Aes128Gcm => 0
    Aes256Gcm => 1
    Aes128Ccm => 2
    Aes256Ccm => 3
    Chacha20Poly1305 => 4
  }
}

///|
pub(all) enum CipherAlgorithm {
  Aes128Cbc
  Aes256Cbc
  Aes128Ctr
  Aes256Ctr
} derive(Debug, Eq)

///|
pub(all) enum KeyAlgorithm {
  P256
  P384
  X25519
  Rsa2048
} derive(Debug, Eq)

///|
fn KeyAlgorithm::code(self : KeyAlgorithm) -> Int {
  match self {
    P256 => 0
    P384 => 1
    X25519 => 2
    Rsa2048 => 3
  }
}

///|
pub(all) enum SignatureAlgorithm {
  EcdsaSha256
  EcdsaSha384
  RsaPssSha256
  RsaPkcs1Sha256
} derive(Debug, Eq)

///|
fn SignatureAlgorithm::code(self : SignatureAlgorithm) -> Int {
  match self {
    EcdsaSha256 => 0
    EcdsaSha384 => 1
    RsaPssSha256 => 2
    RsaPkcs1Sha256 => 3
  }
}

///|
fn CipherAlgorithm::code(self : CipherAlgorithm) -> Int {
  match self {
    Aes128Cbc => 0
    Aes256Cbc => 1
    Aes128Ctr => 2
    Aes256Ctr => 3
  }
}

///|
pub struct AeadSealed {
  ciphertext : Bytes
  tag : Bytes
} derive(Debug, Eq)

///|
pub fn AeadSealed::new(
  ciphertext~ : Bytes,
  tag~ : Bytes,
) -> AeadSealed raise CryptoError {
  if tag.length() != 8 && tag.length() != 16 {
    raise InvalidLength(tag.length())
  }
  { ciphertext, tag, }
}

///|
pub fn AeadSealed::ciphertext(self : AeadSealed) -> Bytes {
  self.ciphertext
}

///|
pub fn AeadSealed::tag(self : AeadSealed) -> Bytes {
  self.tag
}

///|
fn DigestAlgorithm::code(self : DigestAlgorithm) -> Int {
  match self {
    Sha1 => 0
    Sha256 => 1
    Sha384 => 2
    Sha512 => 3
  }
}

///|
fn DigestAlgorithm::output_size(self : DigestAlgorithm) -> Int {
  match self {
    Sha1 => 20
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
}

///|
fn Provider::failure_message(self : Provider) -> String {
  @utf8.decode_lossy(provider_last_error(self))
}

///|
pub fn Provider::open(
  path? : String,
  property_query? : String,
) -> Provider raise CryptoError {
  let path = match path {
    Some(value) => @utf8.encode(value)
    None => b""
  }
  let property_query = match property_query {
    Some(value) => @utf8.encode(value)
    None => b""
  }
  let provider = provider_new(path, property_query)
  if !provider_is_ready(provider) {
    raise CryptoUnavailable(provider.failure_message())
  }
  provider
}

///|
pub fn Provider::version(self : Provider) -> String {
  @utf8.decode_lossy(provider_version(self))
}

///|
pub fn Provider::random_bytes(
  self : Provider,
  length : Int,
) -> Bytes raise CryptoError {
  if length < 1 {
    raise InvalidLength(length)
  }
  let result = provider_random_bytes(self, length)
  if result.length() != length {
    raise OperationFailed(self.failure_message())
  }
  result
}

///|
pub fn Provider::digest(
  self : Provider,
  algorithm : DigestAlgorithm,
  data : Bytes,
) -> Bytes raise CryptoError {
  let result = provider_digest(self, algorithm.code(), data)
  if result.length() != algorithm.output_size() {
    raise OperationFailed(self.failure_message())
  }
  result
}

///|
pub fn Provider::hmac(
  self : Provider,
  algorithm : DigestAlgorithm,
  key : Secret,
  data : Bytes,
) -> Bytes raise CryptoError {
  let result = provider_hmac(self, algorithm.code(), key, data)
  if result.length() != algorithm.output_size() {
    raise OperationFailed(self.failure_message())
  }
  result
}

///|
pub fn Provider::constant_time_equal(
  self : Provider,
  left : Bytes,
  right : Bytes,
) -> Bool {
  provider_constant_time_equal(self, left, right)
}

///|
pub fn Provider::aead_seal(
  self : Provider,
  algorithm : AeadAlgorithm,
  key : Secret,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
  tag_length? : Int = 16,
) -> AeadSealed raise CryptoError {
  if tag_length != 8 && tag_length != 16 {
    raise InvalidLength(tag_length)
  }
  if algorithm != Aes128Ccm && algorithm != Aes256Ccm && tag_length != 16 {
    raise InvalidLength(tag_length)
  }
  let combined = provider_aead_seal(
    self,
    algorithm.code(),
    key,
    nonce,
    aad,
    plaintext,
    tag_length,
  )
  if combined.length() != plaintext.length() + tag_length {
    raise OperationFailed(self.failure_message())
  }
  AeadSealed::new(
    ciphertext=combined[:plaintext.length()].to_owned(),
    tag=combined[plaintext.length():].to_owned(),
  )
}

///|
pub fn Provider::aead_open(
  self : Provider,
  algorithm : AeadAlgorithm,
  key : Secret,
  nonce : Bytes,
  aad : Bytes,
  packet : AeadSealed,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let plaintext = provider_aead_open(
    self,
    algorithm.code(),
    key,
    nonce,
    aad,
    packet.ciphertext,
    packet.tag,
    success,
  )
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  plaintext
}

///|
pub fn Provider::cipher_encrypt(
  self : Provider,
  algorithm : CipherAlgorithm,
  key : Secret,
  iv : Bytes,
  plaintext : Bytes,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let ciphertext = provider_cipher_crypt(
    self,
    algorithm.code(),
    key,
    iv,
    plaintext,
    true,
    success,
  )
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  ciphertext
}

///|
pub fn Provider::cipher_decrypt(
  self : Provider,
  algorithm : CipherAlgorithm,
  key : Secret,
  iv : Bytes,
  ciphertext : Bytes,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let plaintext = provider_cipher_crypt(
    self,
    algorithm.code(),
    key,
    iv,
    ciphertext,
    false,
    success,
  )
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  plaintext
}

///|
pub fn Secret::from_bytes(value : Bytes) -> Secret {
  secret_from_bytes(value)
}

///|
pub fn Provider::random_secret(
  self : Provider,
  length : Int,
) -> Secret raise CryptoError {
  if length < 1 {
    raise InvalidLength(length)
  }
  let result = secret_random(self, length)
  if !secret_is_valid(result) || secret_length(result) != length {
    raise OperationFailed(self.failure_message())
  }
  result
}

///|
pub fn Secret::length(self : Secret) -> Int {
  secret_length(self)
}

///|
pub fn Secret::constant_time_equal(
  self : Secret,
  provider : Provider,
  other : Secret,
) -> Bool {
  secret_constant_time_equal(provider, self, other)
}

///|
pub fn Provider::generate_private_key(
  self : Provider,
  algorithm : KeyAlgorithm,
) -> PrivateKey raise CryptoError {
  let success = Ref(0)
  let key = provider_generate_private_key(self, algorithm.code(), success)
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  key
}

///|
pub fn PrivateKey::public_der(
  self : PrivateKey,
  provider : Provider,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let der = private_key_public_der(provider, self, success)
  if success.val != 1 {
    raise OperationFailed(provider.failure_message())
  }
  der
}

///|
pub fn Provider::import_public_key(
  self : Provider,
  der : Bytes,
) -> PublicKey raise CryptoError {
  let success = Ref(0)
  let key = public_key_from_der(self, der, success)
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  key
}

///|
pub fn Provider::derive_shared_secret(
  self : Provider,
  private_key : PrivateKey,
  peer_key : PublicKey,
) -> Secret raise CryptoError {
  let success = Ref(0)
  let secret = provider_derive_secret(self, private_key, peer_key, success)
  if success.val != 1 || !secret_is_valid(secret) {
    raise OperationFailed(self.failure_message())
  }
  secret
}

///|
pub fn Provider::sign(
  self : Provider,
  algorithm : SignatureAlgorithm,
  key : PrivateKey,
  data : Bytes,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let signature = provider_sign(self, algorithm.code(), key, data, success)
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  signature
}

///|
pub fn Provider::verify(
  self : Provider,
  algorithm : SignatureAlgorithm,
  key : PublicKey,
  data : Bytes,
  signature : Bytes,
) -> Bool raise CryptoError {
  match provider_verify(self, algorithm.code(), key, data, signature) {
    1 => true
    0 => false
    _ => raise OperationFailed(self.failure_message())
  }
}

///|
pub fn Provider::self_signed_certificate(
  self : Provider,
  key : PrivateKey,
  common_name : String,
  not_before : @transport.WallTime,
  not_after : @transport.WallTime,
) -> Certificate raise CryptoError {
  let success = Ref(0)
  let certificate = provider_self_signed_certificate(
    self,
    key,
    @utf8.encode(common_name),
    not_before.as_unix_nanoseconds() / 1000000000L,
    not_after.as_unix_nanoseconds() / 1000000000L,
    success,
  )
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  certificate
}

///|
pub fn Certificate::to_der(
  self : Certificate,
  provider : Provider,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let der = certificate_to_der(provider, self, success)
  if success.val != 1 {
    raise OperationFailed(provider.failure_message())
  }
  der
}

///|
pub fn Provider::import_certificate(
  self : Provider,
  der : Bytes,
) -> Certificate raise CryptoError {
  let success = Ref(0)
  let certificate = certificate_from_der(self, der, success)
  if success.val != 1 {
    raise OperationFailed(self.failure_message())
  }
  certificate
}

///|
pub fn Certificate::public_key(
  self : Certificate,
  provider : Provider,
) -> PublicKey raise CryptoError {
  let success = Ref(0)
  let key = certificate_public_key(provider, self, success)
  if success.val != 1 {
    raise OperationFailed(provider.failure_message())
  }
  key
}

///|
pub fn Certificate::fingerprint(
  self : Certificate,
  provider : Provider,
  algorithm : DigestAlgorithm,
) -> Bytes raise CryptoError {
  let success = Ref(0)
  let fingerprint = certificate_fingerprint(
    provider,
    self,
    algorithm.code(),
    success,
  )
  if success.val != 1 || fingerprint.length() != algorithm.output_size() {
    raise OperationFailed(provider.failure_message())
  }
  fingerprint
}

///|
pub fn Certificate::is_valid_at(
  self : Certificate,
  provider : Provider,
  wall_time : @transport.WallTime,
) -> Bool raise CryptoError {
  let success = Ref(0)
  let valid = certificate_valid_at(
    provider,
    self,
    wall_time.as_unix_nanoseconds() / 1000000000L,
    success,
  )
  if success.val != 1 {
    raise OperationFailed(provider.failure_message())
  }
  valid
}

///|
pub fn Certificate::verify_self_signature(
  self : Certificate,
  provider : Provider,
) -> Bool raise CryptoError {
  let success = Ref(0)
  let valid = certificate_verify_self_signature(provider, self, success)
  if success.val != 1 {
    raise OperationFailed(provider.failure_message())
  }
  valid
}
