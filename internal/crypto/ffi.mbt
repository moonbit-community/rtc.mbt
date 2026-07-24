///|
pub type Provider

///|
pub type Secret

///|
pub type PrivateKey

///|
pub type PublicKey

///|
pub type Certificate

///|
#borrow(path, property_query)
extern "c" fn provider_new(path : Bytes, property_query : Bytes) -> Provider = "moonbit_rtc_crypto_provider_new"

///|
#borrow(provider)
extern "c" fn provider_is_ready(provider : Provider) -> Bool = "moonbit_rtc_crypto_provider_is_ready"

///|
#borrow(provider)
extern "c" fn provider_last_error(provider : Provider) -> Bytes = "moonbit_rtc_crypto_provider_last_error"

///|
#borrow(provider)
extern "c" fn provider_version(provider : Provider) -> Bytes = "moonbit_rtc_crypto_provider_version"

///|
#borrow(provider)
extern "c" fn provider_random_bytes(provider : Provider, length : Int) -> Bytes = "moonbit_rtc_crypto_random_bytes"

///|
#borrow(provider, data)
extern "c" fn provider_digest(
  provider : Provider,
  algorithm : Int,
  data : Bytes,
) -> Bytes = "moonbit_rtc_crypto_digest"

///|
#borrow(provider, key, data)
extern "c" fn provider_hmac(
  provider : Provider,
  algorithm : Int,
  key : Secret,
  data : Bytes,
) -> Bytes = "moonbit_rtc_crypto_hmac"

///|
#borrow(provider, left, right)
extern "c" fn provider_constant_time_equal(
  provider : Provider,
  left : Bytes,
  right : Bytes,
) -> Bool = "moonbit_rtc_crypto_constant_time_equal"

///|
#borrow(provider, key, nonce, aad, plaintext)
extern "c" fn provider_aead_seal(
  provider : Provider,
  algorithm : Int,
  key : Secret,
  nonce : Bytes,
  aad : Bytes,
  plaintext : Bytes,
  tag_length : Int,
) -> Bytes = "moonbit_rtc_crypto_aead_seal"

///|
#borrow(provider, key, nonce, aad, ciphertext, tag, success)
extern "c" fn provider_aead_open(
  provider : Provider,
  algorithm : Int,
  key : Secret,
  nonce : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_aead_open"

///|
#borrow(provider, key, iv, input, success)
extern "c" fn provider_cipher_crypt(
  provider : Provider,
  algorithm : Int,
  key : Secret,
  iv : Bytes,
  input : Bytes,
  encrypt : Bool,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_cipher_crypt"

///|
#borrow(value)
extern "c" fn secret_from_bytes(value : Bytes) -> Secret = "moonbit_rtc_crypto_secret_from_bytes"

///|
#borrow(provider)
extern "c" fn secret_random(provider : Provider, length : Int) -> Secret = "moonbit_rtc_crypto_secret_random"

///|
#borrow(secret)
extern "c" fn secret_is_valid(secret : Secret) -> Bool = "moonbit_rtc_crypto_secret_is_valid"

///|
#borrow(secret)
extern "c" fn secret_length(secret : Secret) -> Int = "moonbit_rtc_crypto_secret_length"

///|
#borrow(provider, left, right)
extern "c" fn secret_constant_time_equal(
  provider : Provider,
  left : Secret,
  right : Secret,
) -> Bool = "moonbit_rtc_crypto_secret_constant_time_equal"

///|
#borrow(provider, success)
extern "c" fn provider_generate_private_key(
  provider : Provider,
  algorithm : Int,
  success : Ref[Int],
) -> PrivateKey = "moonbit_rtc_crypto_generate_private_key"

///|
#borrow(provider, key, success)
extern "c" fn private_key_public_der(
  provider : Provider,
  key : PrivateKey,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_private_key_public_der"

///|
#borrow(provider, der, success)
extern "c" fn public_key_from_der(
  provider : Provider,
  der : Bytes,
  success : Ref[Int],
) -> PublicKey = "moonbit_rtc_crypto_public_key_from_der"

///|
#borrow(provider, private_key, peer_key, success)
extern "c" fn provider_derive_secret(
  provider : Provider,
  private_key : PrivateKey,
  peer_key : PublicKey,
  success : Ref[Int],
) -> Secret = "moonbit_rtc_crypto_derive_secret"

///|
#borrow(provider, key, data, success)
extern "c" fn provider_sign(
  provider : Provider,
  algorithm : Int,
  key : PrivateKey,
  data : Bytes,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_sign"

///|
#borrow(provider, key, data, signature)
extern "c" fn provider_verify(
  provider : Provider,
  algorithm : Int,
  key : PublicKey,
  data : Bytes,
  signature : Bytes,
) -> Int = "moonbit_rtc_crypto_verify"

///|
#borrow(provider, key, common_name, success)
extern "c" fn provider_self_signed_certificate(
  provider : Provider,
  key : PrivateKey,
  common_name : Bytes,
  not_before_seconds : Int64,
  not_after_seconds : Int64,
  success : Ref[Int],
) -> Certificate = "moonbit_rtc_crypto_self_signed_certificate"

///|
#borrow(provider, certificate, success)
extern "c" fn certificate_to_der(
  provider : Provider,
  certificate : Certificate,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_certificate_to_der"

///|
#borrow(provider, der, success)
extern "c" fn certificate_from_der(
  provider : Provider,
  der : Bytes,
  success : Ref[Int],
) -> Certificate = "moonbit_rtc_crypto_certificate_from_der"

///|
#borrow(provider, certificate, success)
extern "c" fn certificate_public_key(
  provider : Provider,
  certificate : Certificate,
  success : Ref[Int],
) -> PublicKey = "moonbit_rtc_crypto_certificate_public_key"

///|
#borrow(provider, certificate, success)
extern "c" fn certificate_fingerprint(
  provider : Provider,
  certificate : Certificate,
  algorithm : Int,
  success : Ref[Int],
) -> Bytes = "moonbit_rtc_crypto_certificate_fingerprint"

///|
#borrow(provider, certificate, success)
extern "c" fn certificate_valid_at(
  provider : Provider,
  certificate : Certificate,
  unix_seconds : Int64,
  success : Ref[Int],
) -> Bool = "moonbit_rtc_crypto_certificate_valid_at"

///|
#borrow(provider, certificate, success)
extern "c" fn certificate_verify_self_signature(
  provider : Provider,
  certificate : Certificate,
  success : Ref[Int],
) -> Bool = "moonbit_rtc_crypto_certificate_verify_self_signature"
