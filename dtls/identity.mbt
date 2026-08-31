///|
pub struct CertificateIdentity {
  provider : @crypto.Provider
  private_key : @crypto.PrivateKey
  certificate : @crypto.Certificate
  certificate_der : Bytes
  key_type : CertificateKeyType
}

///|
pub fn CertificateIdentity::generate(
  common_name? : String = "moonbit-rtc",
  key_type? : CertificateKeyType = EcdsaCertificate,
  not_before~ : @transport.WallTime,
  not_after~ : @transport.WallTime,
) -> CertificateIdentity raise DtlsError {
  if not_after <= not_before {
    raise HandshakeFailed("certificate validity interval is empty")
  }
  let provider = crypto_provider()
  let key_algorithm = match key_type {
    EcdsaCertificate => @crypto.KeyAlgorithm::P256
    RsaCertificate => Rsa2048
  }
  let private_key = crypto_operation(() => {
    provider.generate_private_key(key_algorithm)
  })
  let certificate = crypto_operation(() => {
    provider.self_signed_certificate(
      private_key, common_name, not_before, not_after,
    )
  })
  let certificate_der = crypto_operation(() => certificate.to_der(provider))
  { provider, private_key, certificate, certificate_der, key_type, }
}

///|
pub fn CertificateIdentity::certificate_der(
  self : CertificateIdentity,
) -> Bytes {
  self.certificate_der
}

///|
pub fn CertificateIdentity::key_type(
  self : CertificateIdentity,
) -> CertificateKeyType {
  self.key_type
}

///|
fn fingerprint_digest(
  algorithm : FingerprintAlgorithm,
) -> @crypto.DigestAlgorithm {
  match algorithm {
    Sha256 => Sha256
    Sha384 => Sha384
    Sha512 => Sha512
  }
}

///|
pub fn CertificateIdentity::fingerprint(
  self : CertificateIdentity,
  algorithm? : FingerprintAlgorithm = Sha256,
) -> Fingerprint raise DtlsError {
  let value = crypto_operation(() => {
    self.certificate.fingerprint(self.provider, fingerprint_digest(algorithm))
  })
  Fingerprint::new(algorithm~, value~)
}

///|
fn CertificateIdentity::sign(
  self : CertificateIdentity,
  algorithm : @crypto.SignatureAlgorithm,
  data : Bytes,
) -> Bytes raise DtlsError {
  crypto_operation(() => self.provider.sign(algorithm, self.private_key, data))
}

///|
const P256_SPKI_PREFIX : Bytes = b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"

///|
fn CertificateIdentity::ephemeral_public_point(
  self : CertificateIdentity,
  key : @crypto.PrivateKey,
) -> Bytes raise DtlsError {
  let der = crypto_operation(() => key.public_der(self.provider))
  if der.length() != P256_SPKI_PREFIX.length() + 65 ||
    der[0:P256_SPKI_PREFIX.length()] != P256_SPKI_PREFIX ||
    der[P256_SPKI_PREFIX.length()] != 4 {
    raise HandshakeFailed("OpenSSL returned a non-P-256 public key")
  }
  der[P256_SPKI_PREFIX.length():].to_owned()
}

///|
fn p256_public_key(
  provider : @crypto.Provider,
  point : Bytes,
) -> @crypto.PublicKey raise DtlsError {
  if point.length() != 65 || point[0] != 4 {
    raise InvalidHandshake("P-256 public point must be uncompressed")
  }
  crypto_operation(() => {
    provider.import_public_key(append_bytes(P256_SPKI_PREFIX, point))
  })
}

///|
fn verify_peer_certificate(
  provider : @crypto.Provider,
  certificate_der : Bytes,
  expected_fingerprint : Fingerprint,
  wall_time : @transport.WallTime,
  verify_fingerprint? : Bool = true,
) -> @crypto.PublicKey raise DtlsError {
  let certificate = crypto_operation(() => {
    provider.import_certificate(certificate_der)
  })
  let valid_signature = crypto_operation(() => {
    certificate.verify_self_signature(provider)
  })
  let valid_time = crypto_operation(() => {
    certificate.is_valid_at(provider, wall_time)
  })
  if !valid_signature || !valid_time {
    raise HandshakeFailed("peer certificate is not valid")
  }
  let actual = crypto_operation(() => {
    certificate.fingerprint(
      provider,
      fingerprint_digest(expected_fingerprint.algorithm),
    )
  })
  if verify_fingerprint &&
    !provider.constant_time_equal(actual, expected_fingerprint.value) {
    raise FingerprintMismatch
  }
  crypto_operation(() => certificate.public_key(provider))
}
