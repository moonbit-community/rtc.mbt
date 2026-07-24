///|
pub(all) suberror DtlsError {
  InvalidRecord(String)
  InvalidHandshake(String)
  UnsupportedVersion
  UnsupportedCipherSuite(UInt16)
  UnsupportedSrtpProfile(UInt16)
  HandshakeFailed(String)
  FingerprintMismatch
  ReplayRejected
  CryptoUnavailable(String)
  Time(@transport.TimeError)
  Closed
} derive(Debug, Eq)

///|
pub(all) enum Role {
  Auto
  Client
  Server
} derive(Debug, Eq)

///|
pub(all) enum State {
  New
  Connecting
  Connected
  Closing
  Closed
  Failed
} derive(Debug, Eq)

///|
pub(all) enum FingerprintAlgorithm {
  Sha256
  Sha384
  Sha512
} derive(Debug, Eq)

///|
pub(all) enum CertificateKeyType {
  EcdsaCertificate
  RsaCertificate
} derive(Debug, Eq)

///|
pub struct Fingerprint {
  algorithm : FingerprintAlgorithm
  value : Bytes
} derive(Debug, Eq)

///|
pub fn Fingerprint::new(
  algorithm~ : FingerprintAlgorithm,
  value~ : Bytes,
) -> Fingerprint raise DtlsError {
  let expected_length = match algorithm {
    Sha256 => 32
    Sha384 => 48
    Sha512 => 64
  }
  if value.length() != expected_length {
    raise InvalidHandshake(
      "fingerprint length \{value.length()} does not match its digest",
    )
  }
  { algorithm, value }
}

///|
pub fn Fingerprint::algorithm(self : Fingerprint) -> FingerprintAlgorithm {
  self.algorithm
}

///|
pub fn Fingerprint::value(self : Fingerprint) -> Bytes {
  self.value
}

///|
pub(all) enum ContentType {
  ChangeCipherSpec
  Alert
  Handshake
  ApplicationData
} derive(Debug, Eq)

///|
pub fn ContentType::code(self : ContentType) -> Byte {
  match self {
    ChangeCipherSpec => 20
    Alert => 21
    Handshake => 22
    ApplicationData => 23
  }
}

///|
pub(all) enum ProtocolVersion {
  Dtls10
  Dtls12
} derive(Debug, Eq)

///|
pub fn ProtocolVersion::major(_self : ProtocolVersion) -> Byte {
  0xfe
}

///|
pub fn ProtocolVersion::minor(self : ProtocolVersion) -> Byte {
  match self {
    Dtls10 => 0xff
    Dtls12 => 0xfd
  }
}

///|
pub(all) enum CipherSuite {
  EcdheEcdsaAes128Ccm
  EcdheEcdsaAes128Ccm8
  EcdheEcdsaAes128GcmSha256
  EcdheRsaAes128GcmSha256
  EcdheEcdsaAes256CbcSha
  EcdheRsaAes256CbcSha
  PskAes128Ccm
  PskAes128Ccm8
  PskAes128GcmSha256
  EcdheRsaChacha20Poly1305Sha256
  EcdheEcdsaChacha20Poly1305Sha256
} derive(Debug, Eq)

///|
pub fn CipherSuite::code(self : CipherSuite) -> UInt16 {
  match self {
    EcdheEcdsaAes128Ccm => 0xc0ac
    EcdheEcdsaAes128Ccm8 => 0xc0ae
    EcdheEcdsaAes128GcmSha256 => 0xc02b
    EcdheRsaAes128GcmSha256 => 0xc02f
    EcdheEcdsaAes256CbcSha => 0xc00a
    EcdheRsaAes256CbcSha => 0xc014
    PskAes128Ccm => 0xc0a4
    PskAes128Ccm8 => 0xc0a8
    PskAes128GcmSha256 => 0x00a8
    EcdheRsaChacha20Poly1305Sha256 => 0xcca8
    EcdheEcdsaChacha20Poly1305Sha256 => 0xcca9
  }
}

///|
pub fn CipherSuite::from_code(code : UInt16) -> CipherSuite raise DtlsError {
  match code {
    0xc0ac => EcdheEcdsaAes128Ccm
    0xc0ae => EcdheEcdsaAes128Ccm8
    0xc02b => EcdheEcdsaAes128GcmSha256
    0xc02f => EcdheRsaAes128GcmSha256
    0xc00a => EcdheEcdsaAes256CbcSha
    0xc014 => EcdheRsaAes256CbcSha
    0xc0a4 => PskAes128Ccm
    0xc0a8 => PskAes128Ccm8
    0x00a8 => PskAes128GcmSha256
    0xcca8 => EcdheRsaChacha20Poly1305Sha256
    0xcca9 => EcdheEcdsaChacha20Poly1305Sha256
    _ => raise UnsupportedCipherSuite(code)
  }
}

///|
pub fn CipherSuite::is_psk(self : CipherSuite) -> Bool {
  match self {
    PskAes128Ccm | PskAes128Ccm8 | PskAes128GcmSha256 => true
    _ => false
  }
}

///|
pub fn CipherSuite::uses_rsa(self : CipherSuite) -> Bool {
  match self {
    EcdheRsaAes128GcmSha256
    | EcdheRsaAes256CbcSha
    | EcdheRsaChacha20Poly1305Sha256 => true
    _ => false
  }
}

///|
pub fn CipherSuite::maximum_record_expansion(self : CipherSuite) -> Int {
  match self {
    EcdheEcdsaAes128Ccm8 | PskAes128Ccm8 => 16
    EcdheEcdsaAes256CbcSha | EcdheRsaAes256CbcSha => 52
    EcdheRsaChacha20Poly1305Sha256 | EcdheEcdsaChacha20Poly1305Sha256 => 16
    _ => 24
  }
}

///|
pub(all) enum SrtpProtectionProfile {
  SrtpAes128CmHmacSha1_80
  SrtpAes128CmHmacSha1_32
  SrtpAeadAes128Gcm
  SrtpAeadAes256Gcm
} derive(Debug, Eq)

///|
pub fn SrtpProtectionProfile::aes128_cm_hmac_sha1_80() -> SrtpProtectionProfile {
  SrtpAes128CmHmacSha1_80
}

///|
pub fn SrtpProtectionProfile::aes128_cm_hmac_sha1_32() -> SrtpProtectionProfile {
  SrtpAes128CmHmacSha1_32
}

///|
pub fn SrtpProtectionProfile::aead_aes128_gcm() -> SrtpProtectionProfile {
  SrtpAeadAes128Gcm
}

///|
pub fn SrtpProtectionProfile::aead_aes256_gcm() -> SrtpProtectionProfile {
  SrtpAeadAes256Gcm
}

///|
pub fn SrtpProtectionProfile::code(self : SrtpProtectionProfile) -> UInt16 {
  match self {
    SrtpAes128CmHmacSha1_80 => 0x0001
    SrtpAes128CmHmacSha1_32 => 0x0002
    SrtpAeadAes128Gcm => 0x0007
    SrtpAeadAes256Gcm => 0x0008
  }
}

///|
pub struct RecordHeader {
  content_type : ContentType
  version : ProtocolVersion
  epoch : UInt16
  sequence_number : UInt64
  content_length : UInt16
} derive(Debug, Eq)

///|
pub fn RecordHeader::new(
  content_type~ : ContentType,
  version? : ProtocolVersion = Dtls12,
  epoch~ : UInt16,
  sequence_number~ : UInt64,
  content_length~ : UInt16,
) -> RecordHeader raise DtlsError {
  if sequence_number > 0x0000ffffffffffffUL {
    raise InvalidRecord("DTLS record sequence number exceeds 48 bits")
  }
  { content_type, version, epoch, sequence_number, content_length }
}

///|
pub fn RecordHeader::content_type(self : RecordHeader) -> ContentType {
  self.content_type
}

///|
pub fn RecordHeader::version(self : RecordHeader) -> ProtocolVersion {
  self.version
}

///|
pub fn RecordHeader::epoch(self : RecordHeader) -> UInt16 {
  self.epoch
}

///|
pub fn RecordHeader::sequence_number(self : RecordHeader) -> UInt64 {
  self.sequence_number
}

///|
pub fn RecordHeader::content_length(self : RecordHeader) -> UInt16 {
  self.content_length
}

///|
pub struct Record {
  header : RecordHeader
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn Record::new(
  content_type~ : ContentType,
  version? : ProtocolVersion = Dtls12,
  epoch~ : UInt16,
  sequence_number~ : UInt64,
  payload~ : Bytes,
) -> Record raise DtlsError {
  if payload.length() > 0xffff {
    raise InvalidRecord("DTLS record payload exceeds 65535 bytes")
  }
  {
    header: RecordHeader::new(
      content_type~,
      version~,
      epoch~,
      sequence_number~,
      content_length=payload.length().to_uint16(),
    ),
    payload,
  }
}

///|
pub fn Record::header(self : Record) -> RecordHeader {
  self.header
}

///|
pub fn Record::payload(self : Record) -> Bytes {
  self.payload
}

///|
pub(all) enum HandshakeType {
  HelloRequest
  ClientHello
  ServerHello
  HelloVerifyRequest
  Certificate
  ServerKeyExchange
  CertificateRequest
  ServerHelloDone
  CertificateVerify
  ClientKeyExchange
  Finished
  UnknownHandshake(Byte)
} derive(Debug, Eq)

///|
pub fn HandshakeType::code(self : HandshakeType) -> Byte {
  match self {
    HelloRequest => 0
    ClientHello => 1
    ServerHello => 2
    HelloVerifyRequest => 3
    Certificate => 11
    ServerKeyExchange => 12
    CertificateRequest => 13
    ServerHelloDone => 14
    CertificateVerify => 15
    ClientKeyExchange => 16
    Finished => 20
    UnknownHandshake(value) => value
  }
}

///|
pub struct HandshakeFragment {
  handshake_type : HandshakeType
  total_length : UInt
  message_sequence : UInt16
  fragment_offset : UInt
  body : Bytes
} derive(Debug, Eq)

///|
pub fn HandshakeFragment::new(
  handshake_type~ : HandshakeType,
  total_length~ : UInt,
  message_sequence~ : UInt16,
  fragment_offset~ : UInt,
  body~ : Bytes,
) -> HandshakeFragment raise DtlsError {
  if total_length > 0xffffffU ||
    fragment_offset > total_length ||
    body.length() > 0xffffff ||
    fragment_offset.to_uint64() + body.length().to_uint64() >
    total_length.to_uint64() {
    raise InvalidHandshake("invalid DTLS handshake fragment bounds")
  }
  { handshake_type, total_length, message_sequence, fragment_offset, body }
}

///|
pub fn HandshakeFragment::handshake_type(
  self : HandshakeFragment,
) -> HandshakeType {
  self.handshake_type
}

///|
pub fn HandshakeFragment::total_length(self : HandshakeFragment) -> UInt {
  self.total_length
}

///|
pub fn HandshakeFragment::message_sequence(self : HandshakeFragment) -> UInt16 {
  self.message_sequence
}

///|
pub fn HandshakeFragment::fragment_offset(self : HandshakeFragment) -> UInt {
  self.fragment_offset
}

///|
pub fn HandshakeFragment::body(self : HandshakeFragment) -> Bytes {
  self.body
}

///|
pub fn HandshakeFragment::is_complete(self : HandshakeFragment) -> Bool {
  self.fragment_offset == 0U &&
  self.body.length().reinterpret_as_uint() == self.total_length
}

///|
priv struct EncryptionKeys {
  client_mac_key : Bytes
  server_mac_key : Bytes
  client_write_key : Bytes
  server_write_key : Bytes
  client_write_iv : Bytes
  server_write_iv : Bytes
}
