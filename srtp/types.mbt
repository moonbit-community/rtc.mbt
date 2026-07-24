///|
pub(all) suberror SrtpError {
  InvalidPacket(String)
  AuthenticationFailed
  ReplayRejected
  KeyExpired
  CryptoUnavailable(String)
} derive(Debug, Eq)

///|
pub(all) enum ProtectionProfile {
  Aes128CmHmacSha1_80
  Aes128CmHmacSha1_32
  AeadAes128Gcm
  AeadAes256Gcm
} derive(Debug, Eq)

///|
pub fn ProtectionProfile::key_length(self : ProtectionProfile) -> Int {
  match self {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 | AeadAes128Gcm => 16
    AeadAes256Gcm => 32
  }
}

///|
pub fn ProtectionProfile::salt_length(self : ProtectionProfile) -> Int {
  match self {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => 14
    AeadAes128Gcm | AeadAes256Gcm => 12
  }
}

///|
pub fn ProtectionProfile::rtp_auth_tag_length(self : ProtectionProfile) -> Int {
  match self {
    Aes128CmHmacSha1_80 => 10
    Aes128CmHmacSha1_32 => 4
    AeadAes128Gcm | AeadAes256Gcm => 16
  }
}

///|
pub fn ProtectionProfile::rtcp_auth_tag_length(self : ProtectionProfile) -> Int {
  match self {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => 10
    AeadAes128Gcm | AeadAes256Gcm => 16
  }
}

///|
pub fn ProtectionProfile::code(self : ProtectionProfile) -> UInt16 {
  match self {
    Aes128CmHmacSha1_80 => 0x0001
    Aes128CmHmacSha1_32 => 0x0002
    AeadAes128Gcm => 0x0007
    AeadAes256Gcm => 0x0008
  }
}

///|
pub fn ProtectionProfile::from_code(
  code : UInt16,
) -> ProtectionProfile raise SrtpError {
  match code {
    0x0001 => Aes128CmHmacSha1_80
    0x0002 => Aes128CmHmacSha1_32
    0x0007 => AeadAes128Gcm
    0x0008 => AeadAes256Gcm
    _ => raise InvalidPacket("unsupported SRTP protection profile \{code}")
  }
}
