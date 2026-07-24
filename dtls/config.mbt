///|
pub struct Config {
  role : Role
  identity : CertificateIdentity
  expected_peer_fingerprint : Fingerprint
  wall_time : @transport.WallTime
  cipher_suites : Array[CipherSuite]
  psk : Bytes?
  psk_identity : Bytes?
  srtp_profiles : Array[SrtpProtectionProfile]
  flight_interval : @transport.Duration
  mtu : Int
  replay_window : Int
  verify_peer_fingerprint : Bool
}

///|
pub fn Config::new(
  role~ : Role,
  identity~ : CertificateIdentity,
  expected_peer_fingerprint~ : Fingerprint,
  wall_time~ : @transport.WallTime,
  cipher_suites? : Array[CipherSuite] = [],
  psk? : Bytes,
  psk_identity? : Bytes,
  srtp_profiles? : Array[SrtpProtectionProfile] = [],
  flight_interval? : @transport.Duration,
  mtu? : Int = 1200,
  replay_window? : Int = 64,
  verify_peer_fingerprint? : Bool = true,
) -> Config raise DtlsError {
  if role == Auto {
    raise HandshakeFailed("DTLS setup role must be resolved before start")
  }
  if mtu < 256 || mtu > 65535 {
    raise HandshakeFailed("DTLS MTU must be between 256 and 65535 bytes")
  }
  if replay_window < 1 || replay_window > 64 {
    raise HandshakeFailed("DTLS replay window must be between 1 and 64")
  }
  let cipher_suites = if cipher_suites.is_empty() {
    if psk is Some(_) {
      [PskAes128GcmSha256, PskAes128Ccm, PskAes128Ccm8]
    } else {
      [
        EcdheEcdsaAes128GcmSha256,
        EcdheEcdsaAes256CbcSha,
        EcdheEcdsaChacha20Poly1305Sha256,
        EcdheEcdsaAes128Ccm,
        EcdheEcdsaAes128Ccm8,
      ]
    }
  } else {
    cipher_suites.copy()
  }
  let seen_suites : Map[UInt16, Bool] = Map([])
  for suite in cipher_suites {
    if seen_suites.contains(suite.code()) {
      raise HandshakeFailed("duplicate DTLS cipher suite")
    }
    seen_suites[suite.code()] = true
    if suite.is_psk() != (psk is Some(_)) {
      raise HandshakeFailed(
        "PSK credentials and DTLS cipher-suite type do not match",
      )
    }
  }
  match (psk, psk_identity) {
    (Some(key), Some(identity)) => {
      if key.is_empty() || key.length() > 0xffff {
        raise HandshakeFailed("DTLS PSK must contain 1..65535 bytes")
      }
      if identity.is_empty() || identity.length() > 0xffff {
        raise HandshakeFailed("DTLS PSK identity must contain 1..65535 bytes")
      }
    }
    (Some(_), None) =>
      raise HandshakeFailed("DTLS PSK requires a local identity")
    (None, Some(_)) => raise HandshakeFailed("DTLS PSK identity requires a key")
    (None, None) => ()
  }
  let seen : Map[UInt16, Bool] = Map([])
  for profile in srtp_profiles {
    if seen.contains(profile.code()) {
      raise HandshakeFailed("duplicate SRTP protection profile")
    }
    seen[profile.code()] = true
  }
  let flight_interval = match flight_interval {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(1000) catch {
        NegativeDuration(value) =>
          raise HandshakeFailed("invalid flight interval \{value}")
        NegativeMonotonicTime(value) =>
          raise HandshakeFailed("invalid monotonic time \{value}")
        TimeOverflow => raise HandshakeFailed("flight interval overflow")
      }
  }
  if flight_interval.as_milliseconds() == 0L {
    raise HandshakeFailed("DTLS flight interval must be positive")
  }
  {
    role,
    identity,
    expected_peer_fingerprint,
    wall_time,
    cipher_suites,
    psk,
    psk_identity,
    srtp_profiles: srtp_profiles.copy(),
    flight_interval,
    mtu,
    replay_window,
    verify_peer_fingerprint,
  }
}

///|
pub fn Config::role(self : Config) -> Role {
  self.role
}

///|
pub fn Config::local_fingerprint(self : Config) -> Fingerprint raise DtlsError {
  self.identity.fingerprint(algorithm=self.expected_peer_fingerprint.algorithm)
}

///|
pub fn Config::srtp_profiles(self : Config) -> Array[SrtpProtectionProfile] {
  self.srtp_profiles.copy()
}

///|
pub fn Config::cipher_suites(self : Config) -> Array[CipherSuite] {
  self.cipher_suites.copy()
}

///|
pub fn Config::psk_identity(self : Config) -> Bytes? {
  self.psk_identity
}

///|
fn Config::maximum_record_expansion(self : Config) -> Int {
  let mut result = 0
  for suite in self.cipher_suites {
    let expansion = suite.maximum_record_expansion()
    if expansion > result {
      result = expansion
    }
  }
  result
}

///|
pub(all) enum AlertLevel {
  WarningAlert
  FatalAlert
} derive(Debug, Eq)

///|
pub(all) enum AlertDescription {
  CloseNotify
  UnexpectedMessage
  BadRecordMac
  HandshakeFailure
  BadCertificate
  IllegalParameter
  DecodeError
  DecryptError
  ProtocolVersionAlert
  InternalError
  UnsupportedExtension
  UnknownAlert(Byte)
} derive(Debug, Eq)

///|
pub(all) enum DtlsEvent {
  StateChanged(State)
  ConnectedWithSrtp(SrtpProtectionProfile?)
  ApplicationDataReceived(Bytes)
  AlertReceived(AlertLevel, AlertDescription)
} derive(Debug, Eq)
