///|
enum HandshakePhase {
  ClientReady
  ClientWaitVerifyOrServer
  ClientWaitServerFlight
  ClientWaitServerFinished
  ServerReady
  ServerWaitClientHello
  ServerWaitClientFlight
  Established
  Terminal
} derive(Debug, Eq)

///|
priv struct EncodedHandshake {
  canonical : Bytes
  datagrams : Array[Bytes]
}

///|
pub struct Endpoint {
  config : Config
  provider : @crypto.Provider
  outputs : @queue.Queue[Bytes]
  events : @queue.Queue[DtlsEvent]
  mut state : State
  mut phase : HandshakePhase
  fragments : FragmentBuffer
  transcript : Array[Bytes]
  mut local_handshake_sequence : UInt16
  mut epoch_zero_sequence : UInt64
  mut epoch_one_sequence : UInt64
  mut client_random : Bytes?
  mut server_random : Bytes?
  mut initial_client_hello : Bytes?
  mut cookie : Bytes?
  mut local_ephemeral : @crypto.PrivateKey?
  mut peer_ephemeral : @crypto.PublicKey?
  mut peer_certificate_key : @crypto.PublicKey?
  mut master_secret : @crypto.Secret?
  mut cipher : RecordCipher?
  mut selected_cipher_suite : CipherSuite?
  mut selected_srtp_profile : SrtpProtectionProfile?
  mut certificate_requested : Bool
  mut client_server_stage : Int
  mut server_client_stage : Int
  mut peer_changed_cipher_spec : Bool
  mut last_flight : Array[Bytes]
  mut retransmit_deadline : @transport.Instant?
  mut retransmit_interval_milliseconds : Int64
  mut retransmissions : Int
}

///|
pub fn Endpoint::new(config : Config) -> Endpoint {
  let role = config.role
  {
    provider: config.identity.provider,
    config,
    outputs: Queue([]),
    events: Queue([]),
    state: New,
    phase: if role == Client {
      ClientReady
    } else {
      ServerReady
    },
    fragments: FragmentBuffer::new(),
    transcript: [],
    local_handshake_sequence: 0,
    epoch_zero_sequence: 0UL,
    epoch_one_sequence: 0UL,
    client_random: None,
    server_random: None,
    initial_client_hello: None,
    cookie: None,
    local_ephemeral: None,
    peer_ephemeral: None,
    peer_certificate_key: None,
    master_secret: None,
    cipher: None,
    selected_cipher_suite: None,
    selected_srtp_profile: None,
    certificate_requested: false,
    client_server_stage: 0,
    server_client_stage: 0,
    peer_changed_cipher_spec: false,
    last_flight: [],
    retransmit_deadline: None,
    retransmit_interval_milliseconds: 0L,
    retransmissions: 0,
  }
}

///|
pub fn Endpoint::state(self : Endpoint) -> State {
  self.state
}

///|
pub fn Endpoint::role(self : Endpoint) -> Role {
  self.config.role()
}

///|
pub fn Endpoint::selected_srtp_profile(
  self : Endpoint,
) -> SrtpProtectionProfile? {
  self.selected_srtp_profile
}

///|
pub fn Endpoint::selected_cipher_suite(self : Endpoint) -> CipherSuite? {
  self.selected_cipher_suite
}

///|
fn Endpoint::set_state(self : Endpoint, state : State) -> Unit {
  if self.state != state {
    self.state = state
    self.events.push(StateChanged(state))
  }
}

///|
fn dtls_after(
  now : @transport.Instant,
  milliseconds : Int64,
) -> @transport.Instant raise DtlsError {
  let duration = @transport.Duration::milliseconds(milliseconds) catch {
    error => raise Time(error)
  }
  now.checked_add(duration) catch {
    error => raise Time(error)
  }
}

///|
fn Endpoint::queue_flight(
  self : Endpoint,
  datagrams : Array[Bytes],
  now : @transport.Instant,
  schedule_retransmit? : Bool = true,
) -> Unit raise DtlsError {
  for datagram in datagrams {
    self.outputs.push(datagram)
  }
  self.last_flight = datagrams.copy()
  self.retransmissions = 0
  if schedule_retransmit {
    self.retransmit_interval_milliseconds = self.config.flight_interval.as_milliseconds()
    self.retransmit_deadline = Some(
      dtls_after(now, self.retransmit_interval_milliseconds),
    )
  } else {
    self.retransmit_deadline = None
  }
}

///|
fn Endpoint::requeue_last_flight(self : Endpoint) -> Unit {
  for datagram in self.last_flight {
    self.outputs.push(datagram)
  }
}

///|
fn Endpoint::next_record_sequence(
  self : Endpoint,
  encrypted : Bool,
) -> UInt64 raise DtlsError {
  let sequence = if encrypted {
    self.epoch_one_sequence
  } else {
    self.epoch_zero_sequence
  }
  if sequence > 0x0000ffffffffffffUL {
    raise HandshakeFailed("DTLS record sequence number exhausted")
  }
  if encrypted {
    self.epoch_one_sequence += 1UL
  } else {
    self.epoch_zero_sequence += 1UL
  }
  sequence
}

///|
fn Endpoint::record_datagram(
  self : Endpoint,
  content_type : ContentType,
  payload : Bytes,
  encrypted : Bool,
) -> Bytes raise DtlsError {
  let sequence_number = self.next_record_sequence(encrypted)
  let record = if encrypted {
    guard self.cipher is Some(cipher) else {
      raise HandshakeFailed("DTLS record cipher is not initialized")
    }
    cipher.seal(content_type~, epoch=1, sequence_number~, plaintext=payload)
  } else {
    Record::new(content_type~, epoch=0, sequence_number~, payload~)
  }
  record.encode()
}

///|
fn Endpoint::encode_handshake(
  self : Endpoint,
  message : HandshakeMessage,
  encrypted : Bool,
) -> EncodedHandshake raise DtlsError {
  if self.local_handshake_sequence == 0xffff {
    raise HandshakeFailed("DTLS handshake sequence number exhausted")
  }
  let message_sequence = self.local_handshake_sequence
  self.local_handshake_sequence += 1
  let body = message.encode_body()
  let complete = message.to_fragment(message_sequence)
  let canonical = complete.encode()
  let overhead = if encrypted {
    13 + self.config.maximum_record_expansion() + 12
  } else {
    13 + 12
  }
  let maximum_fragment_body = self.config.mtu - overhead
  if maximum_fragment_body < 1 {
    raise HandshakeFailed("DTLS MTU cannot carry a handshake fragment")
  }
  let datagrams : Array[Bytes] = []
  if body.is_empty() {
    datagrams.push(
      self.record_datagram(Handshake, complete.encode(), encrypted),
    )
  } else {
    let mut offset = 0
    while offset < body.length() {
      let end = if offset + maximum_fragment_body < body.length() {
        offset + maximum_fragment_body
      } else {
        body.length()
      }
      let fragment = HandshakeFragment::new(
        handshake_type=message.handshake_type(),
        total_length=body.length().reinterpret_as_uint(),
        message_sequence~,
        fragment_offset=offset.reinterpret_as_uint(),
        body=body[offset:end].to_owned(),
      )
      datagrams.push(
        self.record_datagram(Handshake, fragment.encode(), encrypted),
      )
      offset = end
    }
  }
  { canonical, datagrams }
}

///|
fn append_datagrams(destination : Array[Bytes], source : Array[Bytes]) -> Unit {
  for datagram in source {
    destination.push(datagram)
  }
}

///|
fn Endpoint::append_transcript(self : Endpoint, canonical : Bytes) -> Unit {
  self.transcript.push(canonical)
}

///|
fn Endpoint::transcript_bytes(self : Endpoint) -> Bytes {
  let result : Array[Byte] = []
  for message in self.transcript {
    for byte in message {
      result.push(byte)
    }
  }
  Bytes::from_array(result)
}

///|
fn Endpoint::random_bytes(
  self : Endpoint,
  length : Int,
) -> Bytes raise DtlsError {
  crypto_operation(() => self.provider.random_bytes(length))
}

///|
fn Endpoint::send_initial_client_hello(
  self : Endpoint,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  let random = self.random_bytes(32)
  self.client_random = Some(random)
  let message = ClientHelloHandshake(
    ClientHelloMessage::new(
      random~,
      cipher_suites=self.config.cipher_suites,
      extensions=HelloExtensions::webrtc(
        srtp_profiles=self.config.srtp_profiles,
      ),
    ),
  )
  let encoded = self.encode_handshake(message, false)
  self.initial_client_hello = Some(encoded.canonical)
  self.queue_flight(encoded.datagrams, now)
  self.phase = ClientWaitVerifyOrServer
}

///|
pub fn Endpoint::start(
  self : Endpoint,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  if self.state != New {
    raise HandshakeFailed("DTLS endpoint has already started")
  }
  self.set_state(Connecting)
  match self.phase {
    ClientReady => self.send_initial_client_hello(now)
    ServerReady => self.phase = ServerWaitClientHello
    _ => raise HandshakeFailed("invalid DTLS start phase")
  }
}

///|
pub fn Endpoint::poll_datagram(self : Endpoint) -> Bytes? {
  self.outputs.pop()
}

///|
pub fn Endpoint::poll_event(self : Endpoint) -> DtlsEvent? {
  self.events.pop()
}

///|
pub fn Endpoint::poll_timeout(self : Endpoint) -> @transport.Instant? {
  self.retransmit_deadline
}

///|
pub fn Endpoint::handle_timeout(
  self : Endpoint,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  if self.state == Closed || self.state == Failed || self.state == Connected {
    return
  }
  guard self.retransmit_deadline is Some(deadline) else { return }
  if deadline > now {
    return
  }
  if self.retransmissions >= 7 {
    self.phase = Terminal
    self.retransmit_deadline = None
    self.set_state(Failed)
    raise HandshakeFailed("DTLS handshake retransmission limit reached")
  }
  self.requeue_last_flight()
  self.retransmissions += 1
  self.retransmit_interval_milliseconds = if self.retransmit_interval_milliseconds <
    60000L {
    let doubled = self.retransmit_interval_milliseconds * 2L
    if doubled < 60000L {
      doubled
    } else {
      60000L
    }
  } else {
    60000L
  }
  self.retransmit_deadline = Some(
    dtls_after(now, self.retransmit_interval_milliseconds),
  )
}

///|
fn SrtpProtectionProfile::from_code(
  code : UInt16,
) -> SrtpProtectionProfile raise DtlsError {
  match code {
    0x0001 => SrtpAes128CmHmacSha1_80
    0x0002 => SrtpAes128CmHmacSha1_32
    0x0007 => SrtpAeadAes128Gcm
    0x0008 => SrtpAeadAes256Gcm
    _ => raise UnsupportedSrtpProfile(code)
  }
}

///|
fn Endpoint::select_srtp_profile(
  self : Endpoint,
  offered : Array[UInt16],
) -> SrtpProtectionProfile? raise DtlsError {
  if self.config.srtp_profiles.is_empty() {
    return None
  }
  for profile in self.config.srtp_profiles {
    if offered.contains(profile.code()) {
      return Some(profile)
    }
  }
  raise HandshakeFailed("no common SRTP protection profile")
}

///|
fn Endpoint::validate_server_srtp(
  self : Endpoint,
  selected : Array[UInt16],
) -> Unit raise DtlsError {
  if self.config.srtp_profiles.is_empty() {
    if !selected.is_empty() {
      raise HandshakeFailed("server selected an unoffered SRTP profile")
    }
    self.selected_srtp_profile = None
    return
  }
  if selected.length() != 1 {
    raise HandshakeFailed("server must select exactly one SRTP profile")
  }
  let profile = SrtpProtectionProfile::from_code(selected[0])
  if !self.config.srtp_profiles.contains(profile) {
    raise HandshakeFailed("server selected an unoffered SRTP profile")
  }
  self.selected_srtp_profile = Some(profile)
}

///|
fn Endpoint::send_cookie_client_hello(
  self : Endpoint,
  cookie : Bytes,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  guard self.client_random is Some(random) else {
    raise HandshakeFailed("ClientHello random is missing")
  }
  let message = ClientHelloHandshake(
    ClientHelloMessage::new(
      random~,
      cookie~,
      cipher_suites=self.config.cipher_suites,
      extensions=HelloExtensions::webrtc(
        srtp_profiles=self.config.srtp_profiles,
      ),
    ),
  )
  let encoded = self.encode_handshake(message, false)
  self.transcript.clear()
  self.append_transcript(encoded.canonical)
  self.queue_flight(encoded.datagrams, now)
  self.phase = ClientWaitServerFlight
  self.client_server_stage = 0
}

///|
fn Endpoint::server_key_exchange_signature_input(
  self : Endpoint,
  message : ServerKeyExchangeMessage,
) -> Bytes raise DtlsError {
  guard self.client_random is Some(client_random) else {
    raise HandshakeFailed("client random is missing")
  }
  guard self.server_random is Some(server_random) else {
    raise HandshakeFailed("server random is missing")
  }
  append_three(client_random, server_random, message.parameters())
}

///|
fn cipher_suite_signature(
  suite : CipherSuite,
) -> (UInt16, @crypto.SignatureAlgorithm, Byte, CertificateKeyType) raise DtlsError {
  if suite.is_psk() {
    raise HandshakeFailed("PSK cipher suite does not use certificates")
  }
  if suite.uses_rsa() {
    (0x0401, RsaPkcs1Sha256, 1, RsaCertificate)
  } else {
    (0x0403, EcdsaSha256, 64, EcdsaCertificate)
  }
}

///|
fn Endpoint::send_server_flight(
  self : Endpoint,
  now : @transport.Instant,
  client_hello : ClientHelloMessage,
) -> Unit raise DtlsError {
  let mut selected_suite : CipherSuite? = None
  for suite in self.config.cipher_suites {
    if client_hello.cipher_suites.contains(suite.code()) {
      selected_suite = Some(suite)
      break
    }
  }
  guard selected_suite is Some(selected_suite) else {
    raise HandshakeFailed("no common DTLS cipher suite")
  }
  self.selected_cipher_suite = Some(selected_suite)
  if !client_hello.extensions.extended_master_secret {
    raise HandshakeFailed("client lacks extended master secret")
  }
  if !selected_suite.is_psk() && !client_hello.extensions.supports_group(23) {
    raise HandshakeFailed("client lacks the P-256 group")
  }
  self.selected_srtp_profile = self.select_srtp_profile(
    client_hello.extensions.srtp_profiles,
  )
  let server_random = self.random_bytes(32)
  self.server_random = Some(server_random)
  let selected_srtp_profile = self.selected_srtp_profile.map(profile => {
    profile.code()
  })
  let messages : Array[HandshakeMessage] = []
  messages.push(
    ServerHelloHandshake(
      ServerHelloMessage::new(
        random=server_random,
        cipher_suite=selected_suite,
        selected_srtp_profile?,
      ),
    ),
  )
  if selected_suite.is_psk() {
    guard self.config.psk_identity is Some(identity_hint) else {
      raise HandshakeFailed("DTLS PSK identity is missing")
    }
    messages.push(
      ServerKeyExchangeHandshake({
        named_curve: 0,
        public_key: b"",
        signature_algorithm: 0,
        signature: b"",
        identity_hint: Some(identity_hint),
      }),
    )
  } else {
    let (
      signature_code,
      signature_algorithm,
      certificate_type,
      required_key_type,
    ) = cipher_suite_signature(selected_suite)
    if self.config.identity.key_type != required_key_type {
      raise HandshakeFailed(
        "local certificate key does not match the selected cipher suite",
      )
    }
    if !client_hello.extensions.signature_algorithms.contains(signature_code) {
      raise HandshakeFailed("client lacks the selected signature algorithm")
    }
    let local_ephemeral = crypto_operation(() => {
      self.provider.generate_private_key(P256)
    })
    let public_point = self.config.identity.ephemeral_public_point(
      local_ephemeral,
    )
    self.local_ephemeral = Some(local_ephemeral)
    messages.push(
      CertificateHandshake({
        certificates: [self.config.identity.certificate_der],
      }),
    )
    let unsigned_key_exchange : ServerKeyExchangeMessage = {
      named_curve: 23,
      public_key: public_point,
      signature_algorithm: signature_code,
      signature: b"",
      identity_hint: None,
    }
    let key_exchange : ServerKeyExchangeMessage = {
      ..unsigned_key_exchange,
      signature: self.config.identity.sign(
        signature_algorithm,
        self.server_key_exchange_signature_input(unsigned_key_exchange),
      ),
    }
    messages.push(ServerKeyExchangeHandshake(key_exchange))
    messages.push(
      CertificateRequestHandshake(
        CertificateRequestMessage::webrtc(certificate_type, signature_code),
      ),
    )
  }
  messages.push(ServerHelloDoneHandshake)
  let datagrams : Array[Bytes] = []
  for message in messages {
    let encoded = self.encode_handshake(message, false)
    self.append_transcript(encoded.canonical)
    append_datagrams(datagrams, encoded.datagrams)
  }
  self.queue_flight(datagrams, now)
  self.phase = ServerWaitClientFlight
  self.server_client_stage = 0
}

///|
fn Endpoint::derive_cipher(self : Endpoint) -> Unit raise DtlsError {
  guard self.client_random is Some(client_random) else {
    raise HandshakeFailed("client random is missing")
  }
  guard self.server_random is Some(server_random) else {
    raise HandshakeFailed("server random is missing")
  }
  guard self.selected_cipher_suite is Some(selected_cipher_suite) else {
    raise HandshakeFailed("DTLS cipher suite is missing")
  }
  let pre_master_secret = if selected_cipher_suite.is_psk() {
    guard self.config.psk is Some(psk) else {
      raise HandshakeFailed("DTLS PSK is missing")
    }
    psk_pre_master_secret(psk)
  } else {
    guard self.local_ephemeral is Some(local_ephemeral) else {
      raise HandshakeFailed("local ECDHE key is missing")
    }
    guard self.peer_ephemeral is Some(peer_ephemeral) else {
      raise HandshakeFailed("peer ECDHE key is missing")
    }
    crypto_operation(() => {
      self.provider.derive_shared_secret(local_ephemeral, peer_ephemeral)
    })
  }
  let session_hash = transcript_hash(self.transcript_bytes())
  let master_secret = extended_master_secret_key(
    pre_master_secret, session_hash,
  )
  let keys = encryption_keys_for_secret(
    master_secret,
    client_random,
    server_random,
    suite=selected_cipher_suite,
  )
  self.cipher = Some(
    RecordCipher::new(
      keys,
      self.config.role,
      suite=selected_cipher_suite,
      replay_window=self.config.replay_window,
    ),
  )
  self.master_secret = Some(master_secret)
}

///|
fn Endpoint::encode_change_cipher_spec(
  self : Endpoint,
) -> Bytes raise DtlsError {
  self.record_datagram(ChangeCipherSpec, b"\x01", false)
}

///|
fn Endpoint::send_client_flight(
  self : Endpoint,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  guard self.selected_cipher_suite is Some(selected_cipher_suite) else {
    raise HandshakeFailed("DTLS cipher suite is missing")
  }
  let datagrams : Array[Bytes] = []
  if selected_cipher_suite.is_psk() {
    guard self.config.psk_identity is Some(identity) else {
      raise HandshakeFailed("DTLS PSK identity is missing")
    }
    let key_exchange = self.encode_handshake(
      ClientKeyExchangeHandshake({
        public_key: b"",
        identity_hint: Some(identity),
      }),
      false,
    )
    self.append_transcript(key_exchange.canonical)
    append_datagrams(datagrams, key_exchange.datagrams)
    self.derive_cipher()
  } else {
    guard self.peer_ephemeral is Some(_) else {
      raise HandshakeFailed("server ECDHE key is missing")
    }
    let local_ephemeral = crypto_operation(() => {
      self.provider.generate_private_key(P256)
    })
    let public_point = self.config.identity.ephemeral_public_point(
      local_ephemeral,
    )
    self.local_ephemeral = Some(local_ephemeral)
    let (signature_code, signature_algorithm, _, required_key_type) = cipher_suite_signature(
      selected_cipher_suite,
    )
    if self.certificate_requested &&
      self.config.identity.key_type != required_key_type {
      raise HandshakeFailed(
        "local certificate key does not match the selected cipher suite",
      )
    }
    if self.certificate_requested {
      let certificate = self.encode_handshake(
        CertificateHandshake({
          certificates: [self.config.identity.certificate_der],
        }),
        false,
      )
      self.append_transcript(certificate.canonical)
      append_datagrams(datagrams, certificate.datagrams)
    }
    let key_exchange = self.encode_handshake(
      ClientKeyExchangeHandshake({
        public_key: public_point,
        identity_hint: None,
      }),
      false,
    )
    self.append_transcript(key_exchange.canonical)
    append_datagrams(datagrams, key_exchange.datagrams)
    self.derive_cipher()
    if self.certificate_requested {
      let signature = self.config.identity.sign(
        signature_algorithm,
        self.transcript_bytes(),
      )
      let certificate_verify = self.encode_handshake(
        CertificateVerifyHandshake({
          signature_algorithm: signature_code,
          signature,
        }),
        false,
      )
      self.append_transcript(certificate_verify.canonical)
      append_datagrams(datagrams, certificate_verify.datagrams)
    }
  }
  datagrams.push(self.encode_change_cipher_spec())
  guard self.master_secret is Some(master_secret) else {
    raise HandshakeFailed("DTLS master secret is missing")
  }
  let verify_data = client_verify_data_for_secret(
    master_secret,
    self.transcript_bytes(),
  )
  let finished = self.encode_handshake(
    FinishedHandshake({ verify_data, }),
    true,
  )
  self.append_transcript(finished.canonical)
  append_datagrams(datagrams, finished.datagrams)
  self.peer_changed_cipher_spec = false
  self.queue_flight(datagrams, now)
  self.phase = ClientWaitServerFinished
}

///|
fn Endpoint::validate_peer_certificate(
  self : Endpoint,
  message : CertificateMessage,
) -> Unit raise DtlsError {
  if message.certificates.is_empty() {
    raise HandshakeFailed("peer did not provide a certificate")
  }
  self.peer_certificate_key = Some(
    verify_peer_certificate(
      self.provider,
      message.certificates[0],
      self.config.expected_peer_fingerprint,
      self.config.wall_time,
      verify_fingerprint=self.config.verify_peer_fingerprint,
    ),
  )
}

///|
fn Endpoint::process_server_flight_message(
  self : Endpoint,
  message : HandshakeMessage,
  canonical : Bytes,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  match (self.client_server_stage, message) {
    (0, ServerHelloHandshake(server_hello)) => {
      let selected_suite = CipherSuite::from_code(server_hello.cipher_suite)
      if !self.config.cipher_suites.contains(selected_suite) {
        raise HandshakeFailed("server selected an unoffered cipher suite")
      }
      self.selected_cipher_suite = Some(selected_suite)
      if !server_hello.extensions.extended_master_secret {
        raise HandshakeFailed("server did not negotiate extended master secret")
      }
      self.validate_server_srtp(server_hello.extensions.srtp_profiles)
      self.server_random = Some(server_hello.random)
      self.append_transcript(canonical)
      self.client_server_stage = 1
    }
    (1, ServerKeyExchangeHandshake(key_exchange)) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) &&
        selected_cipher_suite.is_psk() else {
        raise HandshakeFailed("unexpected PSK ServerKeyExchange")
      }
      guard key_exchange.identity_hint is Some(identity_hint) &&
        !identity_hint.is_empty() else {
        raise HandshakeFailed("server omitted its PSK identity hint")
      }
      self.append_transcript(canonical)
      self.client_server_stage = 2
    }
    (1, CertificateHandshake(certificate)) => {
      self.validate_peer_certificate(certificate)
      self.append_transcript(canonical)
      self.client_server_stage = 2
    }
    (2, ServerKeyExchangeHandshake(key_exchange)) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) else {
        raise HandshakeFailed("DTLS cipher suite is missing")
      }
      let (signature_code, signature_algorithm, _, _) = cipher_suite_signature(
        selected_cipher_suite,
      )
      if key_exchange.named_curve != 23 ||
        key_exchange.signature_algorithm != signature_code {
        raise HandshakeFailed(
          "server selected unsupported ECDHE/signature algorithms",
        )
      }
      guard self.peer_certificate_key is Some(peer_certificate_key) else {
        raise HandshakeFailed("server certificate key is missing")
      }
      let signature_input = self.server_key_exchange_signature_input(
        key_exchange,
      )
      let valid = crypto_operation(() => {
        self.provider.verify(
          signature_algorithm,
          peer_certificate_key,
          signature_input,
          key_exchange.signature,
        )
      })
      if !valid {
        raise HandshakeFailed("ServerKeyExchange signature is invalid")
      }
      self.peer_ephemeral = Some(
        p256_public_key(self.provider, key_exchange.public_key),
      )
      self.append_transcript(canonical)
      self.client_server_stage = 3
    }
    (3, CertificateRequestHandshake(request)) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) else {
        raise HandshakeFailed("DTLS cipher suite is missing")
      }
      let (signature_code, _, certificate_type, required_key_type) = cipher_suite_signature(
        selected_cipher_suite,
      )
      if self.config.identity.key_type != required_key_type ||
        !request.certificate_types.contains(certificate_type) ||
        !request.signature_algorithms.contains(signature_code) {
        raise HandshakeFailed(
          "server does not accept the configured client certificate",
        )
      }
      self.certificate_requested = true
      self.append_transcript(canonical)
      self.client_server_stage = 4
    }
    (2, ServerHelloDoneHandshake) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) &&
        selected_cipher_suite.is_psk() else {
        raise HandshakeFailed("unexpected PSK ServerHelloDone")
      }
      self.append_transcript(canonical)
      self.send_client_flight(now)
    }
    (3, ServerHelloDoneHandshake) => {
      self.append_transcript(canonical)
      self.send_client_flight(now)
    }
    (4, ServerHelloDoneHandshake) => {
      self.append_transcript(canonical)
      self.send_client_flight(now)
    }
    _ => raise HandshakeFailed("unexpected message in DTLS server flight")
  }
}

///|
fn Endpoint::process_client_flight_message(
  self : Endpoint,
  message : HandshakeMessage,
  canonical : Bytes,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  match (self.server_client_stage, message) {
    (0, ClientKeyExchangeHandshake(key_exchange)) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) &&
        selected_cipher_suite.is_psk() else {
        raise HandshakeFailed("unexpected PSK ClientKeyExchange")
      }
      guard key_exchange.identity_hint is Some(identity) &&
        self.config.psk_identity is Some(expected_identity) else {
        raise HandshakeFailed("client omitted its PSK identity")
      }
      if !self.provider.constant_time_equal(identity, expected_identity) {
        raise HandshakeFailed("client supplied an unknown PSK identity")
      }
      self.append_transcript(canonical)
      self.derive_cipher()
      self.server_client_stage = 3
    }
    (0, CertificateHandshake(certificate)) => {
      self.validate_peer_certificate(certificate)
      self.append_transcript(canonical)
      self.server_client_stage = 1
    }
    (1, ClientKeyExchangeHandshake(key_exchange)) => {
      self.peer_ephemeral = Some(
        p256_public_key(self.provider, key_exchange.public_key),
      )
      self.append_transcript(canonical)
      self.derive_cipher()
      self.server_client_stage = 2
    }
    (2, CertificateVerifyHandshake(certificate_verify)) => {
      guard self.selected_cipher_suite is Some(selected_cipher_suite) else {
        raise HandshakeFailed("DTLS cipher suite is missing")
      }
      let (signature_code, signature_algorithm, _, _) = cipher_suite_signature(
        selected_cipher_suite,
      )
      if certificate_verify.signature_algorithm != signature_code {
        raise HandshakeFailed(
          "client selected an unsupported signature algorithm",
        )
      }
      guard self.peer_certificate_key is Some(peer_certificate_key) else {
        raise HandshakeFailed("client certificate key is missing")
      }
      let valid = crypto_operation(() => {
        self.provider.verify(
          signature_algorithm,
          peer_certificate_key,
          self.transcript_bytes(),
          certificate_verify.signature,
        )
      })
      if !valid {
        raise HandshakeFailed("CertificateVerify signature is invalid")
      }
      self.append_transcript(canonical)
      self.server_client_stage = 3
    }
    (3, FinishedHandshake(finished)) => {
      if !self.peer_changed_cipher_spec {
        raise HandshakeFailed("Finished arrived before ChangeCipherSpec")
      }
      guard self.master_secret is Some(master_secret) else {
        raise HandshakeFailed("DTLS master secret is missing")
      }
      let expected = client_verify_data_for_secret(
        master_secret,
        self.transcript_bytes(),
      )
      if !self.provider.constant_time_equal(expected, finished.verify_data) {
        raise HandshakeFailed("client Finished verification failed")
      }
      self.append_transcript(canonical)
      self.send_server_finished(now)
    }
    _ => raise HandshakeFailed("unexpected message in DTLS client flight")
  }
}

///|
fn Endpoint::send_server_finished(
  self : Endpoint,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  guard self.master_secret is Some(master_secret) else {
    raise HandshakeFailed("DTLS master secret is missing")
  }
  let datagrams : Array[Bytes] = [self.encode_change_cipher_spec()]
  let verify_data = server_verify_data_for_secret(
    master_secret,
    self.transcript_bytes(),
  )
  let finished = self.encode_handshake(
    FinishedHandshake({ verify_data, }),
    true,
  )
  self.append_transcript(finished.canonical)
  append_datagrams(datagrams, finished.datagrams)
  self.queue_flight(datagrams, now, schedule_retransmit=false)
  self.phase = Established
  self.set_state(Connected)
  self.events.push(ConnectedWithSrtp(self.selected_srtp_profile))
}

///|
fn Endpoint::process_client_server_finished(
  self : Endpoint,
  message : HandshakeMessage,
  canonical : Bytes,
) -> Unit raise DtlsError {
  guard message is FinishedHandshake(finished) else {
    raise HandshakeFailed("client expected the server Finished message")
  }
  if !self.peer_changed_cipher_spec {
    raise HandshakeFailed("Finished arrived before ChangeCipherSpec")
  }
  guard self.master_secret is Some(master_secret) else {
    raise HandshakeFailed("DTLS master secret is missing")
  }
  let expected = server_verify_data_for_secret(
    master_secret,
    self.transcript_bytes(),
  )
  if !self.provider.constant_time_equal(expected, finished.verify_data) {
    raise HandshakeFailed("server Finished verification failed")
  }
  self.append_transcript(canonical)
  self.retransmit_deadline = None
  self.phase = Established
  self.set_state(Connected)
  self.events.push(ConnectedWithSrtp(self.selected_srtp_profile))
}

///|
fn Endpoint::process_handshake_fragment(
  self : Endpoint,
  fragment : HandshakeFragment,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  let (ready, duplicate) = self.fragments.insert(fragment)
  if duplicate {
    self.requeue_last_flight()
    return
  }
  for complete in ready {
    let canonical = complete.encode()
    let message = HandshakeMessage::decode(complete)
    match self.phase {
      ClientWaitVerifyOrServer =>
        match message {
          HelloVerifyRequestHandshake(verify_request) => {
            if verify_request.cookie.is_empty() {
              raise HandshakeFailed("HelloVerifyRequest cookie is empty")
            }
            self.send_cookie_client_hello(verify_request.cookie, now)
          }
          ServerHelloHandshake(_) => {
            guard self.initial_client_hello is Some(initial) else {
              raise HandshakeFailed("initial ClientHello is missing")
            }
            self.transcript.clear()
            self.append_transcript(initial)
            self.phase = ClientWaitServerFlight
            self.client_server_stage = 0
            self.process_server_flight_message(message, canonical, now)
          }
          _ =>
            raise HandshakeFailed(
              "client expected HelloVerifyRequest or ServerHello",
            )
        }
      ClientWaitServerFlight =>
        self.process_server_flight_message(message, canonical, now)
      ClientWaitServerFinished =>
        self.process_client_server_finished(message, canonical)
      ServerWaitClientHello =>
        match message {
          ClientHelloHandshake(client_hello) =>
            match self.cookie {
              None => {
                if !client_hello.cookie.is_empty() {
                  raise HandshakeFailed("unexpected ClientHello cookie")
                }
                self.client_random = Some(client_hello.random)
                let cookie = self.random_bytes(20)
                self.cookie = Some(cookie)
                let encoded = self.encode_handshake(
                  HelloVerifyRequestHandshake({ cookie, }),
                  false,
                )
                self.queue_flight(encoded.datagrams, now)
              }
              Some(expected_cookie) => {
                if !self.provider.constant_time_equal(
                    expected_cookie,
                    client_hello.cookie,
                  ) {
                  raise HandshakeFailed("ClientHello cookie is invalid")
                }
                self.client_random = Some(client_hello.random)
                self.transcript.clear()
                self.append_transcript(canonical)
                self.send_server_flight(now, client_hello)
              }
            }
          _ => raise HandshakeFailed("server expected ClientHello")
        }
      ServerWaitClientFlight =>
        self.process_client_flight_message(message, canonical, now)
      Established => self.requeue_last_flight()
      _ => raise HandshakeFailed("unexpected DTLS handshake message")
    }
  }
}

///|
fn AlertLevel::code(self : AlertLevel) -> Byte {
  match self {
    WarningAlert => 1
    FatalAlert => 2
  }
}

///|
fn AlertDescription::code(self : AlertDescription) -> Byte {
  match self {
    CloseNotify => 0
    UnexpectedMessage => 10
    BadRecordMac => 20
    HandshakeFailure => 40
    BadCertificate => 42
    IllegalParameter => 47
    ProtocolVersionAlert => 70
    InternalError => 80
    DecodeError => 50
    DecryptError => 51
    UnsupportedExtension => 110
    UnknownAlert(code) => code
  }
}

///|
fn AlertLevel::from_code(code : Byte) -> AlertLevel raise DtlsError {
  match code {
    1 => WarningAlert
    2 => FatalAlert
    _ => raise InvalidRecord("invalid DTLS alert level")
  }
}

///|
fn AlertDescription::from_code(code : Byte) -> AlertDescription {
  match code {
    0 => CloseNotify
    10 => UnexpectedMessage
    20 => BadRecordMac
    40 => HandshakeFailure
    42 => BadCertificate
    47 => IllegalParameter
    50 => DecodeError
    51 => DecryptError
    70 => ProtocolVersionAlert
    80 => InternalError
    110 => UnsupportedExtension
    _ => UnknownAlert(code)
  }
}

///|
fn Endpoint::queue_alert(
  self : Endpoint,
  level : AlertLevel,
  description : AlertDescription,
) -> Unit raise DtlsError {
  let encrypted = self.cipher is Some(_) && self.state == Connected
  self.outputs.push(
    self.record_datagram(
      Alert,
      Bytes::from_array([level.code(), description.code()]),
      encrypted,
    ),
  )
}

///|
fn Endpoint::handle_alert(
  self : Endpoint,
  payload : Bytes,
) -> Unit raise DtlsError {
  if payload.length() != 2 {
    raise InvalidRecord("DTLS alert must contain two bytes")
  }
  let level = AlertLevel::from_code(payload[0])
  let description = AlertDescription::from_code(payload[1])
  self.events.push(AlertReceived(level, description))
  if description == CloseNotify {
    if self.state != Closed {
      self.queue_alert(WarningAlert, CloseNotify)
      self.phase = Terminal
      self.retransmit_deadline = None
      self.set_state(Closed)
    }
  } else if level == FatalAlert {
    self.phase = Terminal
    self.retransmit_deadline = None
    self.set_state(Failed)
    raise HandshakeFailed("peer sent a fatal DTLS alert")
  }
}

///|
fn Endpoint::handle_record(
  self : Endpoint,
  record : Record,
  now : @transport.Instant,
) -> Unit raise DtlsError {
  if record.header.epoch > 1 {
    raise InvalidRecord("unsupported DTLS epoch")
  }
  let payload = if record.header.epoch == 1 {
    guard self.cipher is Some(cipher) else {
      raise InvalidRecord("encrypted DTLS record arrived before key setup")
    }
    cipher.open(record)
  } else {
    record.payload
  }
  match record.header.content_type {
    Handshake => {
      if record.header.epoch == 1 && !self.peer_changed_cipher_spec {
        raise HandshakeFailed("encrypted handshake preceded ChangeCipherSpec")
      }
      for fragment in decode_handshakes(payload) {
        self.process_handshake_fragment(fragment, now)
      }
    }
    ChangeCipherSpec => {
      if record.header.epoch != 0 || payload != b"\x01" {
        raise InvalidRecord("invalid DTLS ChangeCipherSpec record")
      }
      if self.cipher is None {
        raise HandshakeFailed(
          "ChangeCipherSpec arrived before cipher initialization",
        )
      }
      self.peer_changed_cipher_spec = true
    }
    ApplicationData => {
      if record.header.epoch != 1 || self.state != Connected {
        raise InvalidRecord("application data arrived before DTLS connected")
      }
      self.events.push(ApplicationDataReceived(payload))
    }
    Alert => self.handle_alert(payload)
  }
}

///|
fn DtlsError::alert_description(self : DtlsError) -> AlertDescription {
  match self {
    InvalidRecord(_) | InvalidHandshake(_) => DecodeError
    UnsupportedVersion => ProtocolVersionAlert
    UnsupportedCipherSuite(_) | HandshakeFailed(_) => HandshakeFailure
    UnsupportedSrtpProfile(_) => UnsupportedExtension
    FingerprintMismatch => BadCertificate
    ReplayRejected => BadRecordMac
    CryptoUnavailable(_) | Time(_) => InternalError
    Closed => CloseNotify
  }
}

///|
fn Endpoint::fail(self : Endpoint, error : DtlsError) -> Unit {
  ignore(
    self.queue_alert(FatalAlert, error.alert_description()) catch {
      _ => ()
    },
  )
  self.phase = Terminal
  self.retransmit_deadline = None
  self.set_state(Failed)
}

///|
fn Endpoint::handle_datagram_impl(
  self : Endpoint,
  now : @transport.Instant,
  datagram : Bytes,
) -> Unit raise DtlsError {
  if self.state == New {
    raise HandshakeFailed("DTLS endpoint has not started")
  }
  if self.state == Closed || self.state == Failed {
    raise Closed
  }
  for record in decode_records(datagram) {
    self.handle_record(record, now) catch {
      ReplayRejected => {
        self.requeue_last_flight()
        continue
      }
      error => raise error
    }
  }
}

///|
pub fn Endpoint::handle_datagram(
  self : Endpoint,
  now : @transport.Instant,
  datagram : Bytes,
) -> Unit raise DtlsError {
  let result : Result[Unit, DtlsError] = try {
    self.handle_datagram_impl(now, datagram)
    Ok(())
  } catch {
    error => Err(error)
  }
  match result {
    Ok(_) => ()
    Err(error) => {
      self.fail(error)
      raise error
    }
  }
}

///|
pub fn Endpoint::send_application_data(
  self : Endpoint,
  payload : Bytes,
) -> Unit raise DtlsError {
  if self.state != Connected {
    raise HandshakeFailed("DTLS endpoint is not connected")
  }
  if payload.length() >
    self.config.mtu - 13 - self.config.maximum_record_expansion() {
    raise InvalidRecord("DTLS application datagram exceeds configured MTU")
  }
  self.outputs.push(self.record_datagram(ApplicationData, payload, true))
}

///|
pub fn Endpoint::export_keying_material(
  self : Endpoint,
  label : String,
  length : Int,
) -> Bytes raise DtlsError {
  if self.state != Connected {
    raise HandshakeFailed("DTLS exporter is unavailable before connection")
  }
  guard self.master_secret is Some(master_secret) else {
    raise HandshakeFailed("DTLS master secret is missing")
  }
  guard self.client_random is Some(client_random) else {
    raise HandshakeFailed("client random is missing")
  }
  guard self.server_random is Some(server_random) else {
    raise HandshakeFailed("server random is missing")
  }
  if length < 0 {
    raise InvalidHandshake("TLS exporter length cannot be negative")
  }
  let encoded_label = @utf8.encode(label)
  for
    prohibited in [
      "client finished", "server finished", "master secret", "key expansion",
    ] {
    if label == prohibited {
      raise InvalidHandshake("TLS exporter label is reserved")
    }
  }
  p_hash_secret(
    master_secret,
    append_three(encoded_label, client_random, server_random),
    length,
  )
}

///|
pub fn Endpoint::close(self : Endpoint) -> Unit raise DtlsError {
  if self.state == Closed {
    return
  }
  if self.state == Connected {
    self.set_state(Closing)
    self.queue_alert(WarningAlert, CloseNotify)
  }
  self.phase = Terminal
  self.retransmit_deadline = None
  self.last_flight.clear()
  self.master_secret = None
  self.cipher = None
  self.set_state(Closed)
}
