///|
fn test_identity(
  key_type? : CertificateKeyType = EcdsaCertificate,
) -> CertificateIdentity raise DtlsError {
  CertificateIdentity::generate(
    key_type~,
    not_before=@transport.WallTime::from_unix_nanoseconds(1700000000000000000L),
    not_after=@transport.WallTime::from_unix_nanoseconds(1800000000000000000L),
  )
}

///|
fn test_endpoint_pair(
  mtu? : Int = 1200,
  cipher_suites? : Array[CipherSuite] = [],
  key_type? : CertificateKeyType = EcdsaCertificate,
) -> (Endpoint, Endpoint) raise DtlsError {
  let client_identity = test_identity(key_type~)
  let server_identity = test_identity(key_type~)
  let wall_time = @transport.WallTime::from_unix_nanoseconds(
    1750000000000000000L,
  )
  let profiles = [
    SrtpProtectionProfile::aes128_cm_hmac_sha1_80(),
    SrtpProtectionProfile::aead_aes128_gcm(),
  ]
  let client = Endpoint::new(
    Config::new(
      role=Client,
      identity=client_identity,
      expected_peer_fingerprint=server_identity.fingerprint(),
      wall_time~,
      cipher_suites~,
      srtp_profiles=profiles,
      mtu~,
    ),
  )
  let server = Endpoint::new(
    Config::new(
      role=Server,
      identity=server_identity,
      expected_peer_fingerprint=client_identity.fingerprint(),
      wall_time~,
      cipher_suites~,
      srtp_profiles=profiles,
      mtu~,
    ),
  )
  (client, server)
}

///|
fn test_psk_endpoint_pair(
  suite : CipherSuite,
  client_psk? : Bytes = b"shared DTLS pre-shared key",
  server_psk? : Bytes = b"shared DTLS pre-shared key",
) -> (Endpoint, Endpoint) raise DtlsError {
  let client_identity = test_identity()
  let server_identity = test_identity()
  let wall_time = @transport.WallTime::from_unix_nanoseconds(
    1750000000000000000L,
  )
  let client = Endpoint::new(
    Config::new(
      role=Client,
      identity=client_identity,
      expected_peer_fingerprint=server_identity.fingerprint(),
      wall_time~,
      cipher_suites=[suite],
      psk=client_psk,
      psk_identity=b"moonbit-rtc-psk",
    ),
  )
  let server = Endpoint::new(
    Config::new(
      role=Server,
      identity=server_identity,
      expected_peer_fingerprint=client_identity.fingerprint(),
      wall_time~,
      cipher_suites=[suite],
      psk=server_psk,
      psk_identity=b"moonbit-rtc-psk",
    ),
  )
  (client, server)
}

///|
fn pump_handshake(
  client : Endpoint,
  server : Endpoint,
  now : @transport.Instant,
) -> Bool raise DtlsError {
  for step = 0; step < 200; step = step + 1 {
    match client.poll_datagram() {
      Some(datagram) => server.handle_datagram(now, datagram)
      None => ()
    }
    match server.poll_datagram() {
      Some(datagram) => client.handle_datagram(now, datagram)
      None => ()
    }
    if client.state() == Connected && server.state() == Connected {
      return true
    }
  }
  false
}

///|
fn received_application_data(endpoint : Endpoint) -> Bytes? {
  let mut received : Bytes? = None
  for index = 0; index < 32; index = index + 1 {
    match endpoint.poll_event() {
      Some(ApplicationDataReceived(payload)) => received = Some(payload)
      Some(_) => ()
      None => ()
    }
  }
  received
}

///|
test "MoonBit DTLS peers complete mutual-certificate EMS handshake" {
  let (client, server) = test_endpoint_pair(mtu=256)
  let now = @transport.Instant::from_milliseconds(0)
  client.start(now)
  server.start(now)
  assert_true(pump_handshake(client, server, now))
  assert_eq(client.state(), Connected)
  assert_eq(server.state(), Connected)
  assert_eq(
    client.selected_srtp_profile(),
    Some(SrtpProtectionProfile::aes128_cm_hmac_sha1_80()),
  )
  assert_eq(
    server.selected_srtp_profile(),
    Some(SrtpProtectionProfile::aes128_cm_hmac_sha1_80()),
  )
  let client_keying_material = client.export_keying_material(
    "EXTRACTOR-dtls_srtp", 60,
  )
  let server_keying_material = server.export_keying_material(
    "EXTRACTOR-dtls_srtp", 60,
  )
  assert_eq(client_keying_material, server_keying_material)
  try client.export_keying_material("master secret", 1) catch {
    InvalidHandshake(_) => ()
    _ => fail("unexpected reserved TLS exporter label error")
  } noraise {
    _ => fail("reserved TLS exporter label was accepted")
  }
  client.send_application_data(b"fragment-safe DTLS application data")
  guard client.poll_datagram() is Some(application) else {
    fail("DTLS client did not emit application data")
  }
  server.handle_datagram(@transport.Instant::from_milliseconds(1), application)
  assert_eq(
    received_application_data(server),
    Some(b"fragment-safe DTLS application data"),
  )
}

///|
test "DTLS peers negotiate every pinned ECDSA cipher suite" {
  let suites : Array[CipherSuite] = [
    EcdheEcdsaAes128GcmSha256,
    EcdheEcdsaAes256CbcSha,
    EcdheEcdsaChacha20Poly1305Sha256,
    EcdheEcdsaAes128Ccm,
    EcdheEcdsaAes128Ccm8,
  ]
  for suite in suites {
    let (client, server) = test_endpoint_pair(cipher_suites=[suite])
    let now = @transport.Instant::from_milliseconds(0)
    client.start(now)
    server.start(now)
    assert_true(pump_handshake(client, server, now))
    assert_eq(client.selected_cipher_suite(), Some(suite))
    assert_eq(server.selected_cipher_suite(), Some(suite))
    client.send_application_data(b"negotiated cipher")
    guard client.poll_datagram() is Some(application) else {
      fail("DTLS client did not emit protected application data")
    }
    server.handle_datagram(
      @transport.Instant::from_milliseconds(1),
      application,
    )
    assert_eq(received_application_data(server), Some(b"negotiated cipher"))
  }
}

///|
test "DTLS peers negotiate every pinned RSA cipher suite" {
  let suites : Array[CipherSuite] = [
    EcdheRsaAes128GcmSha256,
    EcdheRsaAes256CbcSha,
    EcdheRsaChacha20Poly1305Sha256,
  ]
  for suite in suites {
    let (client, server) = test_endpoint_pair(
      cipher_suites=[suite],
      key_type=RsaCertificate,
    )
    let now = @transport.Instant::from_milliseconds(0)
    client.start(now)
    server.start(now)
    assert_true(pump_handshake(client, server, now))
    assert_eq(client.selected_cipher_suite(), Some(suite))
    assert_eq(server.selected_cipher_suite(), Some(suite))
  }
}

///|
test "DTLS peers negotiate every pinned PSK cipher suite" {
  let suites : Array[CipherSuite] = [
    PskAes128GcmSha256,
    PskAes128Ccm,
    PskAes128Ccm8,
  ]
  for suite in suites {
    let (client, server) = test_psk_endpoint_pair(suite)
    let now = @transport.Instant::from_milliseconds(0)
    client.start(now)
    server.start(now)
    assert_true(pump_handshake(client, server, now))
    assert_eq(client.selected_cipher_suite(), Some(suite))
    assert_eq(server.selected_cipher_suite(), Some(suite))
    client.send_application_data(b"psk application")
    guard client.poll_datagram() is Some(application) else {
      fail("DTLS PSK client did not emit application data")
    }
    server.handle_datagram(
      @transport.Instant::from_milliseconds(1),
      application,
    )
    assert_eq(received_application_data(server), Some(b"psk application"))
  }
}

///|
test "DTLS PSK handshake rejects mismatched keys" {
  let (client, server) = test_psk_endpoint_pair(
    PskAes128GcmSha256,
    server_psk=b"a different server key",
  )
  let now = @transport.Instant::from_milliseconds(0)
  client.start(now)
  server.start(now)
  try pump_handshake(client, server, now) catch {
    InvalidRecord(_) => ()
    _ => fail("unexpected mismatched-PSK handshake error")
  } noraise {
    _ => fail("DTLS peers connected with different PSKs")
  }
}

///|
test "DTLS flights retransmit byte-for-byte on exact deadlines" {
  let (client, server) = test_endpoint_pair()
  let start = @transport.Instant::from_milliseconds(0)
  client.start(start)
  server.start(start)
  guard client.poll_datagram() is Some(initial) else {
    fail("missing initial ClientHello")
  }
  assert_eq(
    client.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(1000)),
  )
  client.handle_timeout(@transport.Instant::from_milliseconds(999))
  assert_eq(client.poll_datagram(), None)
  client.handle_timeout(@transport.Instant::from_milliseconds(1000))
  guard client.poll_datagram() is Some(retransmission) else {
    fail("missing ClientHello retransmission")
  }
  assert_eq(retransmission, initial)
  assert_eq(
    client.poll_timeout(),
    Some(@transport.Instant::from_milliseconds(3000)),
  )
}

///|
test "DTLS fingerprint mismatch fails before accepting peer key exchange" {
  let client_identity = test_identity()
  let server_identity = test_identity()
  let wall_time = @transport.WallTime::from_unix_nanoseconds(
    1750000000000000000L,
  )
  let client = Endpoint::new(
    Config::new(
      role=Client,
      identity=client_identity,
      expected_peer_fingerprint=client_identity.fingerprint(),
      wall_time~,
    ),
  )
  let server = Endpoint::new(
    Config::new(
      role=Server,
      identity=server_identity,
      expected_peer_fingerprint=client_identity.fingerprint(),
      wall_time~,
    ),
  )
  let now = @transport.Instant::from_milliseconds(0)
  client.start(now)
  server.start(now)
  try pump_handshake(client, server, now) catch {
    FingerprintMismatch => ()
    _ => fail("unexpected DTLS fingerprint error")
  } noraise {
    _ => fail("DTLS accepted a certificate with the wrong fingerprint")
  }
  assert_eq(client.state(), Failed)
}

///|
test "DTLS close_notify closes both endpoints and close is idempotent" {
  let (client, server) = test_endpoint_pair()
  let now = @transport.Instant::from_milliseconds(0)
  client.start(now)
  server.start(now)
  assert_true(pump_handshake(client, server, now))
  client.close()
  client.close()
  assert_eq(client.state(), Closed)
  guard client.poll_datagram() is Some(close_notify) else {
    fail("DTLS close did not emit close_notify")
  }
  server.handle_datagram(@transport.Instant::from_milliseconds(1), close_notify)
  assert_eq(server.state(), Closed)
}
