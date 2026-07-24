///|
test "driver queue defaults are bounded" {
  let config = @rtc.Configuration::new()
  inspect(config.command_capacity(), content="64")
  inspect(config.event_capacity(), content="256")
  inspect(config.message_capacity(), content="1024")
}

///|
test "non-positive queue capacity is rejected" {
  try @rtc.Configuration::new(command_capacity=0) catch {
    InvalidConfiguration(message) =>
      inspect(
        message,
        content="command, event, and message capacities must be positive",
      )
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid configuration")
  }
}

///|
test "advanced settings have validated protocol defaults" {
  let settings = @rtc.Settings::new()
  inspect(settings.ice_check_interval().as_milliseconds(), content="50")
  inspect(settings.ice_initial_rto().as_milliseconds(), content="500")
  inspect(settings.ice_disconnected_timeout().as_milliseconds(), content="5000")
  inspect(settings.ice_failed_timeout().as_milliseconds(), content="25000")
  inspect(settings.ice_keepalive_interval().as_milliseconds(), content="2000")
  inspect(settings.dtls_cipher_suites().length(), content="5")
  inspect(settings.dtls_mtu(), content="1200")
  inspect(settings.dtls_replay_window(), content="64")
  inspect(settings.sctp_receive_buffer_size(), content="1048576")
  inspect(settings.receive_mtu(), content="1460")
  let config = @rtc.Configuration::new(settings~)
  inspect(config.settings().receive_mtu(), content="1460")
}

///|
test "advanced settings reject mismatched DTLS credentials and unsafe windows" {
  try @rtc.Settings::new(dtls_psk=b"secret") catch {
    InvalidConfiguration(message) =>
      inspect(message, content="DTLS PSK and PSK identity must appear together")
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid DTLS PSK configuration")
  }
  try @rtc.Settings::new(srtp_replay_window=65) catch {
    InvalidConfiguration(message) =>
      inspect(
        message,
        content="replay protection windows must be between 1 and 64",
      )
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid replay window")
  }
  let zero = try! @rtc.Duration::milliseconds(0)
  try @rtc.Settings::new(ice_keepalive_interval=zero) catch {
    InvalidConfiguration(message) =>
      inspect(message, content="settings durations must be positive")
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid ICE liveness duration")
  }
}

///|
test "RSA and PSK settings derive compatible default cipher suites" {
  let rsa = @rtc.Settings::new(dtls_certificate_key_type=RsaCertificate)
  inspect(rsa.dtls_cipher_suites().length(), content="3")
  assert_true(rsa.dtls_cipher_suites().all(suite => suite.uses_rsa()))
  let psk = @rtc.Settings::new(
    dtls_psk=b"shared secret",
    dtls_psk_identity=b"moonbit-peer",
  )
  inspect(psk.dtls_cipher_suites().length(), content="3")
  assert_true(psk.dtls_cipher_suites().all(suite => suite.is_psk()))
}
