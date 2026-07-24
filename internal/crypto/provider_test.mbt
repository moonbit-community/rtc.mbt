///|
test "OpenSSL 3 provider passes preflight and digest vectors" {
  let provider = @crypto.Provider::open()
  assert_true(provider.version().has_prefix("OpenSSL 3"))
  assert_eq(
    provider.digest(Sha256, b"abc"),
    b"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad",
  )
}

///|
test "HMAC keys use wipeable external objects" {
  let provider = @crypto.Provider::open()
  let key = @crypto.Secret::from_bytes(b"key")
  assert_eq(key.length(), 3)
  assert_eq(
    provider.hmac(Sha256, key, b"abc"),
    b"\x9c\x19\x6e\x32\xdc\x01\x75\xf8\x6f\x4b\x1c\xb8\x92\x89\xd6\x61\x9d\xe6\xbe\xe6\x99\xe4\xc3\x78\xe6\x83\x09\xed\x97\xa1\xa6\xab",
  )
}

///|
test "random and constant-time primitives are exposed safely" {
  let provider = @crypto.Provider::open()
  let random = provider.random_bytes(32)
  assert_eq(random.length(), 32)
  assert_true(provider.constant_time_equal(b"same", b"same"))
  assert_false(provider.constant_time_equal(b"same", b"different"))
  let first = provider.random_secret(32)
  let second = @crypto.Secret::from_bytes(b"not the same")
  assert_false(first.constant_time_equal(provider, second))
}

///|
test "missing library is CryptoUnavailable" {
  try @crypto.Provider::open(path="/definitely/missing/libcrypto.so.3") catch {
    CryptoUnavailable(message) =>
      assert_true(message.has_prefix("unable to load OpenSSL 3 library"))
    InvalidLength(_) | OperationFailed(_) => fail("unexpected error")
  } noraise {
    _ => fail("expected provider loading to fail")
  }
}

///|
test "property query that excludes required algorithms is CryptoUnavailable" {
  try @crypto.Provider::open(property_query="provider=null") catch {
    CryptoUnavailable(message) =>
      assert_true(message.has_prefix("OpenSSL preflight failed"))
    InvalidLength(_) | OperationFailed(_) => fail("unexpected error")
  } noraise {
    _ => fail("expected provider preflight to fail")
  }
}

///|
test "AES-128-GCM matches the NIST zero vector and authenticates on open" {
  let provider = @crypto.Provider::open()
  let key = @crypto.Secret::from_bytes(
    b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
  )
  let nonce = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  let plaintext = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
  let packet = provider.aead_seal(Aes128Gcm, key, nonce, b"", plaintext)
  assert_eq(
    packet.ciphertext(),
    b"\x03\x88\xda\xce\x60\xb6\xa3\x92\xf3\x28\xc2\xb9\x71\xb2\xfe\x78",
  )
  assert_eq(
    packet.tag(),
    b"\xab\x6e\x47\xd4\x2c\xec\x13\xbd\xf5\x3a\x67\xb2\x12\x57\xbd\xdf",
  )
  assert_eq(provider.aead_open(Aes128Gcm, key, nonce, b"", packet), plaintext)
}

///|
test "AEAD round-trips all required provider algorithms" {
  let provider = @crypto.Provider::open()
  let plaintext = b"MoonBit WebRTC"
  let aad = b"record header"
  let cases : Array[(@crypto.AeadAlgorithm, Int, Bytes)] = [
    (Aes128Gcm, 16, b"twelve-bytes"),
    (Aes256Gcm, 32, b"twelve-bytes"),
    (Aes128Ccm, 16, b"twelve-bytes"),
    (Aes256Ccm, 32, b"twelve-bytes"),
    (Chacha20Poly1305, 32, b"twelve-bytes"),
  ]
  for item in cases {
    let (algorithm, key_length, nonce) = item
    let key = @crypto.Secret::from_bytes(Bytes::make(key_length, 7))
    let packet = provider.aead_seal(algorithm, key, nonce, aad, plaintext)
    assert_eq(provider.aead_open(algorithm, key, nonce, aad, packet), plaintext)
  }
}

///|
test "AEAD authentication failure never returns plaintext" {
  let provider = @crypto.Provider::open()
  let key = @crypto.Secret::from_bytes(Bytes::make(16, 1))
  let nonce = b"twelve-bytes"
  let packet = provider.aead_seal(Aes128Gcm, key, nonce, b"aad", b"secret")
  let bad = @crypto.AeadSealed::new(
    ciphertext=packet.ciphertext(),
    tag=Bytes::make(16, 0),
  )
  try provider.aead_open(Aes128Gcm, key, nonce, b"aad", bad) catch {
    OperationFailed(_) => ()
    CryptoUnavailable(_) | InvalidLength(_) => fail("unexpected error")
  } noraise {
    _ => fail("expected authentication failure")
  }
}

///|
test "AES-CBC and AES-CTR match NIST single-block vectors" {
  let provider = @crypto.Provider::open()
  let key = @crypto.Secret::from_bytes(
    b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c",
  )
  let plaintext = b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a"
  let cbc_iv = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
  let cbc = provider.cipher_encrypt(Aes128Cbc, key, cbc_iv, plaintext)
  assert_eq(
    cbc, b"\x76\x49\xab\xac\x81\x19\xb2\x46\xce\xe9\x8e\x9b\x12\xe9\x19\x7d",
  )
  assert_eq(provider.cipher_decrypt(Aes128Cbc, key, cbc_iv, cbc), plaintext)
  let counter = b"\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
  let ctr = provider.cipher_encrypt(Aes128Ctr, key, counter, plaintext)
  assert_eq(
    ctr, b"\x87\x4d\x61\x91\xb6\x20\xe3\x26\x1b\xef\x68\x64\x99\x0d\xb6\xce",
  )
  assert_eq(provider.cipher_decrypt(Aes128Ctr, key, counter, ctr), plaintext)
}

///|
test "ECDH derives identical wipeable secrets for all required groups" {
  let provider = @crypto.Provider::open()
  let algorithms : Array[@crypto.KeyAlgorithm] = [P256, P384, X25519]
  for algorithm in algorithms {
    let alice = provider.generate_private_key(algorithm)
    let bob = provider.generate_private_key(algorithm)
    let alice_public = provider.import_public_key(alice.public_der(provider))
    let bob_public = provider.import_public_key(bob.public_der(provider))
    let alice_secret = provider.derive_shared_secret(alice, bob_public)
    let bob_secret = provider.derive_shared_secret(bob, alice_public)
    assert_true(alice_secret.constant_time_equal(provider, bob_secret))
    assert_true(alice_secret.length() > 0)
  }
}

///|
test "ECDSA and RSA signing algorithms reject modified messages" {
  let provider = @crypto.Provider::open()
  let cases : Array[(@crypto.KeyAlgorithm, @crypto.SignatureAlgorithm)] = [
    (P256, EcdsaSha256),
    (P384, EcdsaSha384),
    (Rsa2048, RsaPssSha256),
    (Rsa2048, RsaPkcs1Sha256),
  ]
  for item in cases {
    let (key_algorithm, signature_algorithm) = item
    let private_key = provider.generate_private_key(key_algorithm)
    let public_key = provider.import_public_key(
      private_key.public_der(provider),
    )
    let signature = try
      provider.sign(signature_algorithm, private_key, b"DTLS transcript")
    catch {
      OperationFailed(message) =>
        fail(
          "sign \{Repr(key_algorithm)}/\{Repr(signature_algorithm)}: \{message}",
        )
      CryptoUnavailable(_) | InvalidLength(_) => fail("unexpected error")
    } noraise {
      value => value
    }
    assert_true(
      provider.verify(
        signature_algorithm, public_key, b"DTLS transcript", signature,
      ),
    )
    assert_false(
      provider.verify(
        signature_algorithm, public_key, b"modified transcript", signature,
      ),
    )
  }
}

///|
test "self-signed X.509 uses injected wall time and stable DER fingerprints" {
  let provider = @crypto.Provider::open()
  let key = provider.generate_private_key(P256)
  let not_before = @transport.WallTime::from_unix_nanoseconds(
    1700000000000000000L,
  )
  let not_after = @transport.WallTime::from_unix_nanoseconds(
    1700086400000000000L,
  )
  let certificate = provider.self_signed_certificate(
    key, "rtc.mbt test", not_before, not_after,
  )
  assert_true(certificate.verify_self_signature(provider))
  assert_true(
    certificate.is_valid_at(
      provider,
      @transport.WallTime::from_unix_nanoseconds(1700000100000000000L),
    ),
  )
  assert_false(
    certificate.is_valid_at(
      provider,
      @transport.WallTime::from_unix_nanoseconds(1699999999000000000L),
    ),
  )
  let fingerprint = certificate.fingerprint(provider, Sha256)
  assert_eq(fingerprint.length(), 32)
  let imported = provider.import_certificate(certificate.to_der(provider))
  assert_true(imported.verify_self_signature(provider))
  assert_true(
    provider.constant_time_equal(
      fingerprint,
      imported.fingerprint(provider, Sha256),
    ),
  )
}

///|
fn exercise_finalizer_owned_crypto_objects() -> (Bool, Bool, Int) raise @crypto.CryptoError {
  let provider = @crypto.Provider::open()
  let secret = @crypto.Secret::from_bytes(b"finalizer-owned secret")
  let private_key = provider.generate_private_key(P256)
  let public_key = provider.import_public_key(private_key.public_der(provider))
  let not_before = @transport.WallTime::from_unix_nanoseconds(
    1700000000000000000L,
  )
  let not_after = @transport.WallTime::from_unix_nanoseconds(
    1700086400000000000L,
  )
  let certificate = provider.self_signed_certificate(
    private_key, "rtc.mbt finalizer test", not_before, not_after,
  )
  let certificate_public_key = certificate.public_key(provider)
  let signature = provider.sign(EcdsaSha256, private_key, b"finalizer probe")
  let public_key_verified = provider.verify(
    EcdsaSha256,
    public_key,
    b"finalizer probe",
    signature,
  )
  let certificate_key_verified = provider.verify(
    EcdsaSha256,
    certificate_public_key,
    b"finalizer probe",
    signature,
  )
  (
    public_key_verified,
    certificate_key_verified,
    secret.length() + certificate.to_der(provider).length(),
  )
}

///|
test "external crypto objects leave scope through GC finalizers under ASan" {
  // The helper makes Provider, Secret, EVP_PKEY, and X509 external objects
  // unreachable on every return. The sanitizer suite's leak check is the
  // authoritative assertion that their registered finalizers release storage.
  let mut observed = 0
  for _ in 0..<8 {
    let (public_key_verified, certificate_key_verified, bytes) = exercise_finalizer_owned_crypto_objects()
    assert_true(public_key_verified)
    assert_true(certificate_key_verified)
    observed += bytes
  }
  assert_true(observed > 0)
}
