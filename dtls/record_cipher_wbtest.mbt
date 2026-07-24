///|
fn test_encryption_keys(
  suite? : CipherSuite = EcdheEcdsaAes128GcmSha256,
) -> EncryptionKeys raise DtlsError {
  encryption_keys_for_secret(
    @crypto.Secret::from_bytes(upstream_master_secret()),
    sequential_bytes(0x00),
    sequential_bytes(0x70),
    suite~,
  )
}

///|
test "DTLS AES-128-GCM matches an independent RFC 5288 vector" {
  let keys = test_encryption_keys()
  let client = RecordCipher::new(keys, Client)
  let server = RecordCipher::new(keys, Server)
  let encrypted = client.seal(
    content_type=ApplicationData,
    epoch=1,
    sequence_number=18UL,
    plaintext=b"\xff\xaa\xbb",
  )
  assert_eq(
    encrypted.encode(),
    b"\x17\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x12\x00\x1b" +
    b"\x00\x01\x00\x00\x00\x00\x00\x12\xf3\x5d\xaf\x66\x8d\x1c\x5d\xa5" +
    b"\xe4\x76\xfc\xe3\x12\x8c\x28\x02\x26\xa1\xd4",
  )
  assert_eq(server.open(encrypted), b"\xff\xaa\xbb")
  try server.open(encrypted) catch {
    ReplayRejected => ()
    _ => fail("unexpected DTLS replay error")
  } noraise {
    _ => fail("a duplicate encrypted DTLS record was accepted")
  }
}

///|
test "DTLS AES-128-GCM rejects modified tags and record sequence AAD" {
  let keys = test_encryption_keys()
  let client = RecordCipher::new(keys, Client)
  let server = RecordCipher::new(keys, Server)
  let encrypted = client.seal(
    content_type=ApplicationData,
    epoch=1,
    sequence_number=99UL,
    plaintext=b"authenticated",
  )
  let corrupted_payload = encrypted.payload().to_array()
  corrupted_payload[corrupted_payload.length() - 1] = corrupted_payload[corrupted_payload.length() -
    1] ^
    1
  let corrupted = Record::new(
    content_type=ApplicationData,
    epoch=1,
    sequence_number=99UL,
    payload=Bytes::from_array(corrupted_payload),
  )
  try server.open(corrupted) catch {
    InvalidRecord(_) => ()
    _ => fail("unexpected DTLS authentication error")
  } noraise {
    _ => fail("a modified DTLS authentication tag was accepted")
  }
  let wrong_sequence = Record::new(
    content_type=ApplicationData,
    epoch=1,
    sequence_number=100UL,
    payload=encrypted.payload(),
  )
  try server.open(wrong_sequence) catch {
    InvalidRecord(_) => ()
    _ => fail("unexpected DTLS authentication error")
  } noraise {
    _ => fail("a record with mismatched sequence-number AAD was accepted")
  }
}

///|
test "DTLS AES-128-GCM accepts peer-selected explicit nonces" {
  let keys = test_encryption_keys()
  let server = RecordCipher::new(keys, Server)
  let epoch : UInt16 = 1
  let sequence_number = 7UL
  let plaintext = b"peer nonce"
  let explicit = b"\xA5\x5A\x01\x02\x03\x04\x05\x06"
  let packet = @crypto.Provider::open().aead_seal(
    Aes128Gcm,
    @crypto.Secret::from_bytes(keys.client_write_key),
    keys.client_write_iv + explicit,
    b"\x00\x01\x00\x00\x00\x00\x00\x07\x17\xFE\xFD\x00\x0A",
    plaintext,
  )
  let record = Record::new(
    content_type=ApplicationData,
    epoch~,
    sequence_number~,
    payload=explicit + packet.ciphertext() + packet.tag(),
  )
  assert_eq(server.open(record), plaintext)
}

///|
test "all pinned DTLS record ciphers round-trip and reject replay" {
  let suites : Array[CipherSuite] = [
    EcdheEcdsaAes128Ccm,
    EcdheEcdsaAes128Ccm8,
    EcdheEcdsaAes128GcmSha256,
    EcdheRsaAes128GcmSha256,
    EcdheEcdsaAes256CbcSha,
    EcdheRsaAes256CbcSha,
    PskAes128Ccm,
    PskAes128Ccm8,
    PskAes128GcmSha256,
    EcdheRsaChacha20Poly1305Sha256,
    EcdheEcdsaChacha20Poly1305Sha256,
  ]
  for suite in suites {
    let keys = test_encryption_keys(suite~)
    let client = RecordCipher::new(keys, Client, suite~)
    let server = RecordCipher::new(keys, Server, suite~)
    let record = client.seal(
      content_type=ApplicationData,
      epoch=1,
      sequence_number=0x102UL,
      plaintext=b"suite-specific record protection",
    )
    assert_eq(server.open(record), b"suite-specific record protection")
    try server.open(record) catch {
      ReplayRejected => ()
      _ => fail("unexpected replay error for configured cipher suite")
    } noraise {
      _ => fail("cipher suite accepted a duplicate record")
    }
  }
}

///|
test "DTLS CCM-8 emits an eight-byte authentication tag" {
  let keys = test_encryption_keys(suite=EcdheEcdsaAes128Ccm8)
  let client = RecordCipher::new(keys, Client, suite=EcdheEcdsaAes128Ccm8)
  let server = RecordCipher::new(keys, Server, suite=EcdheEcdsaAes128Ccm8)
  let record = client.seal(
    content_type=ApplicationData,
    epoch=1,
    sequence_number=1UL,
    plaintext=b"ccm8",
  )
  assert_eq(record.payload().length(), 8 + 4 + 8)
  assert_eq(server.open(record), b"ccm8")
}
