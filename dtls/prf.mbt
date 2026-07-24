///|
let default_crypto_provider : Lazy[Result[@crypto.Provider, String]] = Lazy(() => {
  Ok(@crypto.Provider::open()) catch {
    CryptoUnavailable(message) => Err(message)
    InvalidLength(length) => Err("OpenSSL rejected length \{length}")
    OperationFailed(message) => Err(message)
  }
})

///|
fn crypto_provider() -> @crypto.Provider raise DtlsError {
  match default_crypto_provider.force() {
    Ok(provider) => provider
    Err(message) => raise CryptoUnavailable(message)
  }
}

///|
fn[T] crypto_operation(
  operation : () -> T raise @crypto.CryptoError,
) -> T raise DtlsError {
  operation() catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
}

///|
fn append_bytes(left : Bytes, right : Bytes) -> Bytes {
  let result = left.to_array()
  for byte in right {
    result.push(byte)
  }
  Bytes::from_array(result)
}

///|
fn append_three(first : Bytes, second : Bytes, third : Bytes) -> Bytes {
  append_bytes(append_bytes(first, second), third)
}

///|
fn p_hash_secret(
  secret : @crypto.Secret,
  seed : Bytes,
  requested_length : Int,
) -> Bytes raise DtlsError {
  if requested_length < 0 {
    raise InvalidHandshake("TLS PRF output length cannot be negative")
  }
  if requested_length == 0 {
    return b""
  }
  let provider = crypto_provider()
  let output : Array[Byte] = []
  let mut a = seed
  while output.length() < requested_length {
    a = crypto_operation(() => provider.hmac(Sha256, secret, a))
    let block = crypto_operation(() => {
      provider.hmac(Sha256, secret, append_bytes(a, seed))
    })
    for byte in block {
      if output.length() < requested_length {
        output.push(byte)
      }
    }
  }
  Bytes::from_array(output)
}

///|
fn extended_master_secret_key(
  pre_master_secret : @crypto.Secret,
  session_hash : Bytes,
) -> @crypto.Secret raise DtlsError {
  @crypto.Secret::from_bytes(
    p_hash_secret(
      pre_master_secret,
      append_bytes(b"extended master secret", session_hash),
      48,
    ),
  )
}

///|
fn psk_pre_master_secret(psk : Bytes) -> @crypto.Secret raise DtlsError {
  if psk.is_empty() || psk.length() > 0xffff {
    raise InvalidHandshake("DTLS PSK must contain 1..65535 bytes")
  }
  let result : Array[Byte] = [
    (psk.length() >> 8).to_byte(),
    psk.length().to_byte(),
  ]
  for index = 0; index < psk.length(); index = index + 1 {
    result.push(0)
  }
  result.push((psk.length() >> 8).to_byte())
  result.push(psk.length().to_byte())
  for byte in psk {
    result.push(byte)
  }
  @crypto.Secret::from_bytes(Bytes::from_array(result))
}

///|
fn encryption_keys_with_lengths(
  master_secret : @crypto.Secret,
  client_random : Bytes,
  server_random : Bytes,
  mac_length~ : Int,
  key_length~ : Int,
  iv_length~ : Int,
) -> EncryptionKeys raise DtlsError {
  if master_secret.length() != 48 ||
    client_random.length() != 32 ||
    server_random.length() != 32 {
    raise InvalidHandshake("invalid DTLS key schedule input length")
  }
  if mac_length < 0 || key_length < 1 || iv_length < 0 {
    raise InvalidHandshake("invalid DTLS key schedule output lengths")
  }
  let side_length = mac_length + key_length + iv_length
  let material = p_hash_secret(
    master_secret,
    append_three(b"key expansion", server_random, client_random),
    side_length * 2,
  )
  let client_mac_end = mac_length
  let server_mac_end = client_mac_end + mac_length
  let client_key_end = server_mac_end + key_length
  let server_key_end = client_key_end + key_length
  let client_iv_end = server_key_end + iv_length
  let server_iv_end = client_iv_end + iv_length
  {
    client_mac_key: material[0:client_mac_end].to_owned(),
    server_mac_key: material[client_mac_end:server_mac_end].to_owned(),
    client_write_key: material[server_mac_end:client_key_end].to_owned(),
    server_write_key: material[client_key_end:server_key_end].to_owned(),
    client_write_iv: material[server_key_end:client_iv_end].to_owned(),
    server_write_iv: material[client_iv_end:server_iv_end].to_owned(),
  }
}

///|
fn encryption_keys_for_secret(
  master_secret : @crypto.Secret,
  client_random : Bytes,
  server_random : Bytes,
  suite? : CipherSuite = EcdheEcdsaAes128GcmSha256,
) -> EncryptionKeys raise DtlsError {
  let (mac_length, key_length, iv_length) = match suite {
    EcdheEcdsaAes256CbcSha | EcdheRsaAes256CbcSha => (20, 32, 0)
    EcdheRsaChacha20Poly1305Sha256 | EcdheEcdsaChacha20Poly1305Sha256 =>
      (0, 32, 12)
    _ => (0, 16, 4)
  }
  encryption_keys_with_lengths(
    master_secret,
    client_random,
    server_random,
    mac_length~,
    key_length~,
    iv_length~,
  )
}

///|
fn verify_data_for_secret(
  master_secret : @crypto.Secret,
  handshake_messages : Bytes,
  label : Bytes,
) -> Bytes raise DtlsError {
  if master_secret.length() != 48 {
    raise InvalidHandshake("DTLS master secret must contain 48 bytes")
  }
  let provider = crypto_provider()
  let digest = crypto_operation(() => {
    provider.digest(Sha256, handshake_messages)
  })
  p_hash_secret(master_secret, append_bytes(label, digest), 12)
}

///|
fn client_verify_data_for_secret(
  master_secret : @crypto.Secret,
  handshake_messages : Bytes,
) -> Bytes raise DtlsError {
  verify_data_for_secret(master_secret, handshake_messages, b"client finished")
}

///|
fn server_verify_data_for_secret(
  master_secret : @crypto.Secret,
  handshake_messages : Bytes,
) -> Bytes raise DtlsError {
  verify_data_for_secret(master_secret, handshake_messages, b"server finished")
}

///|
fn transcript_hash(handshake_messages : Bytes) -> Bytes raise DtlsError {
  let provider = crypto_provider()
  crypto_operation(() => provider.digest(Sha256, handshake_messages))
}
