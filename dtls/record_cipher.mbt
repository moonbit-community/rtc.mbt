///|
priv enum RecordCipherMode {
  AeadCipher(
    algorithm~ : @crypto.AeadAlgorithm,
    tag_length~ : Int,
    explicit_nonce~ : Bool
  )
  CbcCipher
}

///|
struct RecordCipher {
  provider : @crypto.Provider
  mode : RecordCipherMode
  write_key : @crypto.Secret
  read_key : @crypto.Secret
  write_mac_key : @crypto.Secret
  read_mac_key : @crypto.Secret
  write_iv : Bytes
  read_iv : Bytes
  replay_windows : Map[UInt16, @replay.ReplayWindow]
  replay_window : Int
}

///|
fn cipher_mode(suite : CipherSuite) -> RecordCipherMode {
  match suite {
    EcdheEcdsaAes128Ccm | PskAes128Ccm =>
      AeadCipher(algorithm=Aes128Ccm, tag_length=16, explicit_nonce=true)
    EcdheEcdsaAes128Ccm8 | PskAes128Ccm8 =>
      AeadCipher(algorithm=Aes128Ccm, tag_length=8, explicit_nonce=true)
    EcdheEcdsaAes128GcmSha256 | EcdheRsaAes128GcmSha256 | PskAes128GcmSha256 =>
      AeadCipher(algorithm=Aes128Gcm, tag_length=16, explicit_nonce=true)
    EcdheRsaChacha20Poly1305Sha256 | EcdheEcdsaChacha20Poly1305Sha256 =>
      AeadCipher(
        algorithm=Chacha20Poly1305,
        tag_length=16,
        explicit_nonce=false,
      )
    EcdheEcdsaAes256CbcSha | EcdheRsaAes256CbcSha => CbcCipher
  }
}

///|
fn expected_key_lengths(suite : CipherSuite) -> (Int, Int, Int) {
  match suite {
    EcdheEcdsaAes256CbcSha | EcdheRsaAes256CbcSha => (32, 0, 20)
    EcdheRsaChacha20Poly1305Sha256 | EcdheEcdsaChacha20Poly1305Sha256 =>
      (32, 12, 0)
    _ => (16, 4, 0)
  }
}

///|
fn RecordCipher::new(
  keys : EncryptionKeys,
  role : Role,
  suite? : CipherSuite = EcdheEcdsaAes128GcmSha256,
  replay_window? : Int = 64,
) -> RecordCipher raise DtlsError {
  if role == Auto {
    raise HandshakeFailed("DTLS record cipher requires a fixed role")
  }
  if replay_window < 1 || replay_window > 64 {
    raise HandshakeFailed("DTLS replay window must be between 1 and 64")
  }
  let (write_key, read_key, write_mac_key, read_mac_key, write_iv, read_iv) = if role ==
    Client {
    (
      keys.client_write_key,
      keys.server_write_key,
      keys.client_mac_key,
      keys.server_mac_key,
      keys.client_write_iv,
      keys.server_write_iv,
    )
  } else {
    (
      keys.server_write_key,
      keys.client_write_key,
      keys.server_mac_key,
      keys.client_mac_key,
      keys.server_write_iv,
      keys.client_write_iv,
    )
  }
  let (key_length, iv_length, mac_length) = expected_key_lengths(suite)
  if write_key.length() != key_length ||
    read_key.length() != key_length ||
    write_iv.length() != iv_length ||
    read_iv.length() != iv_length ||
    write_mac_key.length() != mac_length ||
    read_mac_key.length() != mac_length {
    raise HandshakeFailed(
      "invalid key material for DTLS cipher suite \{suite.code()}",
    )
  }
  {
    provider: crypto_provider(),
    mode: cipher_mode(suite),
    write_key: @crypto.Secret::from_bytes(write_key),
    read_key: @crypto.Secret::from_bytes(read_key),
    write_mac_key: @crypto.Secret::from_bytes(write_mac_key),
    read_mac_key: @crypto.Secret::from_bytes(read_mac_key),
    write_iv,
    read_iv,
    replay_windows: Map([]),
    replay_window,
  }
}

///|
fn epoch_sequence(epoch : UInt16, sequence_number : UInt64) -> Bytes {
  Bytes::from_array([
    (epoch >> 8).to_byte(),
    epoch.to_byte(),
    (sequence_number >> 40).to_byte(),
    (sequence_number >> 32).to_byte(),
    (sequence_number >> 24).to_byte(),
    (sequence_number >> 16).to_byte(),
    (sequence_number >> 8).to_byte(),
    sequence_number.to_byte(),
  ])
}

///|
fn record_aad(
  content_type : ContentType,
  version : ProtocolVersion,
  epoch : UInt16,
  sequence_number : UInt64,
  plaintext_length : Int,
) -> Bytes raise DtlsError {
  if plaintext_length < 0 || plaintext_length > 0xffff {
    raise InvalidRecord("invalid DTLS plaintext length")
  }
  let result = epoch_sequence(epoch, sequence_number).to_array()
  result.push(content_type.code())
  result.push(version.major())
  result.push(version.minor())
  result.push((plaintext_length >> 8).to_byte())
  result.push(plaintext_length.to_byte())
  Bytes::from_array(result)
}

///|
fn explicit_nonce(fixed_iv : Bytes, explicit : Bytes) -> Bytes {
  append_bytes(fixed_iv, explicit)
}

///|
fn chacha_nonce(
  fixed_iv : Bytes,
  epoch : UInt16,
  sequence_number : UInt64,
) -> Bytes raise DtlsError {
  if fixed_iv.length() != 12 {
    raise InvalidRecord("ChaCha20-Poly1305 fixed IV must contain 12 bytes")
  }
  let result = fixed_iv.to_array()
  let sequence = epoch_sequence(epoch, sequence_number)
  for index = 0; index < 8; index = index + 1 {
    result[index + 4] = result[index + 4] ^ sequence[index]
  }
  Bytes::from_array(result)
}

///|
fn endpoint_aead_nonce(
  fixed_iv : Bytes,
  explicit : Bytes,
  epoch : UInt16,
  sequence_number : UInt64,
  has_explicit : Bool,
) -> Bytes raise DtlsError {
  if has_explicit {
    explicit_nonce(fixed_iv, explicit)
  } else {
    chacha_nonce(fixed_iv, epoch, sequence_number)
  }
}

///|
fn cbc_plaintext(
  provider : @crypto.Provider,
  mac_key : @crypto.Secret,
  content_type : ContentType,
  version : ProtocolVersion,
  epoch : UInt16,
  sequence_number : UInt64,
  plaintext : Bytes,
) -> Bytes raise DtlsError {
  let aad = record_aad(
    content_type,
    version,
    epoch,
    sequence_number,
    plaintext.length(),
  )
  let mac = crypto_operation(() => {
    provider.hmac(Sha1, mac_key, append_bytes(aad, plaintext))
  })
  let result = append_bytes(plaintext, mac).to_array()
  let padding_count = 16 - result.length() % 16
  let padding = (padding_count - 1).to_byte()
  for index = 0; index < padding_count; index = index + 1 {
    result.push(padding)
  }
  Bytes::from_array(result)
}

///|
fn RecordCipher::seal(
  self : RecordCipher,
  content_type~ : ContentType,
  version? : ProtocolVersion = Dtls12,
  epoch~ : UInt16,
  sequence_number~ : UInt64,
  plaintext~ : Bytes,
) -> Record raise DtlsError {
  if sequence_number > 0x0000ffffffffffffUL {
    raise InvalidRecord("DTLS record sequence number exceeds 48 bits")
  }
  let payload = match self.mode {
    AeadCipher(algorithm~, tag_length~, explicit_nonce=has_explicit) => {
      let explicit = if has_explicit {
        epoch_sequence(epoch, sequence_number)
      } else {
        b""
      }
      let aad = record_aad(
        content_type,
        version,
        epoch,
        sequence_number,
        plaintext.length(),
      )
      let nonce = endpoint_aead_nonce(
        self.write_iv,
        explicit,
        epoch,
        sequence_number,
        has_explicit,
      )
      let encrypted = crypto_operation(() => {
        self.provider.aead_seal(
          algorithm,
          self.write_key,
          nonce,
          aad,
          plaintext,
          tag_length~,
        )
      })
      append_three(explicit, encrypted.ciphertext(), encrypted.tag())
    }
    CbcCipher => {
      let iv = crypto_operation(() => self.provider.random_bytes(16))
      let padded = cbc_plaintext(
        self.provider,
        self.write_mac_key,
        content_type,
        version,
        epoch,
        sequence_number,
        plaintext,
      )
      let encrypted = crypto_operation(() => {
        self.provider.cipher_encrypt(Aes256Cbc, self.write_key, iv, padded)
      })
      append_bytes(iv, encrypted)
    }
  }
  Record::new(content_type~, version~, epoch~, sequence_number~, payload~)
}

///|
fn RecordCipher::mark_replay(
  self : RecordCipher,
  epoch : UInt16,
  sequence_number : UInt64,
) -> Unit raise DtlsError {
  let window = match self.replay_windows.get(epoch) {
    Some(window) => window
    None => {
      let window = @replay.ReplayWindow::new(width=self.replay_window) catch {
        InvalidWidth(width) =>
          raise InvalidRecord("invalid replay window width \{width}")
      }
      self.replay_windows[epoch] = window
      window
    }
  }
  match window.check_and_mark(sequence_number) {
    AcceptedNew | AcceptedOutOfOrder => ()
    Duplicate | TooOld => raise ReplayRejected
  }
}

///|
fn RecordCipher::open_aead(
  self : RecordCipher,
  record : Record,
  algorithm : @crypto.AeadAlgorithm,
  tag_length : Int,
  has_explicit : Bool,
) -> Bytes raise DtlsError {
  let payload = record.payload
  let explicit_length = if has_explicit { 8 } else { 0 }
  if payload.length() < explicit_length + tag_length {
    raise InvalidRecord("encrypted DTLS record is shorter than nonce and tag")
  }
  let explicit = payload[0:explicit_length].to_owned()
  let ciphertext_length = payload.length() - explicit_length - tag_length
  let ciphertext = payload[explicit_length:explicit_length + ciphertext_length].to_owned()
  let tag = payload[payload.length() - tag_length:].to_owned()
  let aad = record_aad(
    record.header.content_type,
    record.header.version,
    record.header.epoch,
    record.header.sequence_number,
    ciphertext_length,
  )
  let packet = @crypto.AeadSealed::new(ciphertext~, tag~) catch {
    InvalidLength(length) =>
      raise InvalidRecord("invalid DTLS authentication tag length \{length}")
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
  let nonce = endpoint_aead_nonce(
    self.read_iv,
    explicit,
    record.header.epoch,
    record.header.sequence_number,
    has_explicit,
  )
  self.provider.aead_open(algorithm, self.read_key, nonce, aad, packet) catch {
    OperationFailed(_) =>
      raise InvalidRecord("DTLS record authentication failed")
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise InvalidRecord("invalid DTLS cipher input length \{length}")
  }
}

///|
fn RecordCipher::open_cbc(
  self : RecordCipher,
  record : Record,
) -> Bytes raise DtlsError {
  let payload = record.payload
  if payload.length() < 32 || (payload.length() - 16) % 16 != 0 {
    raise InvalidRecord("invalid DTLS AES-CBC record length")
  }
  let iv = payload[0:16].to_owned()
  let encrypted = payload[16:].to_owned()
  let padded = self.provider.cipher_decrypt(
    Aes256Cbc,
    self.read_key,
    iv,
    encrypted,
  ) catch {
    OperationFailed(_) => raise InvalidRecord("DTLS CBC decryption failed")
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise InvalidRecord("invalid DTLS CBC input length \{length}")
  }
  if padded.is_empty() {
    raise InvalidRecord("DTLS CBC plaintext is empty")
  }
  let padding_count = padded[padded.length() - 1].to_int() + 1
  if padding_count > padded.length() {
    raise InvalidRecord("invalid DTLS CBC padding")
  }
  let mut valid_padding = true
  let padding_value = (padding_count - 1).to_byte()
  for byte in padded[padded.length() - padding_count:] {
    if byte != padding_value {
      valid_padding = false
    }
  }
  if !valid_padding {
    raise InvalidRecord("invalid DTLS CBC padding")
  }
  let authenticated_length = padded.length() - padding_count
  if authenticated_length < 20 {
    raise InvalidRecord("DTLS CBC plaintext omitted its MAC")
  }
  let plaintext_length = authenticated_length - 20
  let plaintext = padded[0:plaintext_length].to_owned()
  let received_mac = padded[plaintext_length:authenticated_length].to_owned()
  let aad = record_aad(
    record.header.content_type,
    record.header.version,
    record.header.epoch,
    record.header.sequence_number,
    plaintext_length,
  )
  let expected_mac = crypto_operation(() => {
    self.provider.hmac(Sha1, self.read_mac_key, append_bytes(aad, plaintext))
  })
  if !self.provider.constant_time_equal(expected_mac, received_mac) {
    raise InvalidRecord("DTLS CBC record authentication failed")
  }
  plaintext
}

///|
fn RecordCipher::open(
  self : RecordCipher,
  record : Record,
) -> Bytes raise DtlsError {
  let plaintext = match self.mode {
    AeadCipher(algorithm~, tag_length~, explicit_nonce=has_explicit) =>
      self.open_aead(record, algorithm, tag_length, has_explicit)
    CbcCipher => self.open_cbc(record)
  }
  self.mark_replay(record.header.epoch, record.header.sequence_number)
  plaintext
}
