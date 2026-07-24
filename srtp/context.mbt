///|
struct SessionMaterial {
  encryption_key : @crypto.Secret
  salt : Bytes
  authentication_key : @crypto.Secret?
}

///|
struct RtpIndexState {
  mut initialized : Bool
  mut highest_index : UInt64
}

///|
struct RtpReceiveState {
  index : RtpIndexState
  replay : @replay.ReplayWindow
}

///|
struct SrtcpReceiveState {
  replay : @replay.ReplayWindow
}

///|
priv struct ParsedRtpHeader {
  length : Int
  sequence_number : UInt16
  ssrc : UInt
}

///|
pub struct Context {
  provider : @crypto.Provider
  profile : ProtectionProfile
  rtp_material : SessionMaterial
  rtcp_material : SessionMaterial
  send_rtp_states : Map[UInt, RtpIndexState]
  receive_rtp_states : Map[UInt, RtpReceiveState]
  send_rtcp_indices : Map[UInt, UInt]
  receive_rtcp_states : Map[UInt, SrtcpReceiveState]
  rtp_replay_window : Int
  rtcp_replay_window : Int
  mut closed : Bool
}

///|
fn[T] srtp_crypto(
  operation : () -> T raise @crypto.CryptoError,
) -> T raise SrtpError {
  operation() catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
}

///|
fn[T] srtp_auth_open(
  operation : () -> T raise @crypto.CryptoError,
) -> T raise SrtpError {
  operation() catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(_) | OperationFailed(_) => raise AuthenticationFailed
  }
}

///|
fn derive_session_value(
  provider : @crypto.Provider,
  master_key : @crypto.Secret,
  master_key_length : Int,
  master_salt : Bytes,
  label : Byte,
  output_length : Int,
) -> Bytes raise SrtpError {
  if output_length < 0 {
    raise InvalidPacket("negative SRTP key derivation length")
  }
  let input : Array[Byte] = Array::make(16, 0)
  for index = 0; index < master_salt.length(); index = index + 1 {
    input[index] = master_salt[index]
  }
  input[7] = input[7] ^ label
  let algorithm : @crypto.CipherAlgorithm = if master_key_length == 16 {
    Aes128Ctr
  } else {
    Aes256Ctr
  }
  srtp_crypto(() => {
    provider.cipher_encrypt(
      algorithm,
      master_key,
      Bytes::from_array(input),
      Bytes::make(output_length, 0),
    )
  })
}

///|
fn build_session_material(
  provider : @crypto.Provider,
  profile : ProtectionProfile,
  master_key : @crypto.Secret,
  master_salt : Bytes,
  encryption_label : Byte,
  authentication_label : Byte,
  salt_label : Byte,
) -> SessionMaterial raise SrtpError {
  let encryption_key = @crypto.Secret::from_bytes(
    derive_session_value(
      provider,
      master_key,
      profile.key_length(),
      master_salt,
      encryption_label,
      profile.key_length(),
    ),
  )
  let salt = derive_session_value(
    provider,
    master_key,
    profile.key_length(),
    master_salt,
    salt_label,
    profile.salt_length(),
  )
  let authentication_key = match profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 =>
      Some(
        @crypto.Secret::from_bytes(
          derive_session_value(
            provider,
            master_key,
            profile.key_length(),
            master_salt,
            authentication_label,
            20,
          ),
        ),
      )
    AeadAes128Gcm | AeadAes256Gcm => None
  }
  { encryption_key, salt, authentication_key }
}

///|
pub fn Context::new(
  profile~ : ProtectionProfile,
  master_key~ : Bytes,
  master_salt~ : Bytes,
  rtp_replay_window? : Int = 64,
  rtcp_replay_window? : Int = 64,
) -> Context raise SrtpError {
  if master_key.length() != profile.key_length() {
    raise InvalidPacket(
      "SRTP master key length \{master_key.length()} does not match profile",
    )
  }
  if master_salt.length() != profile.salt_length() {
    raise InvalidPacket(
      "SRTP master salt length \{master_salt.length()} does not match profile",
    )
  }
  if rtp_replay_window < 1 ||
    rtp_replay_window > 64 ||
    rtcp_replay_window < 1 ||
    rtcp_replay_window > 64 {
    raise InvalidPacket("SRTP replay windows must be between 1 and 64")
  }
  let provider = srtp_crypto(() => @crypto.Provider::open())
  let secret = @crypto.Secret::from_bytes(master_key)
  let rtp_material = build_session_material(
    provider, profile, secret, master_salt, 0x00, 0x01, 0x02,
  )
  let rtcp_material = build_session_material(
    provider, profile, secret, master_salt, 0x03, 0x04, 0x05,
  )
  {
    provider,
    profile,
    rtp_material,
    rtcp_material,
    send_rtp_states: Map([]),
    receive_rtp_states: Map([]),
    send_rtcp_indices: Map([]),
    receive_rtcp_states: Map([]),
    rtp_replay_window,
    rtcp_replay_window,
    closed: false,
  }
}

///|
pub fn Context::profile(self : Context) -> ProtectionProfile {
  self.profile
}

///|
fn parse_rtp_header(data : Bytes) -> ParsedRtpHeader raise SrtpError {
  if data.length() < 12 {
    raise InvalidPacket("RTP packet is shorter than its fixed header")
  }
  if data[0] >> 6 != 2 {
    raise InvalidPacket("unsupported RTP version")
  }
  let csrc_count = (data[0] & 0x0f).to_int()
  let mut length = 12 + csrc_count * 4
  if length > data.length() {
    raise InvalidPacket("truncated RTP CSRC list")
  }
  if (data[0] & 0x10) != 0 {
    if length + 4 > data.length() {
      raise InvalidPacket("truncated RTP extension header")
    }
    let words = ((data[length + 2].to_uint() << 8) | data[length + 3].to_uint()).reinterpret_as_int()
    length += 4 + words * 4
    if length > data.length() {
      raise InvalidPacket("truncated RTP extension payload")
    }
  }
  {
    length,
    sequence_number: ((data[2].to_uint() << 8) | data[3].to_uint()).to_uint16(),
    ssrc: (data[8].to_uint() << 24) |
    (data[9].to_uint() << 16) |
    (data[10].to_uint() << 8) |
    data[11].to_uint(),
  }
}

///|
fn guess_packet_index(
  state : RtpIndexState,
  sequence_number : UInt16,
) -> UInt64 {
  if !state.initialized {
    return sequence_number.to_uint64()
  }
  let local_sequence = (state.highest_index & 0xffffUL).to_uint16()
  let mut rollover = state.highest_index >> 16
  if local_sequence < 0x8000 &&
    sequence_number > local_sequence &&
    sequence_number - local_sequence > 0x8000 {
    if rollover > 0UL {
      rollover -= 1UL
    }
  } else if local_sequence >= 0x8000 &&
    local_sequence > sequence_number &&
    local_sequence - sequence_number > 0x8000 {
    rollover += 1UL
  }
  (rollover << 16) | sequence_number.to_uint64()
}

///|
fn update_packet_index(state : RtpIndexState, index : UInt64) -> Unit {
  if !state.initialized || index > state.highest_index {
    state.initialized = true
    state.highest_index = index
  }
}

///|
fn Context::send_rtp_state(self : Context, ssrc : UInt) -> RtpIndexState {
  match self.send_rtp_states.get(ssrc) {
    Some(state) => state
    None => {
      let state = { initialized: false, highest_index: 0UL }
      self.send_rtp_states[ssrc] = state
      state
    }
  }
}

///|
fn new_replay_window(width : Int) -> @replay.ReplayWindow raise SrtpError {
  @replay.ReplayWindow::new(width~) catch {
    _ => raise InvalidPacket("failed to create SRTP replay window")
  }
}

///|
fn Context::receive_rtp_state(
  self : Context,
  ssrc : UInt,
) -> RtpReceiveState raise SrtpError {
  match self.receive_rtp_states.get(ssrc) {
    Some(state) => state
    None => {
      let state = {
        index: { initialized: false, highest_index: 0UL },
        replay: new_replay_window(self.rtp_replay_window),
      }
      self.receive_rtp_states[ssrc] = state
      state
    }
  }
}

///|
fn write_u16_at(output : Array[Byte], offset : Int, value : UInt16) -> Unit {
  output[offset] = (value >> 8).to_byte()
  output[offset + 1] = value.to_byte()
}

///|
fn write_u32_at(output : Array[Byte], offset : Int, value : UInt) -> Unit {
  output[offset] = (value >> 24).to_byte()
  output[offset + 1] = (value >> 16).to_byte()
  output[offset + 2] = (value >> 8).to_byte()
  output[offset + 3] = value.to_byte()
}

///|
fn aes_cm_counter(
  sequence_number : UInt16,
  rollover_counter : UInt,
  ssrc : UInt,
  salt : Bytes,
) -> Bytes {
  let counter : Array[Byte] = Array::make(16, 0)
  write_u32_at(counter, 4, ssrc)
  write_u32_at(counter, 8, rollover_counter)
  write_u32_at(counter, 12, sequence_number.to_uint() << 16)
  for index = 0; index < salt.length(); index = index + 1 {
    counter[index] = counter[index] ^ salt[index]
  }
  Bytes::from_array(counter)
}

///|
fn aead_rtp_nonce(
  sequence_number : UInt16,
  rollover_counter : UInt,
  ssrc : UInt,
  salt : Bytes,
) -> Bytes {
  let nonce : Array[Byte] = Array::make(12, 0)
  write_u32_at(nonce, 2, ssrc)
  write_u32_at(nonce, 6, rollover_counter)
  write_u16_at(nonce, 10, sequence_number)
  for index = 0; index < salt.length(); index = index + 1 {
    nonce[index] = nonce[index] ^ salt[index]
  }
  Bytes::from_array(nonce)
}

///|
fn aead_rtcp_nonce(index : UInt, ssrc : UInt, salt : Bytes) -> Bytes {
  let nonce : Array[Byte] = Array::make(12, 0)
  write_u32_at(nonce, 2, ssrc)
  write_u32_at(nonce, 8, index)
  for salt_index = 0; salt_index < salt.length(); salt_index = salt_index + 1 {
    nonce[salt_index] = nonce[salt_index] ^ salt[salt_index]
  }
  Bytes::from_array(nonce)
}

///|
fn aead_algorithm(profile : ProtectionProfile) -> @crypto.AeadAlgorithm {
  match profile {
    AeadAes128Gcm => Aes128Gcm
    AeadAes256Gcm => Aes256Gcm
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => Aes128Gcm
  }
}

///|
fn cipher_algorithm(profile : ProtectionProfile) -> @crypto.CipherAlgorithm {
  match profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 | AeadAes128Gcm => Aes128Ctr
    AeadAes256Gcm => Aes256Ctr
  }
}

///|
fn append_rollover(packet : Bytes, rollover_counter : UInt) -> Bytes {
  packet +
  Bytes::from_array([
    (rollover_counter >> 24).to_byte(),
    (rollover_counter >> 16).to_byte(),
    (rollover_counter >> 8).to_byte(),
    rollover_counter.to_byte(),
  ])
}

///|
fn Context::ensure_open(self : Context) -> Unit raise SrtpError {
  if self.closed {
    raise KeyExpired
  }
}

///|
pub fn Context::encrypt_rtp(
  self : Context,
  plaintext : Bytes,
) -> Bytes raise SrtpError {
  self.ensure_open()
  let header = parse_rtp_header(plaintext)
  let state = self.send_rtp_state(header.ssrc)
  let index = guess_packet_index(state, header.sequence_number)
  let rollover = index >> 16
  if rollover > 0xffffffffUL {
    raise KeyExpired
  }
  let header_bytes = plaintext[:header.length].to_owned()
  let payload = plaintext[header.length:].to_owned()
  let result = match self.profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => {
      let ciphertext = srtp_crypto(() => {
        self.provider.cipher_encrypt(
          cipher_algorithm(self.profile),
          self.rtp_material.encryption_key,
          aes_cm_counter(
            header.sequence_number,
            rollover.to_uint(),
            header.ssrc,
            self.rtp_material.salt,
          ),
          payload,
        )
      })
      let authenticated = header_bytes + ciphertext
      guard self.rtp_material.authentication_key is Some(authentication_key) else {
        raise CryptoUnavailable("SRTP authentication key is missing")
      }
      let tag = srtp_crypto(() => {
        self.provider.hmac(
          Sha1,
          authentication_key,
          append_rollover(authenticated, rollover.to_uint()),
        )
      })
      authenticated + tag[:self.profile.rtp_auth_tag_length()].to_owned()
    }
    AeadAes128Gcm | AeadAes256Gcm => {
      let sealed_packet = srtp_crypto(() => {
        self.provider.aead_seal(
          aead_algorithm(self.profile),
          self.rtp_material.encryption_key,
          aead_rtp_nonce(
            header.sequence_number,
            rollover.to_uint(),
            header.ssrc,
            self.rtp_material.salt,
          ),
          header_bytes,
          payload,
        )
      })
      header_bytes + sealed_packet.ciphertext() + sealed_packet.tag()
    }
  }
  update_packet_index(state, index)
  result
}

///|
pub fn Context::protect_rtp(
  self : Context,
  packet : @rtp.Packet,
) -> Bytes raise SrtpError {
  let plaintext = packet.marshal() catch {
    _ => raise InvalidPacket("failed to marshal RTP packet")
  }
  self.encrypt_rtp(plaintext)
}

///|
fn verify_replay(
  replay : @replay.ReplayWindow,
  index : UInt64,
) -> Unit raise SrtpError {
  match replay.check_and_mark(index) {
    Duplicate | TooOld => raise ReplayRejected
    AcceptedNew | AcceptedOutOfOrder => ()
  }
}

///|
pub fn Context::decrypt_rtp(
  self : Context,
  encrypted : Bytes,
) -> Bytes raise SrtpError {
  self.ensure_open()
  let header = parse_rtp_header(encrypted)
  let state = self.receive_rtp_state(header.ssrc)
  let index = guess_packet_index(state.index, header.sequence_number)
  let rollover = index >> 16
  if rollover > 0xffffffffUL {
    raise KeyExpired
  }
  let header_bytes = encrypted[:header.length].to_owned()
  let plaintext = match self.profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => {
      let tag_length = self.profile.rtp_auth_tag_length()
      if encrypted.length() < header.length + tag_length {
        raise InvalidPacket(
          "SRTP packet is shorter than its authentication tag",
        )
      }
      let tag_offset = encrypted.length() - tag_length
      let authenticated = encrypted[:tag_offset].to_owned()
      guard self.rtp_material.authentication_key is Some(authentication_key) else {
        raise CryptoUnavailable("SRTP authentication key is missing")
      }
      let expected = srtp_crypto(() => {
        self.provider.hmac(
          Sha1,
          authentication_key,
          append_rollover(authenticated, rollover.to_uint()),
        )
      })
      if !self.provider.constant_time_equal(
          encrypted[tag_offset:].to_owned(),
          expected[:tag_length].to_owned(),
        ) {
        raise AuthenticationFailed
      }
      let payload = srtp_crypto(() => {
        self.provider.cipher_decrypt(
          cipher_algorithm(self.profile),
          self.rtp_material.encryption_key,
          aes_cm_counter(
            header.sequence_number,
            rollover.to_uint(),
            header.ssrc,
            self.rtp_material.salt,
          ),
          encrypted[header.length:tag_offset].to_owned(),
        )
      })
      header_bytes + payload
    }
    AeadAes128Gcm | AeadAes256Gcm => {
      let tag_length = 16
      if encrypted.length() < header.length + tag_length {
        raise InvalidPacket("SRTP packet is shorter than its AEAD tag")
      }
      let tag_offset = encrypted.length() - tag_length
      let sealed_packet = srtp_auth_open(() => {
        @crypto.AeadSealed::new(
          ciphertext=encrypted[header.length:tag_offset].to_owned(),
          tag=encrypted[tag_offset:].to_owned(),
        )
      })
      let payload = srtp_auth_open(() => {
        self.provider.aead_open(
          aead_algorithm(self.profile),
          self.rtp_material.encryption_key,
          aead_rtp_nonce(
            header.sequence_number,
            rollover.to_uint(),
            header.ssrc,
            self.rtp_material.salt,
          ),
          header_bytes,
          sealed_packet,
        )
      })
      header_bytes + payload
    }
  }
  verify_replay(state.replay, index)
  update_packet_index(state.index, index)
  plaintext
}

///|
pub fn Context::unprotect_rtp(
  self : Context,
  encrypted : Bytes,
) -> @rtp.Packet raise SrtpError {
  let plaintext = self.decrypt_rtp(encrypted)
  @rtp.Packet::unmarshal(plaintext) catch {
    _ => raise InvalidPacket("failed to unmarshal decrypted RTP packet")
  }
}

///|
fn rtcp_ssrc(plaintext : Bytes) -> UInt raise SrtpError {
  if plaintext.length() < 8 || plaintext[0] >> 6 != 2 {
    raise InvalidPacket("SRTCP packet is shorter than its SSRC prefix")
  }
  (plaintext[4].to_uint() << 24) |
  (plaintext[5].to_uint() << 16) |
  (plaintext[6].to_uint() << 8) |
  plaintext[7].to_uint()
}

///|
fn encode_srtcp_index(index : UInt) -> Bytes {
  let encrypted_index = index | 0x80000000U
  Bytes::from_array([
    (encrypted_index >> 24).to_byte(),
    (encrypted_index >> 16).to_byte(),
    (encrypted_index >> 8).to_byte(),
    encrypted_index.to_byte(),
  ])
}

///|
fn decode_srtcp_index(data : Bytes, offset : Int) -> UInt raise SrtpError {
  if offset < 0 || offset + 4 > data.length() {
    raise InvalidPacket("truncated SRTCP index")
  }
  let encoded = (data[offset].to_uint() << 24) |
    (data[offset + 1].to_uint() << 16) |
    (data[offset + 2].to_uint() << 8) |
    data[offset + 3].to_uint()
  if (encoded & 0x80000000U) == 0U {
    raise InvalidPacket("unencrypted SRTCP packets are not supported")
  }
  encoded & 0x7fffffffU
}

///|
pub fn Context::encrypt_rtcp(
  self : Context,
  plaintext : Bytes,
) -> Bytes raise SrtpError {
  self.ensure_open()
  ignore(
    @rtcp.decode_compound(plaintext) catch {
      _ => raise InvalidPacket("invalid plaintext RTCP compound packet")
    },
  )
  let ssrc = rtcp_ssrc(plaintext)
  let previous = self.send_rtcp_indices.get(ssrc).unwrap_or(0U)
  if previous >= 0x7fffffffU {
    raise KeyExpired
  }
  let index = previous + 1U
  let index_bytes = encode_srtcp_index(index)
  let result = match self.profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => {
      let payload = srtp_crypto(() => {
        self.provider.cipher_encrypt(
          cipher_algorithm(self.profile),
          self.rtcp_material.encryption_key,
          aes_cm_counter(
            index.to_uint16(),
            index >> 16,
            ssrc,
            self.rtcp_material.salt,
          ),
          plaintext[8:].to_owned(),
        )
      })
      let authenticated = plaintext[:8].to_owned() + payload + index_bytes
      guard self.rtcp_material.authentication_key is Some(authentication_key) else {
        raise CryptoUnavailable("SRTCP authentication key is missing")
      }
      let tag = srtp_crypto(() => {
        self.provider.hmac(Sha1, authentication_key, authenticated)
      })
      authenticated + tag[:10].to_owned()
    }
    AeadAes128Gcm | AeadAes256Gcm => {
      let aad = plaintext[:8].to_owned() + index_bytes
      let sealed_packet = srtp_crypto(() => {
        self.provider.aead_seal(
          aead_algorithm(self.profile),
          self.rtcp_material.encryption_key,
          aead_rtcp_nonce(index, ssrc, self.rtcp_material.salt),
          aad,
          plaintext[8:].to_owned(),
        )
      })
      plaintext[:8].to_owned() +
      sealed_packet.ciphertext() +
      sealed_packet.tag() +
      index_bytes
    }
  }
  self.send_rtcp_indices[ssrc] = index
  result
}

///|
fn Context::receive_rtcp_state(
  self : Context,
  ssrc : UInt,
) -> SrtcpReceiveState raise SrtpError {
  match self.receive_rtcp_states.get(ssrc) {
    Some(state) => state
    None => {
      let state = { replay: new_replay_window(self.rtcp_replay_window) }
      self.receive_rtcp_states[ssrc] = state
      state
    }
  }
}

///|
pub fn Context::decrypt_rtcp(
  self : Context,
  encrypted : Bytes,
) -> Bytes raise SrtpError {
  self.ensure_open()
  let ssrc = rtcp_ssrc(encrypted)
  let (index_offset, tag_offset, index) = match self.profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => {
      if encrypted.length() < 8 + 4 + 10 {
        raise InvalidPacket("SRTCP packet is too short")
      }
      let index_offset = encrypted.length() - 14
      (
        index_offset,
        encrypted.length() - 10,
        decode_srtcp_index(encrypted, index_offset),
      )
    }
    AeadAes128Gcm | AeadAes256Gcm => {
      if encrypted.length() < 8 + 16 + 4 {
        raise InvalidPacket("AEAD SRTCP packet is too short")
      }
      let index_offset = encrypted.length() - 4
      (
        index_offset,
        index_offset - 16,
        decode_srtcp_index(encrypted, index_offset),
      )
    }
  }
  let plaintext = match self.profile {
    Aes128CmHmacSha1_80 | Aes128CmHmacSha1_32 => {
      guard self.rtcp_material.authentication_key is Some(authentication_key) else {
        raise CryptoUnavailable("SRTCP authentication key is missing")
      }
      let expected = srtp_crypto(() => {
        self.provider.hmac(
          Sha1,
          authentication_key,
          encrypted[:tag_offset].to_owned(),
        )
      })
      if !self.provider.constant_time_equal(
          encrypted[tag_offset:].to_owned(),
          expected[:10].to_owned(),
        ) {
        raise AuthenticationFailed
      }
      let payload = srtp_crypto(() => {
        self.provider.cipher_decrypt(
          cipher_algorithm(self.profile),
          self.rtcp_material.encryption_key,
          aes_cm_counter(
            index.to_uint16(),
            index >> 16,
            ssrc,
            self.rtcp_material.salt,
          ),
          encrypted[8:index_offset].to_owned(),
        )
      })
      encrypted[:8].to_owned() + payload
    }
    AeadAes128Gcm | AeadAes256Gcm => {
      let index_bytes = encrypted[index_offset:].to_owned()
      let aad = encrypted[:8].to_owned() + index_bytes
      let sealed_packet = srtp_auth_open(() => {
        @crypto.AeadSealed::new(
          ciphertext=encrypted[8:tag_offset].to_owned(),
          tag=encrypted[tag_offset:index_offset].to_owned(),
        )
      })
      let payload = srtp_auth_open(() => {
        self.provider.aead_open(
          aead_algorithm(self.profile),
          self.rtcp_material.encryption_key,
          aead_rtcp_nonce(index, ssrc, self.rtcp_material.salt),
          aad,
          sealed_packet,
        )
      })
      encrypted[:8].to_owned() + payload
    }
  }
  let receive_state = self.receive_rtcp_state(ssrc)
  verify_replay(receive_state.replay, index.to_uint64())
  ignore(
    @rtcp.decode_compound(plaintext) catch {
      _ => raise InvalidPacket("decrypted SRTCP is not a compound packet")
    },
  )
  plaintext
}

///|
pub fn Context::protect_rtcp(
  self : Context,
  packets : Array[@rtcp.Packet],
) -> Bytes raise SrtpError {
  let plaintext = @rtcp.encode_compound(packets) catch {
    _ => raise InvalidPacket("failed to marshal RTCP compound packet")
  }
  self.encrypt_rtcp(plaintext)
}

///|
pub fn Context::unprotect_rtcp(
  self : Context,
  encrypted : Bytes,
) -> Array[@rtcp.Packet] raise SrtpError {
  let plaintext = self.decrypt_rtcp(encrypted)
  @rtcp.decode_compound(plaintext) catch {
    _ => raise InvalidPacket("failed to unmarshal decrypted RTCP packet")
  }
}

///|
pub fn Context::close(self : Context) -> Unit {
  if self.closed {
    return
  }
  self.closed = true
  self.send_rtp_states.clear()
  self.receive_rtp_states.clear()
  self.send_rtcp_indices.clear()
  self.receive_rtcp_states.clear()
}
