///|
fn write_opaque8(
  writer : @codec.Writer,
  value : Bytes,
  context : String,
) -> Unit raise DtlsError {
  if value.length() > 0xff {
    raise InvalidHandshake("\{context} exceeds 255 bytes")
  }
  writer.write_u8(value.length().to_byte())
  writer.write_bytes(value)
}

///|
fn write_opaque16(
  writer : @codec.Writer,
  value : Bytes,
  context : String,
) -> Unit raise DtlsError {
  if value.length() > 0xffff {
    raise InvalidHandshake("\{context} exceeds 65535 bytes")
  }
  writer.write_u16_be(value.length().to_uint16())
  writer.write_bytes(value)
}

///|
fn write_opaque24(
  writer : @codec.Writer,
  value : Bytes,
  context : String,
) -> Unit raise DtlsError {
  if value.length() > 0xffffff {
    raise InvalidHandshake("\{context} exceeds 24-bit framing")
  }
  writer.write_u24_be(value.length().reinterpret_as_uint())
  writer.write_bytes(value)
}

///|
fn read_opaque8(
  reader : @codec.Reader,
  context : String,
) -> Bytes raise DtlsError {
  let length = hs_read_u8(reader, context).to_int()
  hs_read_bytes(reader, length, context)
}

///|
fn read_opaque16(
  reader : @codec.Reader,
  context : String,
) -> Bytes raise DtlsError {
  let length = hs_read_u16(reader, context).to_int()
  hs_read_bytes(reader, length, context)
}

///|
fn read_opaque24(
  reader : @codec.Reader,
  context : String,
) -> Bytes raise DtlsError {
  let length = hs_read_u24(reader, context).reinterpret_as_int()
  hs_read_bytes(reader, length, context)
}

///|
pub struct ClientHelloMessage {
  random : Bytes
  session_id : Bytes
  cookie : Bytes
  cipher_suites : Array[UInt16]
  compression_methods : Array[Byte]
  extensions : HelloExtensions
} derive(Debug, Eq)

///|
pub fn ClientHelloMessage::new(
  random~ : Bytes,
  cookie? : Bytes = b"",
  cipher_suites? : Array[CipherSuite] = [EcdheEcdsaAes128GcmSha256],
  extensions~ : HelloExtensions,
) -> ClientHelloMessage raise DtlsError {
  if random.length() != 32 {
    raise InvalidHandshake("ClientHello random must contain 32 bytes")
  }
  if cookie.length() > 255 {
    raise InvalidHandshake("ClientHello cookie exceeds 255 bytes")
  }
  if cipher_suites.is_empty() {
    raise InvalidHandshake("ClientHello must offer a cipher suite")
  }
  let cipher_suite_codes : Array[UInt16] = []
  for suite in cipher_suites {
    if cipher_suite_codes.contains(suite.code()) {
      raise InvalidHandshake("ClientHello contains a duplicate cipher suite")
    }
    cipher_suite_codes.push(suite.code())
  }
  {
    random,
    session_id: b"",
    cookie,
    cipher_suites: cipher_suite_codes,
    compression_methods: [0],
    extensions,
  }
}

///|
pub fn ClientHelloMessage::random(self : ClientHelloMessage) -> Bytes {
  self.random
}

///|
pub fn ClientHelloMessage::cookie(self : ClientHelloMessage) -> Bytes {
  self.cookie
}

///|
pub fn ClientHelloMessage::cipher_suites(
  self : ClientHelloMessage,
) -> Array[UInt16] {
  self.cipher_suites.copy()
}

///|
pub fn ClientHelloMessage::extensions(
  self : ClientHelloMessage,
) -> HelloExtensions {
  self.extensions
}

///|
fn ClientHelloMessage::encode_body(
  self : ClientHelloMessage,
) -> Bytes raise DtlsError {
  if self.session_id.length() > 32 ||
    self.cipher_suites.is_empty() ||
    self.cipher_suites.length() > 0x7fff ||
    self.compression_methods.is_empty() ||
    self.compression_methods.length() > 0xff {
    raise InvalidHandshake("invalid ClientHello vector length")
  }
  let writer = dtls_writer(256, "ClientHello")
  writer.write_u8(Dtls12.major())
  writer.write_u8(Dtls12.minor())
  writer.write_bytes(self.random)
  write_opaque8(writer, self.session_id, "ClientHello session ID")
  write_opaque8(writer, self.cookie, "ClientHello cookie")
  writer.write_u16_be((self.cipher_suites.length() * 2).to_uint16())
  for cipher_suite in self.cipher_suites {
    writer.write_u16_be(cipher_suite)
  }
  writer.write_u8(self.compression_methods.length().to_byte())
  for compression_method in self.compression_methods {
    writer.write_u8(compression_method)
  }
  writer.write_bytes(self.extensions.encode())
  writer.finish()
}

///|
fn ClientHelloMessage::decode_body(
  body : Bytes,
) -> ClientHelloMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  let version = ProtocolVersion::from_bytes(
    hs_read_u8(reader, "ClientHello version"),
    hs_read_u8(reader, "ClientHello version"),
  )
  if version != Dtls12 {
    raise UnsupportedVersion
  }
  let random = hs_read_bytes(reader, 32, "ClientHello random")
  let session_id = read_opaque8(reader, "ClientHello session ID")
  if session_id.length() > 32 {
    raise InvalidHandshake("ClientHello session ID exceeds 32 bytes")
  }
  let cookie = read_opaque8(reader, "ClientHello cookie")
  let cipher_suite_bytes = hs_read_u16(reader, "ClientHello cipher suites").to_int()
  if cipher_suite_bytes == 0 ||
    cipher_suite_bytes % 2 != 0 ||
    reader.remaining() < cipher_suite_bytes {
    raise InvalidHandshake("malformed ClientHello cipher-suite vector")
  }
  let cipher_suites : Array[UInt16] = []
  for offset = 0; offset < cipher_suite_bytes; offset = offset + 2 {
    cipher_suites.push(hs_read_u16(reader, "ClientHello cipher suite"))
  }
  let compression_count = hs_read_u8(reader, "ClientHello compression methods").to_int()
  if compression_count == 0 || reader.remaining() < compression_count {
    raise InvalidHandshake("malformed ClientHello compression vector")
  }
  let compression_methods = hs_read_bytes(
    reader, compression_count, "ClientHello compression methods",
  ).to_array()
  if !compression_methods.contains(0) {
    raise InvalidHandshake("ClientHello does not offer null compression")
  }
  if reader.remaining() < 2 {
    raise InvalidHandshake("ClientHello extensions are missing")
  }
  let extensions = HelloExtensions::decode(
    hs_read_bytes(reader, reader.remaining(), "ClientHello extensions"),
  )
  { random, session_id, cookie, cipher_suites, compression_methods, extensions }
}

///|
pub struct ServerHelloMessage {
  random : Bytes
  session_id : Bytes
  cipher_suite : UInt16
  compression_method : Byte
  extensions : HelloExtensions
} derive(Debug, Eq)

///|
pub fn ServerHelloMessage::new(
  random~ : Bytes,
  cipher_suite? : CipherSuite = EcdheEcdsaAes128GcmSha256,
  selected_srtp_profile? : UInt16,
) -> ServerHelloMessage raise DtlsError {
  if random.length() != 32 {
    raise InvalidHandshake("ServerHello random must contain 32 bytes")
  }
  {
    random,
    session_id: b"",
    cipher_suite: cipher_suite.code(),
    compression_method: 0,
    extensions: HelloExtensions::server(selected_srtp_profile),
  }
}

///|
pub fn ServerHelloMessage::random(self : ServerHelloMessage) -> Bytes {
  self.random
}

///|
pub fn ServerHelloMessage::cipher_suite(self : ServerHelloMessage) -> UInt16 {
  self.cipher_suite
}

///|
pub fn ServerHelloMessage::extensions(
  self : ServerHelloMessage,
) -> HelloExtensions {
  self.extensions
}

///|
fn ServerHelloMessage::encode_body(
  self : ServerHelloMessage,
) -> Bytes raise DtlsError {
  if self.random.length() != 32 || self.session_id.length() > 32 {
    raise InvalidHandshake("invalid ServerHello field length")
  }
  let writer = dtls_writer(160, "ServerHello")
  writer.write_u8(Dtls12.major())
  writer.write_u8(Dtls12.minor())
  writer.write_bytes(self.random)
  write_opaque8(writer, self.session_id, "ServerHello session ID")
  writer.write_u16_be(self.cipher_suite)
  writer.write_u8(self.compression_method)
  writer.write_bytes(self.extensions.encode())
  writer.finish()
}

///|
fn ServerHelloMessage::decode_body(
  body : Bytes,
) -> ServerHelloMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  let version = ProtocolVersion::from_bytes(
    hs_read_u8(reader, "ServerHello version"),
    hs_read_u8(reader, "ServerHello version"),
  )
  if version != Dtls12 {
    raise UnsupportedVersion
  }
  let random = hs_read_bytes(reader, 32, "ServerHello random")
  let session_id = read_opaque8(reader, "ServerHello session ID")
  if session_id.length() > 32 {
    raise InvalidHandshake("ServerHello session ID exceeds 32 bytes")
  }
  let cipher_suite = hs_read_u16(reader, "ServerHello cipher suite")
  let compression_method = hs_read_u8(reader, "ServerHello compression method")
  if compression_method != 0 {
    raise InvalidHandshake("ServerHello selected non-null compression")
  }
  let extensions = HelloExtensions::decode(
    hs_read_bytes(reader, reader.remaining(), "ServerHello extensions"),
  )
  { random, session_id, cipher_suite, compression_method, extensions }
}

///|
pub struct HelloVerifyRequestMessage {
  cookie : Bytes
} derive(Debug, Eq)

///|
fn HelloVerifyRequestMessage::encode_body(
  self : HelloVerifyRequestMessage,
) -> Bytes raise DtlsError {
  let writer = dtls_writer(3 + self.cookie.length(), "HelloVerifyRequest")
  writer.write_u8(Dtls12.major())
  writer.write_u8(Dtls12.minor())
  write_opaque8(writer, self.cookie, "HelloVerifyRequest cookie")
  writer.finish()
}

///|
fn HelloVerifyRequestMessage::decode_body(
  body : Bytes,
) -> HelloVerifyRequestMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  ignore(
    ProtocolVersion::from_bytes(
      hs_read_u8(reader, "HelloVerifyRequest version"),
      hs_read_u8(reader, "HelloVerifyRequest version"),
    ),
  )
  let cookie = read_opaque8(reader, "HelloVerifyRequest cookie")
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing HelloVerifyRequest bytes")
  }
  { cookie, }
}

///|
pub struct CertificateMessage {
  certificates : Array[Bytes]
} derive(Debug, Eq)

///|
fn CertificateMessage::encode_body(
  self : CertificateMessage,
) -> Bytes raise DtlsError {
  let certificates = dtls_writer(1024, "Certificate list")
  for certificate in self.certificates {
    write_opaque24(certificates, certificate, "certificate")
  }
  let certificates = certificates.finish()
  let writer = dtls_writer(certificates.length() + 3, "Certificate")
  write_opaque24(writer, certificates, "certificate list")
  writer.finish()
}

///|
fn CertificateMessage::decode_body(
  body : Bytes,
) -> CertificateMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  let encoded_certificates = read_opaque24(reader, "certificate list")
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing Certificate message bytes")
  }
  let certificate_reader = @codec.Reader::new(encoded_certificates)
  let certificates : Array[Bytes] = []
  while certificate_reader.remaining() > 0 {
    certificates.push(read_opaque24(certificate_reader, "certificate"))
  }
  { certificates, }
}

///|
pub struct ServerKeyExchangeMessage {
  named_curve : UInt16
  public_key : Bytes
  signature_algorithm : UInt16
  signature : Bytes
  identity_hint : Bytes?
} derive(Debug, Eq)

///|
fn ServerKeyExchangeMessage::parameters(
  self : ServerKeyExchangeMessage,
) -> Bytes raise DtlsError {
  if self.identity_hint is Some(_) {
    raise InvalidHandshake("PSK ServerKeyExchange has no ECDHE parameters")
  }
  let writer = dtls_writer(4 + self.public_key.length(), "ECDHE parameters")
  writer.write_u8(3)
  writer.write_u16_be(self.named_curve)
  write_opaque8(writer, self.public_key, "ECDHE public key")
  writer.finish()
}

///|
fn ServerKeyExchangeMessage::encode_body(
  self : ServerKeyExchangeMessage,
) -> Bytes raise DtlsError {
  match self.identity_hint {
    Some(identity_hint) => {
      let writer = dtls_writer(
        2 + identity_hint.length(),
        "PSK ServerKeyExchange",
      )
      write_opaque16(writer, identity_hint, "PSK identity hint")
      return writer.finish()
    }
    None => ()
  }
  let writer = dtls_writer(160, "ServerKeyExchange")
  writer.write_bytes(self.parameters())
  writer.write_u16_be(self.signature_algorithm)
  write_opaque16(writer, self.signature, "ServerKeyExchange signature")
  writer.finish()
}

///|
fn ServerKeyExchangeMessage::decode_body(
  body : Bytes,
) -> ServerKeyExchangeMessage raise DtlsError {
  if body.length() >= 2 {
    let identity_length = ((body[0].to_uint() << 8) | body[1].to_uint()).reinterpret_as_int()
    if identity_length + 2 == body.length() {
      return {
        named_curve: 0,
        public_key: b"",
        signature_algorithm: 0,
        signature: b"",
        identity_hint: Some(body[2:].to_owned()),
      }
    }
  }
  let reader = @codec.Reader::new(body)
  if hs_read_u8(reader, "elliptic curve type") != 3 {
    raise InvalidHandshake("only named ECDHE curves are supported")
  }
  let named_curve = hs_read_u16(reader, "named curve")
  let public_key = read_opaque8(reader, "ECDHE public key")
  let signature_algorithm = hs_read_u16(
    reader, "ServerKeyExchange signature algorithm",
  )
  let signature = read_opaque16(reader, "ServerKeyExchange signature")
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing ServerKeyExchange bytes")
  }
  {
    named_curve,
    public_key,
    signature_algorithm,
    signature,
    identity_hint: None,
  }
}

///|
pub struct CertificateRequestMessage {
  certificate_types : Array[Byte]
  signature_algorithms : Array[UInt16]
} derive(Debug, Eq)

///|
fn CertificateRequestMessage::webrtc(
  certificate_type : Byte,
  signature_algorithm : UInt16,
) -> CertificateRequestMessage {
  {
    certificate_types: [certificate_type],
    signature_algorithms: [signature_algorithm],
  }
}

///|
fn CertificateRequestMessage::encode_body(
  self : CertificateRequestMessage,
) -> Bytes raise DtlsError {
  if self.certificate_types.is_empty() || self.certificate_types.length() > 0xff {
    raise InvalidHandshake("invalid certificate-type vector")
  }
  let writer = dtls_writer(32, "CertificateRequest")
  writer.write_u8(self.certificate_types.length().to_byte())
  for certificate_type in self.certificate_types {
    writer.write_u8(certificate_type)
  }
  writer.write_bytes(u16_vector(self.signature_algorithms))
  writer.write_u16_be(0)
  writer.finish()
}

///|
fn CertificateRequestMessage::decode_body(
  body : Bytes,
) -> CertificateRequestMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  let certificate_type_count = hs_read_u8(
    reader, "CertificateRequest certificate types",
  ).to_int()
  if certificate_type_count == 0 {
    raise InvalidHandshake("CertificateRequest has no certificate type")
  }
  let certificate_types = hs_read_bytes(
    reader, certificate_type_count, "CertificateRequest certificate types",
  ).to_array()
  let algorithm_length = hs_read_u16(
    reader, "CertificateRequest signature algorithms",
  ).to_int()
  if algorithm_length == 0 ||
    algorithm_length % 2 != 0 ||
    reader.remaining() < algorithm_length + 2 {
    raise InvalidHandshake("malformed CertificateRequest signature vector")
  }
  let signature_algorithms : Array[UInt16] = []
  for offset = 0; offset < algorithm_length; offset = offset + 2 {
    signature_algorithms.push(
      hs_read_u16(reader, "CertificateRequest signature algorithm"),
    )
  }
  let authorities_length = hs_read_u16(reader, "CertificateRequest authorities").to_int()
  ignore(
    hs_read_bytes(reader, authorities_length, "CertificateRequest authorities"),
  )
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing CertificateRequest bytes")
  }
  { certificate_types, signature_algorithms }
}

///|
pub struct ClientKeyExchangeMessage {
  public_key : Bytes
  identity_hint : Bytes?
} derive(Debug, Eq)

///|
fn ClientKeyExchangeMessage::encode_body(
  self : ClientKeyExchangeMessage,
) -> Bytes raise DtlsError {
  match self.identity_hint {
    Some(identity_hint) => {
      let writer = dtls_writer(
        2 + identity_hint.length(),
        "PSK ClientKeyExchange",
      )
      write_opaque16(writer, identity_hint, "PSK identity")
      return writer.finish()
    }
    None => ()
  }
  let writer = dtls_writer(66, "ClientKeyExchange")
  write_opaque8(writer, self.public_key, "ECDHE public key")
  writer.finish()
}

///|
fn ClientKeyExchangeMessage::decode_body(
  body : Bytes,
) -> ClientKeyExchangeMessage raise DtlsError {
  if body.length() >= 2 {
    let identity_length = ((body[0].to_uint() << 8) | body[1].to_uint()).reinterpret_as_int()
    if identity_length + 2 == body.length() {
      return { public_key: b"", identity_hint: Some(body[2:].to_owned()) }
    }
  }
  let reader = @codec.Reader::new(body)
  let public_key = read_opaque8(reader, "ECDHE public key")
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing ClientKeyExchange bytes")
  }
  { public_key, identity_hint: None }
}

///|
pub struct CertificateVerifyMessage {
  signature_algorithm : UInt16
  signature : Bytes
} derive(Debug, Eq)

///|
fn CertificateVerifyMessage::encode_body(
  self : CertificateVerifyMessage,
) -> Bytes raise DtlsError {
  let writer = dtls_writer(4 + self.signature.length(), "CertificateVerify")
  writer.write_u16_be(self.signature_algorithm)
  write_opaque16(writer, self.signature, "CertificateVerify signature")
  writer.finish()
}

///|
fn CertificateVerifyMessage::decode_body(
  body : Bytes,
) -> CertificateVerifyMessage raise DtlsError {
  let reader = @codec.Reader::new(body)
  let signature_algorithm = hs_read_u16(
    reader, "CertificateVerify signature algorithm",
  )
  let signature = read_opaque16(reader, "CertificateVerify signature")
  if reader.remaining() != 0 {
    raise InvalidHandshake("trailing CertificateVerify bytes")
  }
  { signature_algorithm, signature }
}

///|
pub struct FinishedMessage {
  verify_data : Bytes
} derive(Debug, Eq)

///|
fn FinishedMessage::encode_body(
  self : FinishedMessage,
) -> Bytes raise DtlsError {
  if self.verify_data.length() != 12 {
    raise InvalidHandshake("Finished verify_data must contain 12 bytes")
  }
  self.verify_data
}

///|
fn FinishedMessage::decode_body(
  body : Bytes,
) -> FinishedMessage raise DtlsError {
  if body.length() != 12 {
    raise InvalidHandshake("Finished verify_data must contain 12 bytes")
  }
  { verify_data: body }
}

///|
pub(all) enum HandshakeMessage {
  ClientHelloHandshake(ClientHelloMessage)
  ServerHelloHandshake(ServerHelloMessage)
  HelloVerifyRequestHandshake(HelloVerifyRequestMessage)
  CertificateHandshake(CertificateMessage)
  ServerKeyExchangeHandshake(ServerKeyExchangeMessage)
  CertificateRequestHandshake(CertificateRequestMessage)
  ServerHelloDoneHandshake
  CertificateVerifyHandshake(CertificateVerifyMessage)
  ClientKeyExchangeHandshake(ClientKeyExchangeMessage)
  FinishedHandshake(FinishedMessage)
} derive(Debug, Eq)

///|
pub fn HandshakeMessage::handshake_type(
  self : HandshakeMessage,
) -> HandshakeType {
  match self {
    ClientHelloHandshake(_) => ClientHello
    ServerHelloHandshake(_) => ServerHello
    HelloVerifyRequestHandshake(_) => HelloVerifyRequest
    CertificateHandshake(_) => Certificate
    ServerKeyExchangeHandshake(_) => ServerKeyExchange
    CertificateRequestHandshake(_) => CertificateRequest
    ServerHelloDoneHandshake => ServerHelloDone
    CertificateVerifyHandshake(_) => CertificateVerify
    ClientKeyExchangeHandshake(_) => ClientKeyExchange
    FinishedHandshake(_) => Finished
  }
}

///|
pub fn HandshakeMessage::encode_body(
  self : HandshakeMessage,
) -> Bytes raise DtlsError {
  match self {
    ClientHelloHandshake(message) => message.encode_body()
    ServerHelloHandshake(message) => message.encode_body()
    HelloVerifyRequestHandshake(message) => message.encode_body()
    CertificateHandshake(message) => message.encode_body()
    ServerKeyExchangeHandshake(message) => message.encode_body()
    CertificateRequestHandshake(message) => message.encode_body()
    ServerHelloDoneHandshake => b""
    CertificateVerifyHandshake(message) => message.encode_body()
    ClientKeyExchangeHandshake(message) => message.encode_body()
    FinishedHandshake(message) => message.encode_body()
  }
}

///|
pub fn HandshakeMessage::to_fragment(
  self : HandshakeMessage,
  message_sequence : UInt16,
) -> HandshakeFragment raise DtlsError {
  let body = self.encode_body()
  HandshakeFragment::new(
    handshake_type=self.handshake_type(),
    total_length=body.length().reinterpret_as_uint(),
    message_sequence~,
    fragment_offset=0,
    body~,
  )
}

///|
pub fn HandshakeMessage::decode(
  fragment : HandshakeFragment,
) -> HandshakeMessage raise DtlsError {
  if !fragment.is_complete() {
    raise InvalidHandshake(
      "fragmented handshake must be reassembled before decoding",
    )
  }
  match fragment.handshake_type {
    ClientHello =>
      ClientHelloHandshake(ClientHelloMessage::decode_body(fragment.body))
    ServerHello =>
      ServerHelloHandshake(ServerHelloMessage::decode_body(fragment.body))
    HelloVerifyRequest =>
      HelloVerifyRequestHandshake(
        HelloVerifyRequestMessage::decode_body(fragment.body),
      )
    Certificate =>
      CertificateHandshake(CertificateMessage::decode_body(fragment.body))
    ServerKeyExchange =>
      ServerKeyExchangeHandshake(
        ServerKeyExchangeMessage::decode_body(fragment.body),
      )
    CertificateRequest =>
      CertificateRequestHandshake(
        CertificateRequestMessage::decode_body(fragment.body),
      )
    ServerHelloDone => {
      if !fragment.body.is_empty() {
        raise InvalidHandshake("ServerHelloDone must be empty")
      }
      ServerHelloDoneHandshake
    }
    CertificateVerify =>
      CertificateVerifyHandshake(
        CertificateVerifyMessage::decode_body(fragment.body),
      )
    ClientKeyExchange =>
      ClientKeyExchangeHandshake(
        ClientKeyExchangeMessage::decode_body(fragment.body),
      )
    Finished => FinishedHandshake(FinishedMessage::decode_body(fragment.body))
    _ =>
      raise InvalidHandshake(
        "unsupported DTLS handshake type \{fragment.handshake_type.code()}",
      )
  }
}
