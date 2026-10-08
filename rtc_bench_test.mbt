///|
fn bench_sdp_wire() -> String {
  "v=0\r\n" +
  "o=- 1 2 IN IP4 0.0.0.0\r\n" +
  "s=-\r\n" +
  "t=0 0\r\n" +
  "a=group:BUNDLE 0\r\n" +
  "a=ice-ufrag:abcd\r\n" +
  "a=ice-pwd:abcdefghijklmnopqrstuv\r\n" +
  "a=fingerprint:sha-256 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F\r\n" +
  "a=setup:actpass\r\n" +
  "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" +
  "c=IN IP4 0.0.0.0\r\n" +
  "a=mid:0\r\n" +
  "a=sctp-port:5000\r\n" +
  "a=max-message-size:262144\r\n"
}

///|
test "bench SDP parse and marshal" (it : @bench.T) {
  let wire = bench_sdp_wire()
  it.bench(() => {
    let document = try! @sdp.SdpDocument::parse(wire)
    document.marshal() |> ignore
  })
}

///|
test "bench STUN decode and encode" (it : @bench.T) {
  let transaction_id = try! @stun.TransactionId::from_bytes(b"0123456789ab")
  let request = @stun.Message::new(
    class=Request,
    stun_method=Binding,
    transaction_id~,
    attributes=[
      try! @stun.Attribute::username("remote:local"),
      @stun.Attribute::priority(1862270975U),
      @stun.Attribute::ice_controlling(0x0102030405060708UL),
      @stun.Attribute::use_candidate(),
    ],
  )
  let wire = try! request.encode_authenticated(b"benchmark-password")
  it.bench(() => {
    let decoded = try! @stun.Message::decode(wire)
    try! (decoded.encode() |> ignore)
  })
}

///|
fn bench_dtls_pair() -> (@dtls.Endpoint, @dtls.Endpoint) {
  let not_before = @transport.WallTime::from_unix_nanoseconds(
    1700000000000000000L,
  )
  let not_after = @transport.WallTime::from_unix_nanoseconds(
    1800000000000000000L,
  )
  let wall_time = @transport.WallTime::from_unix_nanoseconds(
    1750000000000000000L,
  )
  let client_identity = try! @dtls.CertificateIdentity::generate(
    not_before~,
    not_after~,
  )
  let server_identity = try! @dtls.CertificateIdentity::generate(
    not_before~,
    not_after~,
  )
  let profiles = [@dtls.SrtpProtectionProfile::aead_aes128_gcm()]
  let client = try! @dtls.Endpoint::new(
    @dtls.Config::new(
      role=Client,
      identity=client_identity,
      expected_peer_fingerprint=server_identity.fingerprint(),
      wall_time~,
      cipher_suites=[EcdheEcdsaAes128GcmSha256],
      srtp_profiles=profiles,
    ),
  )
  let server = try! @dtls.Endpoint::new(
    @dtls.Config::new(
      role=Server,
      identity=server_identity,
      expected_peer_fingerprint=client_identity.fingerprint(),
      wall_time~,
      cipher_suites=[EcdheEcdsaAes128GcmSha256],
      srtp_profiles=profiles,
    ),
  )
  let now = try! @transport.Instant::from_milliseconds(0)
  try! client.start(now)
  try! server.start(now)
  for step = 0; step < 200; step = step + 1 {
    match client.poll_datagram() {
      Some(datagram) => try! server.handle_datagram(now, datagram)
      None => ()
    }
    match server.poll_datagram() {
      Some(datagram) => try! client.handle_datagram(now, datagram)
      None => ()
    }
    if client.state() == Connected && server.state() == Connected {
      return (client, server)
    }
  }
  abort("benchmark DTLS handshake did not complete")
}

///|
test "bench DTLS application-data crypto" (it : @bench.T) {
  let (client, server) = bench_dtls_pair()
  let now = try! @transport.Instant::from_milliseconds(1)
  let payload = Bytes::make(1024, 0x5a)
  it.bench(() => {
    try! client.send_application_data(payload)
    guard client.poll_datagram() is Some(datagram) else {
      abort("benchmark DTLS endpoint omitted its datagram")
    }
    try! server.handle_datagram(now, datagram)
    while server.poll_event() is Some(_) {

    }
  })
}

///|
test "bench SRTP protect and unprotect" (it : @bench.T) {
  let key = Bytes::make(16, 0x11)
  let salt = Bytes::make(12, 0x22)
  let sender = try! @srtp.Context::new(
    profile=AeadAes128Gcm,
    master_key=key,
    master_salt=salt,
  )
  let receiver = try! @srtp.Context::new(
    profile=AeadAes128Gcm,
    master_key=key,
    master_salt=salt,
  )
  let sequence = [0U]
  it.bench(() => {
    let packet = try! @rtp.Packet::new(
      payload_type=96,
      sequence_number=sequence[0].to_uint16(),
      timestamp=sequence[0] * 960U,
      ssrc=0x10203040U,
      payload=Bytes::make(1200, 0x33),
    )
    sequence[0] = sequence[0] + 1U
    let encrypted = try! sender.protect_rtp(packet)
    try! (receiver.unprotect_rtp(encrypted) |> ignore)
  })
}

///|
test "bench RTP and RTCP codecs" (it : @bench.T) {
  let rtp_packet = try! @rtp.Packet::new(
    marker=true,
    payload_type=111,
    sequence_number=42,
    timestamp=0x01020304U,
    ssrc=0x11223344U,
    extensions=[
      try! @rtp.HeaderExtension::new(id=1, payload=b"\x01\x02"),
      try! @rtp.HeaderExtension::new(id=3, payload=b"mid"),
    ],
    payload=Bytes::make(1200, 0x55),
  )
  let rtp_wire = try! rtp_packet.marshal()
  let report = try! @rtcp.SenderReportPacket::new(
    sender_ssrc=0x11223344U,
    ntp_timestamp=0x0102030405060708UL,
    rtp_timestamp=0x10203040U,
    packet_count=1234U,
    octet_count=567890U,
  )
  let rtcp_wire = try! @rtcp.encode_compound([report.to_packet()])
  it.bench(() => {
    let decoded_rtp = try! @rtp.Packet::unmarshal(rtp_wire)
    try! (decoded_rtp.marshal() |> ignore)
    let decoded_rtcp = try! @rtcp.decode_compound(rtcp_wire)
    try! (@rtcp.encode_compound(decoded_rtcp) |> ignore)
  })
}

///|
fn bench_sctp_pair() -> (@sctp.Association, @sctp.Association) {
  let active = try! @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Active,
      initial_tag=0x11111111U,
      initial_tsn=100U,
      max_payload_size=1100,
    ),
  )
  let passive = try! @sctp.Association::new(
    @sctp.AssociationConfig::new(
      role=Passive,
      initial_tag=0x22222222U,
      initial_tsn=500U,
      max_payload_size=1100,
    ),
  )
  let now = try! @transport.Instant::from_milliseconds(0)
  try! active.start(now)
  try! passive.start(now)
  for step = 0; step < 20; step = step + 1 {
    match active.poll_datagram() {
      Some(packet) => try! passive.handle_datagram(now, packet)
      None => ()
    }
    match passive.poll_datagram() {
      Some(packet) => try! active.handle_datagram(now, packet)
      None => ()
    }
    if active.state() == Established && passive.state() == Established {
      return (active, passive)
    }
  }
  abort("benchmark SCTP association did not establish")
}

///|
test "bench SCTP reliable throughput" (it : @bench.T) {
  let (active, passive) = bench_sctp_pair()
  let now = try! @transport.Instant::from_milliseconds(1)
  let message = @sctp.Message::new(
    stream=StreamId(1),
    protocol_id=53U,
    payload=Bytes::make(16384, 0x66),
  )
  it.bench(() => {
    try! active.send(message, now~)
    while active.poll_datagram() is Some(packet) {
      try! passive.handle_datagram(now, packet)
    }
    while passive.poll_datagram() is Some(packet) {
      try! active.handle_datagram(now, packet)
    }
    while passive.poll_event() is Some(_) {

    }
  })
}

///|
fn bench_swap_datagram(
  datagram : @rtc.OutboundDatagram,
  now : @rtc.Instant,
) -> @rtc.InboundDatagram {
  {
    now,
    context: {
      local_address: datagram.context.peer,
      peer: datagram.context.local_address,
      ecn: datagram.context.ecn,
      protocol: datagram.context.protocol,
    },
    payload: datagram.payload,
  }
}

///|
fn bench_pump_peers(
  offerer : @rtc.PeerConnection,
  answerer : @rtc.PeerConnection,
  now : @rtc.Instant,
) -> Unit raise @rtc.RtcError {
  for round = 0; round < 16384; round = round + 1 {
    let mut progressed = false
    match offerer.poll_datagram() {
      Some(datagram) => {
        answerer.handle_datagram(bench_swap_datagram(datagram, now))
        progressed = true
      }
      None => ()
    }
    match answerer.poll_datagram() {
      Some(datagram) => {
        offerer.handle_datagram(bench_swap_datagram(datagram, now))
        progressed = true
      }
      None => ()
    }
    if !progressed {
      return
    }
  }
  abort("benchmark PeerConnection pump did not quiesce")
}

///|
fn bench_peer_pair() -> (
  @rtc.PeerConnection,
  @rtc.PeerConnection,
  @sctp.StreamId,
) {
  let now = try! @rtc.Instant::from_milliseconds(0)
  let sample = @rtc.ClockSample::new(
    monotonic=now,
    wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let offerer = try! @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      try! @ice.IceCandidate::host(
        foundation="bench-offerer",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=58000,
        ),
      ),
    ]),
    sample,
  )
  let answerer = try! @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[
      try! @ice.IceCandidate::host(
        foundation="bench-answerer",
        @rtc.SocketAddress::new(
          address=@rtc.IpAddress::loopback_v4(),
          port=58001,
        ),
      ),
    ]),
    sample,
  )
  let channel = try! offerer.create_data_channel(
    @datachannel.DataChannelConfig::new(label="benchmark"),
    now,
  )
  let offer = try! offerer.create_offer(now)
  try! offerer.set_local_description(offer, now)
  try! answerer.set_remote_description(offer, now)
  let answer = try! answerer.create_answer(now)
  try! answerer.set_local_description(answer, now)
  try! offerer.set_remote_description(answer, now)
  try! bench_pump_peers(offerer, answerer, now)
  while offerer.poll_event() is Some(_) {

  }
  while answerer.poll_event() is Some(_) {

  }
  (offerer, answerer, channel.id())
}

///|
test "bench end-to-end PeerConnection DataChannel pipeline" (it : @bench.T) {
  let (offerer, answerer, channel) = bench_peer_pair()
  let now = try! @rtc.Instant::from_milliseconds(1)
  let message = @rtc.RtcMessage::DataChannel(
    channel_id=channel,
    message=Binary(Bytes::make(4096, 0x77)),
  )
  it.bench(() => {
    try! offerer.handle_message(message, now)
    try! bench_pump_peers(offerer, answerer, now)
    answerer.poll_message() |> ignore
    while offerer.poll_event() is Some(_) {

    }
    while answerer.poll_event() is Some(_) {

    }
  })
}
