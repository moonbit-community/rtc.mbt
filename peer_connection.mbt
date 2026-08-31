///|
fn[T] rtc_crypto(
  operation : () -> T raise @crypto.CryptoError,
) -> T raise RtcError {
  operation() catch {
    CryptoUnavailable(message) => raise CryptoUnavailable(message)
    InvalidLength(length) =>
      raise CryptoUnavailable("OpenSSL rejected length \{length}")
    OperationFailed(message) => raise CryptoUnavailable(message)
  }
}

///|
fn[T] rtc_sdp(operation : () -> T raise @sdp.SdpError) -> T raise RtcError {
  operation() catch {
    error => raise Sdp(error)
  }
}

///|
fn[T] rtc_ice(operation : () -> T raise @ice.IceError) -> T raise RtcError {
  operation() catch {
    error => raise Ice(error)
  }
}

///|
fn[T] rtc_mdns(operation : () -> T raise @mdns.MdnsError) -> T raise RtcError {
  operation() catch {
    error => raise Mdns(error)
  }
}

///|
fn[T] rtc_turn(operation : () -> T raise @turn.TurnError) -> T raise RtcError {
  operation() catch {
    error => raise Turn(error)
  }
}

///|
fn[T] rtc_dtls(operation : () -> T raise @dtls.DtlsError) -> T raise RtcError {
  operation() catch {
    error => raise Dtls(error)
  }
}

///|
fn[T] rtc_sctp(operation : () -> T raise @sctp.SctpError) -> T raise RtcError {
  operation() catch {
    error => raise Sctp(error)
  }
}

///|
fn[T] rtc_datachannel(
  operation : () -> T raise @datachannel.DataChannelError,
) -> T raise RtcError {
  operation() catch {
    error => raise DataChannel(error)
  }
}

///|
fn[T] rtc_srtp(operation : () -> T raise @srtp.SrtpError) -> T raise RtcError {
  operation() catch {
    error => raise Srtp(error)
  }
}

///|
fn[T] rtc_media(
  operation : () -> T raise @media.MediaError,
) -> T raise RtcError {
  operation() catch {
    _ => raise InvalidConfiguration("invalid media configuration")
  }
}

///|
fn[T] rtc_interceptor(
  operation : () -> T raise @interceptor.InterceptorError,
) -> T raise RtcError {
  operation() catch {
    error => raise Interceptor(error)
  }
}

///|
fn[T] rtc_rtcp(operation : () -> T raise @rtcp.RtcpError) -> T raise RtcError {
  operation() catch {
    _ => raise InvalidState("RTCP processing failed")
  }
}

///|
fn[T] rtc_rtp(operation : () -> T raise @rtp.RtpError) -> T raise RtcError {
  operation() catch {
    _ => raise InvalidState("RTP processing failed")
  }
}

///|
fn random_uint64(provider : @crypto.Provider) -> UInt64 raise RtcError {
  let bytes = rtc_crypto(() => provider.random_bytes(8))
  let result = (bytes[0].to_uint64() << 56) |
    (bytes[1].to_uint64() << 48) |
    (bytes[2].to_uint64() << 40) |
    (bytes[3].to_uint64() << 32) |
    (bytes[4].to_uint64() << 24) |
    (bytes[5].to_uint64() << 16) |
    (bytes[6].to_uint64() << 8) |
    bytes[7].to_uint64()
  if result == 0UL {
    1UL
  } else {
    result
  }
}

///|
fn random_ice_token(
  provider : @crypto.Provider,
  length : Int,
) -> String raise RtcError {
  let alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/"
  let bytes = rtc_crypto(() => provider.random_bytes(length))
  let characters : Array[Char] = []
  for byte in bytes {
    characters.push(
      alphabet[byte.to_int() % alphabet.length()].to_char().unwrap(),
    )
  }
  String::from_array(characters)
}

///|
fn generate_ice_credentials(
  provider : @crypto.Provider,
) -> @ice.IceCredentials raise RtcError {
  let username_fragment = random_ice_token(provider, 8)
  let password = random_ice_token(provider, 32)
  rtc_ice(() => @ice.IceCredentials::new(username_fragment~, password~))
}

///|
fn generate_mdns_name(provider : @crypto.Provider) -> String raise RtcError {
  let digits = "0123456789abcdef"
  let bytes = rtc_crypto(() => provider.random_bytes(16))
  let characters : Array[Char] = []
  for byte in bytes {
    characters.push(digits[(byte >> 4).to_int()].to_char().unwrap())
    characters.push(digits[(byte & 0x0f).to_int()].to_char().unwrap())
  }
  String::from_array(characters) + ".local"
}

///|
fn parse_ice_server_port(value : String) -> UInt16 raise RtcError {
  let parsed : UInt64 = @strconv.from_str(value) catch {
    _ => raise InvalidConfiguration("invalid ICE server port")
  }
  if parsed == 0UL || parsed > 65535UL {
    raise InvalidConfiguration("ICE server port is out of range")
  }
  parsed.to_uint16()
}

///|
fn parse_literal_ice_server(
  url : String,
  expected_scheme : String,
  default_port? : UInt16 = 3478,
) -> SocketAddress? raise RtcError {
  let prefix = expected_scheme + ":"
  guard url.to_lower().strip_prefix(prefix) is Some(remainder) else {
    return None
  }
  let remainder = match remainder.strip_prefix("//") {
    Some(value) => value
    None => remainder
  }
  let authority = remainder.split("?").next().unwrap().to_owned()
  let (host, port) = if authority.has_prefix("[") {
    guard authority.split_once("]:") is Some((host, port)) else {
      raise InvalidConfiguration("IPv6 ICE server URLs must use [address]:port")
    }
    guard host.strip_prefix("[") is Some(host) else {
      raise InvalidConfiguration("invalid bracketed ICE server address")
    }
    (host.to_owned(), parse_ice_server_port(port.to_owned()))
  } else {
    let parts = authority.split(":").to_array()
    match parts {
      [host] => (host.to_owned(), default_port)
      [host, port] => (host.to_owned(), parse_ice_server_port(port.to_owned()))
      _ =>
        raise InvalidConfiguration(
          "ICE server host must be a literal IP address",
        )
    }
  }
  let address = @transport.IpAddress::parse(host) catch {
    _ =>
      raise InvalidConfiguration(
        "ICE server DNS resolution is delegated to the application",
      )
  }
  Some(SocketAddress::new(address~, port~))
}

///|
priv struct ParsedTurnServer {
  address : SocketAddress
  transport : @turn.TurnTransport
}

///|
fn parse_literal_turn_server(url : String) -> ParsedTurnServer? raise RtcError {
  let lower = url.to_lower()
  let secure = lower.has_prefix("turns:")
  if !secure && !lower.has_prefix("turn:") {
    return None
  }
  let scheme = if secure { "turns" } else { "turn" }
  let mut transport : @turn.TurnTransport = if secure { Tls } else { Udp }
  let default_port : UInt16 = if secure { 5349 } else { 3478 }
  let query = match lower.split_once("?") {
    Some((_, query)) => query
    None => ""
  }
  if !query.is_empty() {
    for parameter in query.split("&") {
      guard parameter.split_once("=") is Some((key, value)) else {
        raise InvalidConfiguration("invalid TURN URL query parameter")
      }
      if key == "transport" {
        transport = match value {
          "udp" =>
            if scheme == "turns" {
              raise InvalidConfiguration(
                "turns: URLs cannot request UDP transport",
              )
            } else {
              Udp
            }
          "tcp" => if scheme == "turns" { Tls } else { Tcp }
          _ => raise InvalidConfiguration("unsupported TURN URL transport")
        }
      }
    }
  }
  guard parse_literal_ice_server(url, scheme, default_port~) is Some(address) else {
    return None
  }
  Some({ address, transport, })
}

///|
fn hex_character(value : Byte) -> String {
  let digits = "0123456789ABCDEF"
  String::from_array([digits[value.to_int()].to_char().unwrap()])
}

///|
fn fingerprint_text(value : Bytes) -> String {
  let mut result = ""
  for index = 0; index < value.length(); index = index + 1 {
    if index > 0 {
      result = result + ":"
    }
    let byte = value[index]
    result = result + hex_character(byte >> 4) + hex_character(byte & 0x0f)
  }
  result
}

///|
fn hex_nibble(value : UInt16) -> Byte raise RtcError {
  if value >= '0' && value <= '9' {
    (value - '0').to_byte()
  } else if value >= 'a' && value <= 'f' {
    (value - 'a' + 10).to_byte()
  } else if value >= 'A' && value <= 'F' {
    (value - 'A' + 10).to_byte()
  } else {
    raise InvalidConfiguration("invalid DTLS fingerprint hex digit")
  }
}

///|
fn dtls_fingerprint(
  value : @sdp.DtlsFingerprint,
) -> @dtls.Fingerprint raise RtcError {
  let algorithm = match value.algorithm() {
    "sha-256" => @dtls.Sha256
    "sha-384" => Sha384
    "sha-512" => Sha512
    _ => raise InvalidConfiguration("unsupported DTLS fingerprint algorithm")
  }
  let text = value.value()
  let bytes : Array[Byte] = []
  let mut index = 0
  while index < text.length() {
    bytes.push((hex_nibble(text[index]) << 4) | hex_nibble(text[index + 1]))
    index += 3
  }
  rtc_dtls(() => {
    @dtls.Fingerprint::new(algorithm~, value=Bytes::from_array(bytes))
  })
}

///|
fn sdp_fingerprint(
  identity : @dtls.CertificateIdentity,
) -> @sdp.DtlsFingerprint raise RtcError {
  let fingerprint = rtc_dtls(() => identity.fingerprint(algorithm=Sha256))
  rtc_sdp(() => {
    @sdp.DtlsFingerprint::new(
      algorithm="sha-256",
      value=fingerprint_text(fingerprint.value()),
    )
  })
}

///|
fn minimum_instant(
  current : @transport.Instant?,
  candidate : @transport.Instant?,
) -> @transport.Instant? {
  match (current, candidate) {
    (None, value) => value
    (value, None) => value
    (Some(left), Some(right)) => Some(if left < right { left } else { right })
  }
}

///|
struct PendingRelayDatagram {
  datagram : OutboundDatagram
}

///|
enum RtcStreamOwner {
  IceStream
  TurnStream(Int)
} derive(Debug, Eq)

///|
struct PendingRtcStream {
  connection : ConnectionId
  owner : RtcStreamOwner
  logical_context : TransportContext
  writes : @queue.Queue[Bytes]
}

///|
struct ActiveRtcStream {
  connection : ConnectionId
  owner : RtcStreamOwner
  logical_context : TransportContext
  writes : @queue.Queue[Bytes]
  mut input : Bytes
}

///|
struct ActiveRtcListener {
  listener : ListenerId
  local_address : SocketAddress
}

///|
priv struct LocalMediaControl {
  ssrc : UInt
  rtx_ssrc : UInt?
  sender_report : @interceptor.SenderReportGenerator
  rtx_sender : @interceptor.RtxSender?
}

///|
priv struct RemoteMediaControl {
  ssrc : UInt
  rtx_ssrc : UInt?
  receiver_report : @interceptor.ReceiverReportGenerator
  nack_generator : @interceptor.NackGenerator
  rtx_receiver : @interceptor.RtxReceiver?
}

///|
struct LocalMediaSection {
  transceiver : RtpTransceiver
  remote_created : Bool
  mut mid : String?
  mut track : MediaTrack?
  mut codec : @media.CodecCapability
  mut payload_type : Byte
  mut ssrc : UInt?
  mut rtx_payload_type : Byte?
  mut rtx_ssrc : UInt?
  mut encodings : Array[@media.RtpEncodingParameters]
  mut twcc_extension_id : Byte?
  mut control : LocalMediaControl?
  additional_controls : Array[LocalMediaControl]
}

///|
struct RemoteMediaSection {
  mid : String
  mut track : MediaTrack?
  mut payload_type : Byte
  mut rtx_payload_type : Byte?
  mut encodings : Array[@media.RtpEncodingParameters]
  mut twcc_extension_id : Byte?
  mut control : RemoteMediaControl?
  additional_controls : Array[RemoteMediaControl]
}

///|
pub struct PeerConnection {
  configuration : Configuration
  clock_sample : ClockSample
  signaling : @sdp.SignalingStateMachine
  identity : @dtls.CertificateIdentity
  mut local_credentials : @ice.IceCredentials
  session_id : UInt64
  mut session_version : UInt64
  tie_breaker : UInt64
  events : @queue.Queue[PeerEvent]
  messages : @queue.Queue[RtcMessage]
  outbound : @queue.Queue[OutboundDatagram]
  io_actions : @queue.Queue[IoAction]
  pending_streams : Array[PendingRtcStream]
  active_streams : Array[ActiveRtcStream]
  active_listeners : Array[ActiveRtcListener]
  mut next_connection_id : UInt64
  mut next_listener_id : UInt64
  local_transport_candidates : Array[IceCandidate]
  local_advertised_candidates : Array[IceCandidate]
  srflx_gatherers : Array[@ice.SrflxGatherer]
  turn_allocations : Array[@turn.Allocation]
  pending_relay_datagrams : Array[PendingRelayDatagram]
  remote_candidates : Array[IceCandidate]
  mdns_resolver : @mdns.Resolver
  pending_mdns_candidates : Map[@mdns.QueryId, IceCandidate]
  mut state : PeerConnectionState
  mut gathering_state : @ice.IceGatheringState
  mut data_manager : @datachannel.Manager?
  mut ice_agent : @ice.IceAgent?
  mut dtls_endpoint : @dtls.Endpoint?
  mut data_transport : @datachannel.Transport?
  local_media_sections : Array[LocalMediaSection]
  remote_media_sections : Array[RemoteMediaSection]
  mut outbound_srtp : @srtp.Context?
  mut inbound_srtp : @srtp.Context?
  mut media_started : Bool
  rtcp_sender_ssrc : UInt
  mut next_rtcp_report : Instant?
  mut next_transport_sequence : UInt16
  mut remote_twcc_recorder : @interceptor.TwccRecorder?
  data_channel_buffered_amount_low_thresholds : Map[@sctp.StreamId, UInt64]
  mut transport_started : Bool
  mut ice_restart_pending : Bool
  mut dtls_started : Bool
  mut data_started : Bool
  mut closing : Bool
  mut bytes_sent : UInt64
  mut bytes_received : UInt64
  mut packets_sent : UInt64
  mut packets_received : UInt64
  mut data_channels_opened : UInt
  mut data_channels_closed : UInt
}

///|
pub fn PeerConnection::new(
  configuration : Configuration,
  clock_sample : ClockSample,
) -> PeerConnection raise RtcError {
  let provider = rtc_crypto(() => @crypto.Provider::open())
  let local_credentials = match configuration.settings.ice_credentials {
    Some(credentials) => credentials
    None => generate_ice_credentials(provider)
  }
  let mdns_resolver = rtc_mdns(() => {
    @mdns.Resolver::new(
      mode=configuration.mdns_mode,
      retry_interval=configuration.settings.mdns_retry_interval,
      query_timeout=configuration.settings.mdns_query_timeout,
    )
  })
  let local_transport_candidates : Array[IceCandidate] = []
  let local_advertised_candidates : Array[IceCandidate] = []
  if configuration.ice_transport_policy == All {
    for candidate in configuration.host_candidates {
      local_transport_candidates.push(candidate)
    }
    match configuration.mdns_mode {
      QueryOnly =>
        for candidate in configuration.host_candidates {
          local_advertised_candidates.push(candidate)
        }
      QueryAndGather => {
        let name = configuration.settings.mdns_local_name.unwrap_or(
          generate_mdns_name(provider),
        )
        let addresses : Array[IpAddress] = []
        for candidate in configuration.host_candidates {
          if candidate.protocol() == Tcp {
            local_advertised_candidates.push(candidate)
            continue
          }
          let address = candidate.socket_address().unwrap().address()
          if !addresses.contains(address) {
            addresses.push(address)
          }
          local_advertised_candidates.push(
            rtc_ice(() => candidate.with_mdns_name(name)),
          )
        }
        if !addresses.is_empty() {
          rtc_mdns(() => mdns_resolver.register(name, addresses))
        }
      }
    }
  }
  let srflx_gatherers : Array[@ice.SrflxGatherer] = []
  let turn_allocations : Array[@turn.Allocation] = []
  for server_config in configuration.ice_servers {
    for url in server_config.urls {
      if configuration.ice_transport_policy == All {
        match parse_literal_ice_server(url, "stun") {
          Some(server) =>
            for local_candidate in configuration.host_candidates {
              if local_candidate.protocol() != Udp {
                continue
              }
              srflx_gatherers.push(
                rtc_ice(() => @ice.SrflxGatherer::new(local_candidate~, server~)),
              )
            }
          None => ()
        }
      }
      match parse_literal_turn_server(url) {
        Some(parsed_server) => {
          let server = parsed_server.address
          guard server_config.username is Some(username) &&
            server_config.credential is Some(password) else {
            raise InvalidConfiguration(
              "TURN URLs require a username and credential",
            )
          }
          let credentials = rtc_turn(() => {
            @turn.TurnCredentials::new(username~, password~)
          })
          let local_addresses : Array[SocketAddress] = []
          for local_address_candidate in configuration.host_candidates {
            guard local_address_candidate.socket_address()
              is Some(candidate_address) else {
              continue
            }
            let local_address = if parsed_server.transport == Udp {
              if local_address_candidate.protocol() != Udp {
                continue
              }
              candidate_address
            } else {
              SocketAddress::new(address=candidate_address.address(), port=0)
            }
            if local_addresses.contains(local_address) {
              continue
            }
            local_addresses.push(local_address)
            turn_allocations.push(
              rtc_turn(() => {
                @turn.Allocation::new(
                  local_address~,
                  server~,
                  credentials~,
                  transport=parsed_server.transport,
                )
              }),
            )
          }
        }
        None => ()
      }
    }
  }
  if configuration.ice_transport_policy == Relay && turn_allocations.is_empty() {
    raise InvalidConfiguration(
      "relay-only ICE policy requires a literal TURN server",
    )
  }
  let wall_nanoseconds = clock_sample.wall().as_unix_nanoseconds()
  let minute = 60000000000L
  let year = 31536000000000000L
  let not_before = WallTime::from_unix_nanoseconds(
    if wall_nanoseconds > -9223371976854775808L {
      wall_nanoseconds - minute
    } else {
      wall_nanoseconds
    },
  )
  let not_after = WallTime::from_unix_nanoseconds(
    if wall_nanoseconds < 9191836036854775807L {
      wall_nanoseconds + year
    } else {
      9223372036854775807L
    },
  )
  let identity = rtc_dtls(() => {
    @dtls.CertificateIdentity::generate(
      not_before~,
      not_after~,
      key_type=configuration.settings.dtls_certificate_key_type,
    )
  })
  let rtcp_sender_ssrc = {
    let value = (random_uint64(provider) & 0xffffffffUL).to_uint()
    if value == 0U {
      1U
    } else {
      value
    }
  }
  {
    configuration,
    clock_sample,
    signaling: @sdp.SignalingStateMachine::new(),
    identity,
    local_credentials,
    session_id: random_uint64(provider),
    session_version: 1UL,
    tie_breaker: random_uint64(provider),
    events: Queue([]),
    messages: Queue([]),
    outbound: Queue([]),
    io_actions: Queue([]),
    pending_streams: [],
    active_streams: [],
    active_listeners: [],
    next_connection_id: 1UL,
    next_listener_id: 1UL,
    local_transport_candidates,
    local_advertised_candidates,
    srflx_gatherers,
    turn_allocations,
    pending_relay_datagrams: [],
    remote_candidates: [],
    mdns_resolver,
    pending_mdns_candidates: Map([]),
    state: New,
    gathering_state: New,
    data_manager: None,
    ice_agent: None,
    dtls_endpoint: None,
    data_transport: None,
    local_media_sections: [],
    remote_media_sections: [],
    outbound_srtp: None,
    inbound_srtp: None,
    media_started: false,
    rtcp_sender_ssrc,
    next_rtcp_report: None,
    next_transport_sequence: 0,
    remote_twcc_recorder: None,
    data_channel_buffered_amount_low_thresholds: Map([]),
    transport_started: false,
    ice_restart_pending: false,
    dtls_started: false,
    data_started: false,
    closing: false,
    bytes_sent: 0UL,
    bytes_received: 0UL,
    packets_sent: 0UL,
    packets_received: 0UL,
    data_channels_opened: 0U,
    data_channels_closed: 0U,
  }
}

///|
fn PeerConnection::enqueue_event(
  self : PeerConnection,
  event : PeerEvent,
) -> Unit raise RtcError {
  if self.events.length() >= self.configuration.event_capacity {
    if self.closing {
      ignore(self.events.pop())
    } else {
      self.state = Failed
      raise BackpressureExceeded
    }
  }
  self.events.push(event)
}

///|
fn PeerConnection::enqueue_message(
  self : PeerConnection,
  message : RtcMessage,
) -> Unit raise RtcError {
  if self.closing {
    return
  }
  if self.messages.length() >= self.configuration.message_capacity {
    self.state = Failed
    raise BackpressureExceeded
  }
  self.messages.push(message)
}

///|
fn PeerConnection::set_state(
  self : PeerConnection,
  state : PeerConnectionState,
) -> Unit raise RtcError {
  if self.state != state {
    self.state = state
    self.enqueue_event(ConnectionStateChanged(state))
  }
}

///|
fn PeerConnection::set_gathering_state(
  self : PeerConnection,
  state : @ice.IceGatheringState,
) -> Unit raise RtcError {
  if self.gathering_state != state {
    self.gathering_state = state
    self.enqueue_event(IceGatheringStateChanged(state))
  }
}

///|
fn PeerConnection::gather_candidates(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.gathering_state != New {
    return
  }
  self.set_gathering_state(Gathering)
  self.ensure_tcp_listeners()
  for candidate in self.local_advertised_candidates {
    self.enqueue_event(IceCandidateDiscovered(candidate))
  }
  for gatherer in self.srflx_gatherers {
    rtc_ice(() => gatherer.start(now))
  }
  for index = 0; index < self.turn_allocations.length(); index = index + 1 {
    let allocation = self.turn_allocations[index]
    rtc_turn(() => allocation.start(now))
    if allocation.transport() != Udp {
      let context : TransportContext = {
        local_address: allocation.local_address(),
        peer: allocation.server(),
        ecn: None,
        protocol: Tcp,
      }
      ignore(
        self.ensure_stream_connection(
          TurnStream(index),
          context,
          allocation.transport() == Tls,
        ),
      )
    }
  }
  if self.srflx_gatherers.is_empty() && self.turn_allocations.is_empty() {
    self.set_gathering_state(Complete)
  }
}

///|
fn media_kind_name(kind : MediaKind) -> String {
  match kind {
    Audio => "audio"
    Video => "video"
  }
}

///|
fn media_kind_from_name(kind : String) -> MediaKind raise RtcError {
  match kind {
    "audio" => Audio
    "video" => Video
    _ => raise InvalidConfiguration("unsupported RTP media kind")
  }
}

///|
fn transceiver_to_sdp_direction(
  direction : TransceiverDirection,
) -> @sdp.MediaDirection {
  match direction {
    SendRecv => SendRecv
    SendOnly => SendOnly
    RecvOnly => RecvOnly
    Inactive | Stopped => Inactive
  }
}

///|
fn direction_can_send(direction : TransceiverDirection) -> Bool {
  direction == SendRecv || direction == SendOnly
}

///|
fn direction_can_receive(direction : TransceiverDirection) -> Bool {
  direction == SendRecv || direction == RecvOnly
}

///|
fn sdp_direction_can_send(direction : @sdp.MediaDirection) -> Bool {
  direction == SendRecv || direction == SendOnly
}

///|
fn sdp_direction_can_receive(direction : @sdp.MediaDirection) -> Bool {
  direction == SendRecv || direction == RecvOnly
}

///|
fn answer_media_direction(
  local_direction : TransceiverDirection,
  remote : @sdp.MediaDirection,
) -> @sdp.MediaDirection {
  let sends = direction_can_send(local_direction) &&
    sdp_direction_can_receive(remote)
  let receives = direction_can_receive(local_direction) &&
    sdp_direction_can_send(remote)
  match (sends, receives) {
    (true, true) => SendRecv
    (true, false) => SendOnly
    (false, true) => RecvOnly
    (false, false) => Inactive
  }
}

///|
fn media_codec_to_sdp(
  codec : @media.CodecCapability,
  payload_type : Byte,
) -> @sdp.RtpCodecParameters raise RtcError {
  rtc_sdp(() => {
    @sdp.RtpCodecParameters::new(
      payload_type~,
      encoding_name=codec.encoding_name(),
      clock_rate=codec.clock_rate(),
      channels=codec.channels(),
      fmtp=codec.fmtp(),
      rtcp_feedback=codec.rtcp_feedback(),
    )
  })
}

///|
fn media_codec_from_sdp(
  kind : MediaKind,
  codec : @sdp.RtpCodecParameters,
) -> @media.CodecCapability raise RtcError {
  rtc_media(() => {
    @media.CodecCapability::new(
      mime_type=media_kind_name(kind) + "/" + codec.encoding_name(),
      clock_rate=codec.clock_rate(),
      channels=codec.channels(),
      fmtp=codec.fmtp(),
      rtcp_feedback=codec.rtcp_feedback(),
    )
  })
}

///|
fn codecs_compatible(
  local_codec : @media.CodecCapability,
  remote : @sdp.RtpCodecParameters,
) -> Bool {
  local_codec.encoding_name().to_lower() == remote.encoding_name().to_lower() &&
  local_codec.clock_rate() == remote.clock_rate() &&
  local_codec.channels() == remote.channels()
}

///|
fn default_media_codec(
  kind : MediaKind,
) -> @media.CodecCapability raise RtcError {
  rtc_media(() => {
    match kind {
      Audio =>
        @media.CodecCapability::new(
          mime_type="audio/opus",
          clock_rate=48000U,
          channels=2,
          fmtp="minptime=10;useinbandfec=1",
          rtcp_feedback=["transport-cc"],
        )
      Video =>
        @media.CodecCapability::new(mime_type="video/vp8", clock_rate=90000U, rtcp_feedback=[
          "nack", "nack pli", "goog-remb", "transport-cc",
        ])
    }
  })
}

///|
fn preferred_payload_type(
  codec : @media.CodecCapability,
  fallback : Byte,
) -> Byte {
  match codec.mime_type().to_lower() {
    "audio/pcmu" => 0
    "audio/pcma" => 8
    "audio/opus" => 111
    "video/av1" | "video/av1x" => 45
    "video/vp8" => 96
    "video/vp9" => 98
    "video/h264" => 102
    "video/h265" => 104
    _ => fallback
  }
}

///|
fn codec_uses_rtx(kind : MediaKind) -> Bool {
  kind == Video
}

///|
const TRANSPORT_CC_EXTENSION_URI : String = "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01"

///|
fn codec_uses_twcc(codec : @media.CodecCapability) -> Bool {
  codec.rtcp_feedback().contains("transport-cc")
}

///|
fn transport_cc_extension(
  id : Byte,
) -> @sdp.RtpHeaderExtensionParameters raise RtcError {
  rtc_sdp(() => {
    @sdp.RtpHeaderExtensionParameters::new(id~, uri=TRANSPORT_CC_EXTENSION_URI)
  })
}

///|
fn negotiated_transport_cc_id(
  extensions : Array[@sdp.RtpHeaderExtensionParameters],
) -> Byte? {
  for extension in extensions {
    if extension.uri() == TRANSPORT_CC_EXTENSION_URI {
      return Some(extension.id())
    }
  }
  None
}

///|
fn media_rtp_parameters(
  codec : @media.CodecCapability,
  payload_type : Byte,
  ssrc : UInt?,
  rtx_payload_type : Byte?,
  rtx_ssrc : UInt?,
) -> @media.RtpParameters raise RtcError {
  rtc_media(() => {
    @media.RtpParameters::new(codec~, encodings=[
      @media.RtpEncodingParameters::new(
        ssrc?,
        payload_type~,
        rtx_ssrc?,
        rtx_payload_type?,
      ),
    ])
  })
}

///|
fn sdp_stream_parameters(
  encodings : Array[@media.RtpEncodingParameters],
  include_rtx : Bool,
  include_ssrc? : Bool = true,
) -> Array[@sdp.RtpStreamParameters] raise RtcError {
  let streams : Array[@sdp.RtpStreamParameters] = []
  for encoding in encodings {
    if encoding.ssrc is None && encoding.rid is None {
      continue
    }
    let ssrc = if include_ssrc { encoding.ssrc } else { None }
    let rtx_ssrc = if include_ssrc && include_rtx {
      encoding.rtx_ssrc
    } else {
      None
    }
    let rid = encoding.rid
    streams.push(
      rtc_sdp(() => {
        @sdp.RtpStreamParameters::new(
          ssrc?,
          rtx_ssrc?,
          rid?,
          paused=!encoding.active,
        )
      }),
    )
  }
  streams
}

///|
fn negotiated_media_encodings(
  encodings : Array[@media.RtpEncodingParameters],
  payload_type : Byte,
  rtx_payload_type : Byte?,
) -> Array[@media.RtpEncodingParameters] raise RtcError {
  let negotiated : Array[@media.RtpEncodingParameters] = []
  for encoding in encodings {
    let ssrc = encoding.ssrc
    let rtx_ssrc = if rtx_payload_type is Some(_) {
      encoding.rtx_ssrc
    } else {
      None
    }
    let rid = encoding.rid
    let max_bitrate = encoding.max_bitrate
    let scale_resolution_down_by = encoding.scale_resolution_down_by
    let scalability_mode = encoding.scalability_mode
    negotiated.push(
      rtc_media(() => {
        @media.RtpEncodingParameters::new(
          ssrc?,
          payload_type~,
          rtx_ssrc?,
          rtx_payload_type?,
          rid?,
          active=encoding.active,
          max_bitrate?,
          scale_resolution_down_by?,
          scalability_mode?,
        )
      }),
    )
  }
  negotiated
}

///|
fn accepted_media_encodings(
  encodings : Array[@media.RtpEncodingParameters],
  answer_streams : Array[@sdp.RtpStreamParameters],
) -> Array[@media.RtpEncodingParameters] raise RtcError {
  let accepted : Array[@sdp.RtpStreamParameters] = []
  for stream in answer_streams {
    if stream.rid_direction == RidRecv && stream.rid is Some(_) {
      accepted.push(stream)
    }
  }
  if accepted.is_empty() {
    return encodings
  }
  let result : Array[@media.RtpEncodingParameters] = []
  for encoding in encodings {
    let mut enabled = encoding.active
    match encoding.rid {
      Some(rid) => {
        let mut matched : @sdp.RtpStreamParameters? = None
        for stream in accepted {
          if stream.rid == Some(rid) {
            matched = Some(stream)
            break
          }
        }
        enabled = match matched {
          Some(stream) => enabled && !stream.paused
          None => false
        }
      }
      None => ()
    }
    let ssrc = encoding.ssrc
    let payload_type = encoding.payload_type
    let rtx_ssrc = encoding.rtx_ssrc
    let rtx_payload_type = encoding.rtx_payload_type
    let rid = encoding.rid
    let max_bitrate = encoding.max_bitrate
    let scale_resolution_down_by = encoding.scale_resolution_down_by
    let scalability_mode = encoding.scalability_mode
    result.push(
      rtc_media(() => {
        @media.RtpEncodingParameters::new(
          ssrc?,
          payload_type?,
          rtx_ssrc?,
          rtx_payload_type?,
          rid?,
          active=enabled,
          max_bitrate?,
          scale_resolution_down_by?,
          scalability_mode?,
        )
      }),
    )
  }
  result
}

///|
fn rtx_codec_for(
  primary : @sdp.RtpCodecParameters,
  payload_type : Byte,
) -> @sdp.RtpCodecParameters raise RtcError {
  rtc_sdp(() => {
    @sdp.RtpCodecParameters::new(
      payload_type~,
      encoding_name="rtx",
      clock_rate=primary.clock_rate(),
      fmtp="apt=" + primary.payload_type().to_uint().to_string(),
    )
  })
}

///|
fn rtx_codec_matching(
  codecs : Array[@sdp.RtpCodecParameters],
  primary_payload_type : Byte,
) -> @sdp.RtpCodecParameters? {
  let expected = primary_payload_type.to_uint().to_string()
  for codec in codecs {
    if codec.encoding_name().to_lower() != "rtx" {
      continue
    }
    for parameter in codec.fmtp().split(";") {
      match parameter.trim().split_once("=") {
        Some((key, value)) if key.trim() == "apt" && value.trim() == expected =>
          return Some(codec)
        _ => ()
      }
    }
  }
  None
}

///|
fn PeerConnection::unused_payload_type(
  self : PeerConnection,
  preferred : Byte,
) -> Byte raise RtcError {
  if !self.local_media_sections.any(section => {
      section.payload_type == preferred ||
      section.rtx_payload_type == Some(preferred)
    }) {
    return preferred
  }
  for candidate = 96; candidate <= 127; candidate = candidate + 1 {
    let payload_type = candidate.to_byte()
    if !self.local_media_sections.any(section => {
        section.payload_type == payload_type ||
        section.rtx_payload_type == Some(payload_type)
      }) {
      return payload_type
    }
  }
  raise InvalidConfiguration("no dynamic RTP payload type remains")
}

///|
fn PeerConnection::unused_rtx_payload_type(
  self : PeerConnection,
  primary : Byte,
) -> Byte raise RtcError {
  for candidate = 97; candidate <= 127; candidate = candidate + 1 {
    let payload_type = candidate.to_byte()
    if payload_type != primary &&
      !self.local_media_sections.any(section => {
        section.payload_type == payload_type ||
        section.rtx_payload_type == Some(payload_type)
      }) {
      return payload_type
    }
  }
  raise InvalidConfiguration("no dynamic RTX payload type remains")
}

///|
fn PeerConnection::generate_media_ssrc(
  self : PeerConnection,
) -> UInt raise RtcError {
  let provider = rtc_crypto(() => @crypto.Provider::open())
  for attempt = 0; attempt < 64; attempt = attempt + 1 {
    let candidate = (random_uint64(provider) & 0xffffffffUL).to_uint()
    if candidate != 0U &&
      !self.local_media_sections.any(section => {
        section.encodings.any(encoding => {
          encoding.ssrc == Some(candidate) ||
          encoding.rtx_ssrc == Some(candidate)
        })
      }) {
      return candidate
    }
  }
  raise CryptoUnavailable("failed to generate a unique RTP SSRC")
}

///|
fn PeerConnection::new_local_media_control(
  _self : PeerConnection,
  ssrc : UInt,
  rtx_ssrc : UInt?,
  rtx_payload_type : Byte?,
) -> LocalMediaControl raise RtcError {
  let rtx_sender = match (rtx_ssrc, rtx_payload_type) {
    (Some(rtx_source), Some(rtx_pt)) =>
      Some(
        rtc_interceptor(() => {
          @interceptor.RtxSender::new(
            media_ssrc=ssrc,
            rtx_ssrc=rtx_source,
            rtx_payload_type=rtx_pt,
          )
        }),
      )
    _ => None
  }
  {
    ssrc,
    rtx_ssrc,
    sender_report: @interceptor.SenderReportGenerator::new(ssrc),
    rtx_sender,
  }
}

///|
fn PeerConnection::new_remote_media_control(
  self : PeerConnection,
  ssrc : UInt,
  payload_type : Byte,
  rtx_ssrc : UInt?,
  rtx_payload_type : Byte?,
  clock_rate : UInt,
) -> RemoteMediaControl raise RtcError {
  let rtx_receiver = match (rtx_ssrc, rtx_payload_type) {
    (Some(rtx_source), Some(rtx_pt)) =>
      Some(
        rtc_interceptor(() => {
          @interceptor.RtxReceiver::new(
            media_ssrc=ssrc,
            media_payload_type=payload_type,
            rtx_ssrc=rtx_source,
            rtx_payload_type=rtx_pt,
          )
        }),
      )
    _ => None
  }
  {
    ssrc,
    rtx_ssrc,
    receiver_report: rtc_interceptor(() => {
      @interceptor.ReceiverReportGenerator::new(
        sender_ssrc=self.rtcp_sender_ssrc,
        media_ssrc=ssrc,
        clock_rate~,
      )
    }),
    nack_generator: rtc_interceptor(() => {
      @interceptor.NackGenerator::new(
        sender_ssrc=self.rtcp_sender_ssrc,
        media_ssrc=ssrc,
      )
    }),
    rtx_receiver,
  }
}

///|
fn local_control_for_ssrc(
  section : LocalMediaSection,
  ssrc : UInt,
) -> LocalMediaControl? {
  match section.control {
    Some(control) if control.ssrc == ssrc || control.rtx_ssrc == Some(ssrc) =>
      return Some(control)
    _ => ()
  }
  for control in section.additional_controls {
    if control.ssrc == ssrc || control.rtx_ssrc == Some(ssrc) {
      return Some(control)
    }
  }
  None
}

///|
fn remote_control_for_ssrc(
  section : RemoteMediaSection,
  ssrc : UInt,
) -> RemoteMediaControl? {
  match section.control {
    Some(control) if control.ssrc == ssrc || control.rtx_ssrc == Some(ssrc) =>
      return Some(control)
    _ => ()
  }
  for control in section.additional_controls {
    if control.ssrc == ssrc || control.rtx_ssrc == Some(ssrc) {
      return Some(control)
    }
  }
  None
}

///|
fn PeerConnection::configure_local_media_controls(
  self : PeerConnection,
  section : LocalMediaSection,
) -> Unit raise RtcError {
  section.control = None
  section.additional_controls.clear()
  for encoding in section.encodings {
    guard encoding.ssrc is Some(ssrc) else { continue }
    let control = self.new_local_media_control(
      ssrc,
      encoding.rtx_ssrc,
      encoding.rtx_payload_type,
    )
    match section.control {
      None => section.control = Some(control)
      Some(_) => section.additional_controls.push(control)
    }
  }
}

///|
fn set_sender_parameters(
  transceiver : RtpTransceiver,
  codec : @media.CodecCapability,
  encodings : Array[@media.RtpEncodingParameters],
) -> Unit raise RtcError {
  transceiver
  .sender()
  .set_parameters(
    Some(rtc_media(() => @media.RtpParameters::new(codec~, encodings~))),
  )
}

///|
fn PeerConnection::assign_offer_mids(
  self : PeerConnection,
) -> Unit raise RtcError {
  let used : Array[String] = ["0"]
  for section in self.local_media_sections {
    match section.mid {
      Some(mid) => {
        if used.contains(mid) {
          raise InvalidConfiguration("duplicate RTP transceiver MID")
        }
        used.push(mid)
      }
      None => ()
    }
  }
  let mut candidate = 1
  for section in self.local_media_sections {
    if section.mid is Some(_) {
      continue
    }
    while used.contains(candidate.to_string()) {
      candidate += 1
    }
    let mid = candidate.to_string()
    rtc_media(() => section.transceiver.assign_mid(mid))
    section.mid = Some(mid)
    used.push(mid)
    candidate += 1
  }
}

///|
fn PeerConnection::local_sdp_media_sections(
  self : PeerConnection,
  sdp_type : SdpType,
) -> Array[@sdp.RtpMediaParameters] raise RtcError {
  let result : Array[@sdp.RtpMediaParameters] = []
  match sdp_type {
    Offer => {
      self.assign_offer_mids()
      for section in self.local_media_sections {
        guard section.mid is Some(mid) else {
          raise InvalidState("RTP transceiver has no MID")
        }
        let direction = transceiver_to_sdp_direction(
          section.transceiver.direction(),
        )
        let (stream_id, track_id) = match section.track {
          Some(track) => (Some(track.stream_id()), Some(track.id()))
          None => (None, None)
        }
        let codec = media_codec_to_sdp(section.codec, section.payload_type)
        let codecs : Array[@sdp.RtpCodecParameters] = [codec]
        match section.rtx_payload_type {
          Some(rtx_payload_type) =>
            codecs.push(rtx_codec_for(codec, rtx_payload_type))
          None => ()
        }
        let header_extensions : Array[@sdp.RtpHeaderExtensionParameters] = []
        match section.twcc_extension_id {
          Some(id) => header_extensions.push(transport_cc_extension(id))
          None => ()
        }
        let include_simulcast_ssrc = section.encodings.length() <= 1 ||
          self.configuration.settings.write_ssrc_attributes_for_simulcast
        let ssrc = if include_simulcast_ssrc { section.ssrc } else { None }
        let rtx_ssrc = if include_simulcast_ssrc {
          section.rtx_ssrc
        } else {
          None
        }
        let streams = sdp_stream_parameters(
          section.encodings,
          section.rtx_payload_type is Some(_),
          include_ssrc=include_simulcast_ssrc,
        )
        let cname : String? = match ssrc {
          Some(_) => Some("rtc.mbt")
          None => None
        }
        result.push(
          rtc_sdp(() => {
            @sdp.RtpMediaParameters::new(
              kind=media_kind_name(section.transceiver.kind()),
              mid~,
              direction~,
              codecs~,
              header_extensions~,
              stream_id?,
              track_id?,
              ssrc?,
              rtx_ssrc?,
              streams~,
              cname?,
            )
          }),
        )
      }
    }
    Answer | Pranswer => {
      guard self.signaling.remote_description() is Some(remote_description) else {
        raise InvalidState("RTP answer requires a remote offer")
      }
      let remote_sections = rtc_sdp(() => {
        remote_description.rtp_media_parameters()
      })
      for remote in remote_sections {
        let mut local_section : LocalMediaSection? = None
        for candidate in self.local_media_sections {
          if candidate.mid == Some(remote.mid()) {
            local_section = Some(candidate)
            break
          }
        }
        guard local_section is Some(section) else {
          raise InvalidState("remote RTP media section has no transceiver")
        }
        let mut selected_codec : @sdp.RtpCodecParameters? = None
        for remote_codec in remote.codecs() {
          if codecs_compatible(section.codec, remote_codec) {
            selected_codec = Some(remote_codec)
            break
          }
        }
        guard selected_codec is Some(codec) else {
          raise InvalidConfiguration("RTP offer has no supported codec")
        }
        let offered_rtx = rtx_codec_matching(
          remote.codecs(),
          codec.payload_type(),
        )
        let selected_rtx_payload_type = match offered_rtx {
          Some(rtx) => Some(rtx.payload_type())
          None => None
        }
        let negotiated_codec = media_codec_from_sdp(
          section.transceiver.kind(),
          codec,
        )
        section.codec = negotiated_codec
        section.payload_type = codec.payload_type()
        section.rtx_payload_type = selected_rtx_payload_type
        let selected_twcc_extension_id = if codec_uses_twcc(section.codec) {
          negotiated_transport_cc_id(remote.header_extensions())
        } else {
          None
        }
        section.twcc_extension_id = selected_twcc_extension_id
        section.encodings = negotiated_media_encodings(
          section.encodings,
          codec.payload_type(),
          selected_rtx_payload_type,
        )
        self.configure_local_media_controls(section)
        set_sender_parameters(
          section.transceiver,
          negotiated_codec,
          section.encodings,
        )
        let direction = answer_media_direction(
          section.transceiver.direction(),
          remote.direction(),
        )
        let current_direction : TransceiverDirection = match direction {
          SendRecv => SendRecv
          SendOnly => SendOnly
          RecvOnly => RecvOnly
          Inactive => Inactive
        }
        section.transceiver.set_current_direction(current_direction)
        let (stream_id, track_id) = match section.track {
          Some(track) => (Some(track.stream_id()), Some(track.id()))
          None => (None, None)
        }
        let include_simulcast_ssrc = section.encodings.length() <= 1 ||
          self.configuration.settings.write_ssrc_attributes_for_simulcast
        let ssrc : UInt? = if sdp_direction_can_send(direction) &&
          include_simulcast_ssrc {
          section.ssrc
        } else {
          None
        }
        let rtx_ssrc : UInt? = if sdp_direction_can_send(direction) &&
          include_simulcast_ssrc &&
          selected_rtx_payload_type is Some(_) {
          section.rtx_ssrc
        } else {
          None
        }
        let codecs : Array[@sdp.RtpCodecParameters] = [codec]
        match offered_rtx {
          Some(rtx) => codecs.push(rtx)
          None => ()
        }
        let header_extensions : Array[@sdp.RtpHeaderExtensionParameters] = []
        match selected_twcc_extension_id {
          Some(id) => header_extensions.push(transport_cc_extension(id))
          None => ()
        }
        let cname : String? = if sdp_direction_can_send(direction) &&
          section.ssrc is Some(_) {
          Some("rtc.mbt")
        } else {
          None
        }
        let streams : Array[@sdp.RtpStreamParameters] = []
        if sdp_direction_can_send(direction) {
          for
            stream in sdp_stream_parameters(
              section.encodings,
              selected_rtx_payload_type is Some(_),
              include_ssrc=include_simulcast_ssrc,
            ) {
            streams.push(stream)
          }
        }
        if sdp_direction_can_receive(direction) {
          for offered_stream in remote.streams() {
            match (offered_stream.rid, offered_stream.rid_direction) {
              (Some(rid), RidSend) =>
                streams.push(
                  rtc_sdp(() => {
                    @sdp.RtpStreamParameters::new(
                      rid~,
                      paused=offered_stream.paused &&
                        !self.configuration.settings.ignore_rid_pause_for_recv,
                      rid_direction=RidRecv,
                    )
                  }),
                )
              _ => ()
            }
          }
        }
        result.push(
          rtc_sdp(() => {
            @sdp.RtpMediaParameters::new(
              kind=remote.kind(),
              mid=remote.mid(),
              direction~,
              codecs~,
              header_extensions~,
              stream_id?,
              track_id?,
              ssrc?,
              rtx_ssrc?,
              streams~,
              cname?,
            )
          }),
        )
      }
    }
    Rollback => ()
  }
  result
}

///|
fn PeerConnection::next_local_description(
  self : PeerConnection,
  sdp_type : SdpType,
  setup : @sdp.DtlsSetup,
  mid : String,
  now : Instant,
  application_index? : Int = 0,
) -> SessionDescription raise RtcError {
  self.gather_candidates(now)
  let version = self.session_version
  self.session_version += 1UL
  let candidates = self.local_advertised_candidates.map(candidate => {
    candidate.marshal()
  })
  let media_sections = self.local_sdp_media_sections(sdp_type)
  let fingerprint = sdp_fingerprint(self.identity)
  let document = rtc_sdp(() => {
    @sdp.SdpDocument::new_datachannel(
      session_id=self.session_id,
      session_version=version,
      mid~,
      ice_credentials=self.local_credentials,
      fingerprint~,
      setup~,
      candidates~,
      end_of_candidates=self.gathering_state == Complete,
      sctp_port=self.configuration.sctp_port,
      max_message_size=self.configuration.max_message_size,
      media_sections~,
      application_index~,
    )
  })
  let description = rtc_sdp(() => {
    SessionDescription::from_document(sdp_type~, document)
  })
  self.drive(now)
  description
}

///|
pub fn PeerConnection::create_offer(
  self : PeerConnection,
  now : Instant,
) -> SessionDescription raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if self.signaling.state() != Stable {
    raise InvalidState("an offer can only be created in stable signaling state")
  }
  self.next_local_description(Offer, ActPass, "0", now)
}

///|
fn datachannel_media_index(
  description : SessionDescription,
) -> Int raise RtcError {
  let media_descriptions = rtc_sdp(() => {
    description.document().media_descriptions()
  })
  for index = 0; index < media_descriptions.length(); index = index + 1 {
    if media_descriptions[index].media_kind() == "application" {
      return index
    }
  }
  raise InvalidConfiguration("remote SDP has no data-channel media section")
}

///|
pub fn PeerConnection::create_answer(
  self : PeerConnection,
  now : Instant,
) -> SessionDescription raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if self.signaling.state() != HaveRemoteOffer &&
    self.signaling.state() != HaveLocalPranswer {
    raise InvalidState("an answer requires a pending remote offer")
  }
  guard self.signaling.remote_description() is Some(remote) else {
    raise InvalidState("the pending remote offer is missing")
  }
  let parameters = rtc_sdp(() => remote.datachannel_parameters())
  let setup : @sdp.DtlsSetup = match
    self.configuration.settings.answering_dtls_role {
    Some(Client) => Active
    Some(Server) => Passive
    Some(Auto) =>
      raise InvalidConfiguration("the answering DTLS role cannot be Auto")
    None => Active
  }
  self.next_local_description(
    Answer,
    setup,
    parameters.mid(),
    now,
    application_index=datachannel_media_index(remote),
  )
}

///|
pub fn PeerConnection::create_pranswer(
  self : PeerConnection,
  now : Instant,
) -> SessionDescription raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if self.signaling.state() != HaveRemoteOffer {
    raise InvalidState("a provisional answer requires a pending remote offer")
  }
  guard self.signaling.remote_description() is Some(remote) else {
    raise InvalidState("the pending remote offer is missing")
  }
  let parameters = rtc_sdp(() => remote.datachannel_parameters())
  let setup : @sdp.DtlsSetup = match
    self.configuration.settings.answering_dtls_role {
    Some(Client) => Active
    Some(Server) => Passive
    Some(Auto) =>
      raise InvalidConfiguration("the answering DTLS role cannot be Auto")
    None => Active
  }
  self.next_local_description(
    Pranswer,
    setup,
    parameters.mid(),
    now,
    application_index=datachannel_media_index(remote),
  )
}

///|
fn PeerConnection::validate_local_description(
  self : PeerConnection,
  description : SessionDescription,
) -> Unit raise RtcError {
  if description.sdp_type() == Rollback {
    return
  }
  let parameters = rtc_sdp(() => description.datachannel_parameters())
  if parameters.ice_credentials() != self.local_credentials {
    raise InvalidConfiguration(
      "local description does not contain this connection's ICE credentials",
    )
  }
  let expected = sdp_fingerprint(self.identity)
  if parameters.fingerprint() != expected {
    raise InvalidConfiguration(
      "local description does not contain this connection's DTLS fingerprint",
    )
  }
}

///|
fn append_remote_candidate(
  destination : Array[IceCandidate],
  candidate : IceCandidate,
) -> Unit {
  if !destination.contains(candidate) {
    destination.push(candidate)
  }
}

///|
fn PeerConnection::ingest_remote_candidate(
  self : PeerConnection,
  candidate : IceCandidate,
  now : Instant,
) -> Unit raise RtcError {
  match candidate.socket_address() {
    Some(_) => {
      let already_known = self.remote_candidates.contains(candidate)
      append_remote_candidate(self.remote_candidates, candidate)
      if !already_known && !self.ice_restart_pending {
        match self.ice_agent {
          Some(agent) =>
            rtc_ice(() => agent.add_remote_candidate(candidate, now~))
          None => ()
        }
      }
    }
    None =>
      match candidate.address() {
        MdnsName(name) => {
          for pending in self.pending_mdns_candidates.values() {
            if pending == candidate {
              return
            }
          }
          let query_id = rtc_mdns(() => self.mdns_resolver.query(name, now))
          self.pending_mdns_candidates[query_id] = candidate
        }
        IpAddress(_) =>
          raise InvalidConfiguration("ICE candidate address is unresolved")
      }
  }
}

///|
fn PeerConnection::refresh_local_ice_credentials(
  self : PeerConnection,
) -> Unit raise RtcError {
  self.local_credentials = match self.configuration.settings.ice_credentials {
    Some(credentials) => credentials
    None => {
      let provider = rtc_crypto(() => @crypto.Provider::open())
      generate_ice_credentials(provider)
    }
  }
}

///|
fn PeerConnection::clear_remote_ice_candidates(self : PeerConnection) -> Unit {
  self.remote_candidates.clear()
  for query_id in self.pending_mdns_candidates.keys() {
    self.mdns_resolver.cancel(query_id)
  }
  self.pending_mdns_candidates.clear()
}

///|
fn PeerConnection::prepare_remote_ice_restart(
  self : PeerConnection,
  description : SessionDescription,
) -> Unit raise RtcError {
  if description.sdp_type() == Rollback || !self.transport_started {
    return
  }
  let parameters = rtc_sdp(() => description.datachannel_parameters())
  let changed = match self.ice_agent {
    Some(agent) =>
      match agent.remote_credentials() {
        Some(credentials) => credentials != parameters.ice_credentials()
        None => false
      }
    None => false
  }
  if changed && !self.ice_restart_pending {
    self.refresh_local_ice_credentials()
    self.clear_remote_ice_candidates()
    self.ice_restart_pending = true
  }
}

///|
fn PeerConnection::remember_remote_description(
  self : PeerConnection,
  description : SessionDescription,
  now : Instant,
) -> Unit raise RtcError {
  if description.sdp_type() == Rollback {
    return
  }
  let parameters = rtc_sdp(() => description.datachannel_parameters())
  for encoded in parameters.candidates() {
    self.ingest_remote_candidate(
      rtc_ice(() => IceCandidate::parse(encoded)),
      now,
    )
  }
}

///|
fn PeerConnection::ingest_remote_media(
  self : PeerConnection,
  description : SessionDescription,
) -> Unit raise RtcError {
  if description.sdp_type() == Rollback {
    return
  }
  let media_sections = rtc_sdp(() => description.rtp_media_parameters())
  let present_mids : Array[String] = []
  for remote in media_sections {
    present_mids.push(remote.mid())
    let kind = media_kind_from_name(remote.kind())
    let remote_codecs = remote.codecs()
    let mut primary_codec : @sdp.RtpCodecParameters? = None
    for codec in remote_codecs {
      if codec.encoding_name().to_lower() != "rtx" {
        primary_codec = Some(codec)
        break
      }
    }
    guard primary_codec is Some(first_codec) else {
      raise InvalidConfiguration("remote RTP section has no codec")
    }
    let remote_rtx_codec = rtx_codec_matching(
      remote_codecs,
      first_codec.payload_type(),
    )
    let remote_rtx_payload_type = match remote_rtx_codec {
      Some(codec) => Some(codec.payload_type())
      None => None
    }
    let remote_twcc_extension_id = negotiated_transport_cc_id(
      remote.header_extensions(),
    )
    let mut matched_local : LocalMediaSection? = None
    for section in self.local_media_sections {
      if section.mid == Some(remote.mid()) {
        matched_local = Some(section)
        break
      }
    }
    if matched_local is None {
      for section in self.local_media_sections {
        if section.mid is None && section.transceiver.kind() == kind {
          matched_local = Some(section)
          break
        }
      }
    }
    if matched_local is None {
      let codec = media_codec_from_sdp(kind, first_codec)
      let desired_direction : TransceiverDirection = if sdp_direction_can_send(
          remote.direction(),
        ) {
        RecvOnly
      } else {
        Inactive
      }
      let transceiver = RtpTransceiver::new(kind~, direction=desired_direction)
      let section = {
        transceiver,
        remote_created: true,
        mid: None,
        track: None,
        codec,
        payload_type: first_codec.payload_type(),
        ssrc: None,
        rtx_payload_type: remote_rtx_payload_type,
        rtx_ssrc: None,
        encodings: [],
        twcc_extension_id: remote_twcc_extension_id,
        control: None,
        additional_controls: [],
      }
      self.local_media_sections.push(section)
      matched_local = Some(section)
    }
    guard matched_local is Some(local_section) else {
      raise InvalidState("failed to create RTP transceiver")
    }
    if local_section.mid is None {
      rtc_media(() => local_section.transceiver.assign_mid(remote.mid()))
      local_section.mid = Some(remote.mid())
    }
    if local_section.track is None &&
      !remote_codecs.any(codec => codecs_compatible(local_section.codec, codec)) {
      local_section.codec = media_codec_from_sdp(kind, first_codec)
      local_section.payload_type = first_codec.payload_type()
      local_section.rtx_payload_type = remote_rtx_payload_type
      local_section.twcc_extension_id = remote_twcc_extension_id
    }
    if description.sdp_type() == Answer || description.sdp_type() == Pranswer {
      let negotiated_codec = media_codec_from_sdp(kind, first_codec)
      local_section.codec = negotiated_codec
      local_section.payload_type = first_codec.payload_type()
      local_section.rtx_payload_type = remote_rtx_payload_type
      local_section.twcc_extension_id = remote_twcc_extension_id
      local_section.encodings = negotiated_media_encodings(
        local_section.encodings,
        first_codec.payload_type(),
        remote_rtx_payload_type,
      )
      local_section.encodings = accepted_media_encodings(
        local_section.encodings,
        remote.streams(),
      )
      self.configure_local_media_controls(local_section)
      set_sender_parameters(
        local_section.transceiver,
        negotiated_codec,
        local_section.encodings,
      )
    }
    let remote_sends = sdp_direction_can_send(remote.direction())
    let remote_codec = media_codec_from_sdp(kind, first_codec)
    let remote_track : MediaTrack? = if remote_sends {
      Some(
        MediaTrack::new(
          id=remote.track_id().unwrap_or("remote-" + remote.mid()),
          stream_id=remote.stream_id().unwrap_or("remote"),
          kind~,
          codec=remote_codec,
        ),
      )
    } else {
      None
    }
    let remote_encodings : Array[@media.RtpEncodingParameters] = []
    if remote_sends {
      for stream in remote.streams() {
        if stream.rid_direction != RidSend {
          continue
        }
        let ssrc = stream.ssrc
        let rtx_ssrc = stream.rtx_ssrc
        let rid = stream.rid
        let rtx_payload_type = if rtx_ssrc is Some(_) {
          remote_rtx_payload_type
        } else {
          None
        }
        remote_encodings.push(
          rtc_media(() => {
            @media.RtpEncodingParameters::new(
              ssrc?,
              payload_type=first_codec.payload_type(),
              rtx_ssrc?,
              rtx_payload_type?,
              rid?,
              active=!stream.paused ||
                self.configuration.settings.ignore_rid_pause_for_recv,
            )
          }),
        )
      }
    }
    let remote_controls : Array[RemoteMediaControl] = []
    for encoding in remote_encodings {
      match encoding.ssrc {
        Some(remote_ssrc) =>
          remote_controls.push(
            self.new_remote_media_control(
              remote_ssrc,
              first_codec.payload_type(),
              encoding.rtx_ssrc,
              encoding.rtx_payload_type,
              first_codec.clock_rate(),
            ),
          )
        None => ()
      }
    }
    let remote_control = remote_controls.get(0)
    let additional_remote_controls = if remote_controls.length() > 1 {
      remote_controls[1:].to_owned()
    } else {
      []
    }
    rtc_media(() => local_section.transceiver.receiver().set_track(remote_track))
    let receiver_parameters = if remote_sends {
      Some(
        rtc_media(() => {
          @media.RtpParameters::new(
            codec=remote_codec,
            encodings=remote_encodings,
          )
        }),
      )
    } else {
      None
    }
    local_section.transceiver.receiver().set_parameters(receiver_parameters)
    let mut existing : RemoteMediaSection? = None
    for section in self.remote_media_sections {
      if section.mid == remote.mid() {
        existing = Some(section)
        break
      }
    }
    match existing {
      Some(section) => {
        match (section.track, remote_track) {
          (Some(previous), None) =>
            self.enqueue_event(TrackClosed(previous.id()))
          (Some(previous), Some(next)) if previous.id() != next.id() => {
            self.enqueue_event(TrackClosed(previous.id()))
            self.enqueue_event(TrackOpened(next))
          }
          (None, Some(next)) => self.enqueue_event(TrackOpened(next))
          _ => ()
        }
        section.track = remote_track
        section.payload_type = first_codec.payload_type()
        section.rtx_payload_type = remote_rtx_payload_type
        section.encodings = remote_encodings
        section.twcc_extension_id = remote_twcc_extension_id
        section.control = remote_control
        section.additional_controls.clear()
        for control in additional_remote_controls {
          section.additional_controls.push(control)
        }
      }
      None => {
        self.remote_media_sections.push({
          mid: remote.mid(),
          track: remote_track,
          payload_type: first_codec.payload_type(),
          rtx_payload_type: remote_rtx_payload_type,
          encodings: remote_encodings,
          twcc_extension_id: remote_twcc_extension_id,
          control: remote_control,
          additional_controls: additional_remote_controls,
        })
        match remote_track {
          Some(track) => self.enqueue_event(TrackOpened(track))
          None => ()
        }
      }
    }
  }
  for index = self.remote_media_sections.length() - 1
      index >= 0
      index = index - 1 {
    let section = self.remote_media_sections[index]
    if !present_mids.contains(section.mid) {
      match section.track {
        Some(track) => self.enqueue_event(TrackClosed(track.id()))
        None => ()
      }
      for local_section in self.local_media_sections {
        if local_section.mid == Some(section.mid) {
          rtc_media(() => local_section.transceiver.receiver().set_track(None))
          local_section.transceiver.receiver().set_parameters(None)
          break
        }
      }
      ignore(self.remote_media_sections.remove(index))
    }
  }
  let mut twcc_extension_id : Byte? = None
  for section in self.remote_media_sections {
    match section.twcc_extension_id {
      Some(id) => {
        twcc_extension_id = Some(id)
        break
      }
      None => ()
    }
  }
  match (twcc_extension_id, self.remote_twcc_recorder) {
    (Some(extension_id), None) =>
      self.remote_twcc_recorder = Some(
        rtc_interceptor(() => {
          @interceptor.TwccRecorder::new(
            sender_ssrc=self.rtcp_sender_ssrc,
            media_ssrc=0U,
            extension_id~,
          )
        }),
      )
    (None, Some(_)) => self.remote_twcc_recorder = None
    _ => ()
  }
}

///|
fn PeerConnection::restore_committed_remote_description(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  let committed = self.signaling.current_remote_description()
  let committed_mids : Array[String] = []
  match committed {
    Some(description) => {
      let media_sections = rtc_sdp(() => description.rtp_media_parameters())
      for section in media_sections {
        committed_mids.push(section.mid())
      }
      self.clear_remote_ice_candidates()
      self.remember_remote_description(description, now)
      self.remote_twcc_recorder = None
      self.ingest_remote_media(description)
    }
    None => {
      for section in self.remote_media_sections {
        match section.track {
          Some(track) => self.enqueue_event(TrackClosed(track.id()))
          None => ()
        }
      }
      self.remote_media_sections.clear()
      self.remote_twcc_recorder = None
      self.clear_remote_ice_candidates()
    }
  }
  for index = self.local_media_sections.length() - 1
      index >= 0
      index = index - 1 {
    let section = self.local_media_sections[index]
    let retained = match section.mid {
      Some(mid) => committed_mids.contains(mid)
      None => false
    }
    if section.remote_created && !retained {
      ignore(self.local_media_sections.remove(index))
    }
  }
  self.ice_restart_pending = false
}

///|
fn stream_role_for_dtls(
  role : @dtls.Role,
) -> @datachannel.StreamRole raise RtcError {
  match role {
    Client => DtlsClient
    Server => DtlsServer
    Auto => raise InvalidState("DTLS role is unresolved")
  }
}

///|
fn PeerConnection::resolved_dtls_role(
  _self : PeerConnection,
  local_description : SessionDescription,
  remote : SessionDescription,
) -> @dtls.Role raise RtcError {
  let local_parameters = rtc_sdp(() => {
    local_description.datachannel_parameters()
  })
  let remote_parameters = rtc_sdp(() => remote.datachannel_parameters())
  match
    (
      local_description.sdp_type(),
      local_parameters.setup(),
      remote_parameters.setup(),
    ) {
    (Offer, ActPass, Active) => Server
    (Offer, ActPass, Passive) => Client
    (Answer, Active, ActPass) => Client
    (Answer, Passive, ActPass) => Server
    _ =>
      raise InvalidState("local and remote DTLS setup roles are incompatible")
  }
}

///|
fn PeerConnection::ensure_data_manager(
  self : PeerConnection,
  role : @datachannel.StreamRole,
) -> @datachannel.Manager raise RtcError {
  match self.data_manager {
    Some(manager) =>
      if manager.role() != role {
        let remapped = rtc_datachannel(() => manager.set_role(role))
        for mapping in remapped {
          let (previous, replacement) = mapping
          match self.data_channel_buffered_amount_low_thresholds.get(previous) {
            Some(threshold) => {
              self.data_channel_buffered_amount_low_thresholds.remove(previous)
              self.data_channel_buffered_amount_low_thresholds[replacement] = threshold
            }
            None => ()
          }
        }
        manager
      } else {
        manager
      }
    None => {
      let manager = @datachannel.Manager::new(role~)
      self.data_manager = Some(manager)
      manager
    }
  }
}

///|
fn PeerConnection::begin_transport(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.transport_started && !self.ice_restart_pending {
    return
  }
  guard self.signaling.current_local_description() is Some(local_description) else {
    return
  }
  guard self.signaling.current_remote_description() is Some(remote) else {
    return
  }
  if self.configuration.host_candidates.is_empty() {
    raise InvalidConfiguration(
      "at least one resolved host transport candidate is required",
    )
  }
  if self.local_transport_candidates.is_empty() {
    return
  }
  let remote_parameters = rtc_sdp(() => remote.datachannel_parameters())
  let dtls_role = self.resolved_dtls_role(local_description, remote)
  ignore(self.ensure_data_manager(stream_role_for_dtls(dtls_role)))
  let ice_role : @ice.IceRole = if local_description.sdp_type() == Offer {
    Controlling
  } else {
    Controlled
  }
  let ice_agent = rtc_ice(() => {
    @ice.IceAgent::new(
      local_credentials=self.local_credentials,
      role=ice_role,
      tie_breaker=self.tie_breaker,
      check_interval=self.configuration.settings.ice_check_interval,
      initial_rto=self.configuration.settings.ice_initial_rto,
      reliable_timeout=self.configuration.settings.ice_reliable_timeout,
      max_retransmissions=self.configuration.settings.ice_max_retransmissions,
      disconnected_timeout=self.configuration.settings.ice_disconnected_timeout,
      failed_timeout=self.configuration.settings.ice_failed_timeout,
      keepalive_interval=self.configuration.settings.ice_keepalive_interval,
    )
  })
  for candidate in self.local_transport_candidates {
    rtc_ice(() => ice_agent.add_local_candidate(candidate))
  }
  for candidate in self.remote_candidates {
    rtc_ice(() => ice_agent.add_remote_candidate(candidate))
  }
  rtc_ice(() => {
    ice_agent.set_remote_credentials(remote_parameters.ice_credentials())
  })
  match self.ice_agent {
    Some(previous) => previous.close()
    None => ()
  }
  self.ice_agent = Some(ice_agent)
  if self.dtls_endpoint is None {
    let wall_time = self.clock_sample.wall_at(now) catch {
      _ => raise InvalidState("cannot derive DTLS certificate wall time")
    }
    let expected_peer_fingerprint = dtls_fingerprint(
      remote_parameters.fingerprint(),
    )
    let dtls_config = rtc_dtls(() => {
      let psk = self.configuration.settings.dtls_psk
      let psk_identity = self.configuration.settings.dtls_psk_identity
      @dtls.Config::new(
        role=dtls_role,
        identity=self.identity,
        expected_peer_fingerprint~,
        wall_time~,
        cipher_suites=self.configuration.settings.dtls_cipher_suites,
        psk?,
        psk_identity?,
        srtp_profiles=self.configuration.settings.dtls_srtp_profiles,
        flight_interval=self.configuration.settings.dtls_flight_interval,
        mtu=self.configuration.settings.dtls_mtu,
        replay_window=self.configuration.settings.dtls_replay_window,
        verify_peer_fingerprint=self.configuration.settings.verify_peer_fingerprint,
      )
    })
    self.dtls_endpoint = Some(@dtls.Endpoint::new(dtls_config))
  }
  self.transport_started = true
  self.ice_restart_pending = false
  self.set_state(Connecting)
  rtc_ice(() => ice_agent.start(now))
  self.drive(now)
}

///|
pub fn PeerConnection::set_local_description(
  self : PeerConnection,
  description : SessionDescription,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  let rollback = description.sdp_type() == Rollback
  self.validate_local_description(description)
  let previous = self.signaling.state()
  rtc_sdp(() => self.signaling.set_local_description(description))
  if rollback {
    self.restore_committed_remote_description(now)
  }
  let next = self.signaling.state()
  if next != previous {
    self.enqueue_event(SignalingStateChanged(next))
  }
  if next == Stable {
    self.begin_transport(now)
  }
}

///|
pub fn PeerConnection::set_remote_description(
  self : PeerConnection,
  description : SessionDescription,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  let rollback = description.sdp_type() == Rollback
  if !rollback {
    self.prepare_remote_ice_restart(description)
    self.remember_remote_description(description, now)
  }
  let previous = self.signaling.state()
  rtc_sdp(() => self.signaling.set_remote_description(description))
  if rollback {
    self.restore_committed_remote_description(now)
  } else {
    self.ingest_remote_media(description)
  }
  let next = self.signaling.state()
  if next != previous {
    self.enqueue_event(SignalingStateChanged(next))
  }
  if next == Stable {
    self.begin_transport(now)
  }
}

///|
pub fn PeerConnection::rollback(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  let description = SessionDescription::new(sdp_type=Rollback, sdp="")
  match self.signaling.state() {
    HaveLocalOffer | HaveRemotePranswer =>
      self.set_local_description(description, now)
    HaveRemoteOffer | HaveLocalPranswer =>
      self.set_remote_description(description, now)
    _ => raise InvalidState("there is no pending negotiation to roll back")
  }
}

///|
pub fn PeerConnection::set_remote_description_perfect(
  self : PeerConnection,
  description : SessionDescription,
  policy : OfferCollisionPolicy,
  now : Instant,
) -> Unit raise RtcError {
  if description.sdp_type() != Offer || self.signaling.state() == Stable {
    self.set_remote_description(description, now)
    return
  }
  match policy {
    Impolite => raise InvalidState("incoming offer collided with negotiation")
    Polite =>
      match self.signaling.state() {
        HaveLocalOffer | HaveRemotePranswer => {
          self.set_local_description(
            SessionDescription::new(sdp_type=Rollback, sdp=""),
            now,
          )
          self.set_remote_description(description, now)
        }
        _ => raise InvalidState("incoming offer collided with negotiation")
      }
  }
}

///|
pub fn PeerConnection::add_ice_candidate(
  self : PeerConnection,
  candidate : IceCandidate,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  self.ingest_remote_candidate(candidate, now)
  self.drive(now)
}

///|
pub fn PeerConnection::restart_ice(
  self : PeerConnection,
  _now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if self.ice_restart_pending {
    return
  }
  self.refresh_local_ice_credentials()
  self.clear_remote_ice_candidates()
  self.ice_restart_pending = true
  self.enqueue_event(NegotiationNeeded)
}

///|
fn PeerConnection::predicted_stream_role(
  self : PeerConnection,
) -> @datachannel.StreamRole {
  match self.signaling.state() {
    HaveRemoteOffer | HaveLocalPranswer => DtlsClient
    _ => DtlsServer
  }
}

///|
pub fn PeerConnection::create_data_channel(
  self : PeerConnection,
  config : DataChannelConfig,
  now : Instant,
) -> DataChannel raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  let role = self.predicted_stream_role()
  let manager = self.ensure_data_manager(role)
  let channel = match self.data_transport {
    Some(transport) =>
      rtc_datachannel(() => transport.create_channel(config, now))
    None => rtc_datachannel(() => manager.create_channel(config))
  }
  self.enqueue_event(NegotiationNeeded)
  self.drive(now)
  channel
}

///|
pub fn PeerConnection::close_data_channel(
  self : PeerConnection,
  channel_id : @sctp.StreamId,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  match self.data_transport {
    Some(transport) =>
      rtc_datachannel(() => transport.close_channel(channel_id, now))
    None =>
      match self.data_manager {
        Some(manager) =>
          rtc_datachannel(() => manager.close_channel(channel_id))
        None => raise InvalidState("data channel manager is not initialized")
      }
  }
  self.drive(now)
}

///|
pub fn PeerConnection::data_channel_buffered_amount(
  self : PeerConnection,
  channel_id : @sctp.StreamId,
) -> UInt64 {
  match self.data_transport {
    Some(transport) => transport.buffered_amount(channel_id)
    None => 0UL
  }
}

///|
pub fn PeerConnection::set_data_channel_buffered_amount_low_threshold(
  self : PeerConnection,
  channel_id : @sctp.StreamId,
  threshold : UInt64,
) -> Unit raise RtcError {
  guard self.data_manager is Some(manager) &&
    manager.channel(channel_id) is Some(_) else {
    raise InvalidState("data channel is not initialized")
  }
  self.data_channel_buffered_amount_low_thresholds[channel_id] = threshold
  match self.data_transport {
    Some(transport) =>
      transport.set_buffered_amount_low_threshold(channel_id, threshold)
    None => ()
  }
}

///|
pub fn PeerConnection::data_channel_buffered_amount_low_threshold(
  self : PeerConnection,
  channel_id : @sctp.StreamId,
) -> UInt64 {
  self.data_channel_buffered_amount_low_thresholds.get_or_default(
    channel_id, 0UL,
  )
}

///|
pub fn PeerConnection::add_track(
  self : PeerConnection,
  track : MediaTrack,
  now : Instant,
) -> RtpTransceiver raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  let expected_prefix = media_kind_name(track.kind()) + "/"
  if !track.codec().mime_type().to_lower().has_prefix(expected_prefix) {
    raise InvalidConfiguration("track kind and codec MIME type disagree")
  }
  if self.local_media_sections.any(section => {
      match section.track {
        Some(existing) => existing.id() == track.id()
        None => false
      }
    }) {
    raise InvalidConfiguration("track id is already attached")
  }
  let fallback = (96 + self.local_media_sections.length() % 32).to_byte()
  let payload_type = self.unused_payload_type(
    preferred_payload_type(track.codec(), fallback),
  )
  let transceiver = RtpTransceiver::new(kind=track.kind())
  let ssrc = self.generate_media_ssrc()
  let rtx_payload_type : Byte? = if codec_uses_rtx(track.kind()) {
    Some(self.unused_rtx_payload_type(payload_type))
  } else {
    None
  }
  let rtx_ssrc : UInt? = if rtx_payload_type is Some(_) {
    let mut candidate = self.generate_media_ssrc()
    while candidate == ssrc {
      candidate = self.generate_media_ssrc()
    }
    Some(candidate)
  } else {
    None
  }
  let control = self.new_local_media_control(ssrc, rtx_ssrc, rtx_payload_type)
  let sender_parameters = media_rtp_parameters(
    track.codec(),
    payload_type,
    Some(ssrc),
    rtx_payload_type,
    rtx_ssrc,
  )
  rtc_media(() => {
    transceiver.sender().replace_track(Some(track))
    transceiver.sender().set_parameters(Some(sender_parameters))
  })
  self.local_media_sections.push({
    transceiver,
    remote_created: false,
    mid: None,
    track: Some(track),
    codec: track.codec(),
    payload_type,
    ssrc: Some(ssrc),
    rtx_payload_type,
    rtx_ssrc,
    encodings: sender_parameters.encodings(),
    twcc_extension_id: if codec_uses_twcc(track.codec()) {
      Some(3)
    } else {
      None
    },
    control: Some(control),
    additional_controls: [],
  })
  self.enqueue_event(NegotiationNeeded)
  self.drive(now)
  transceiver
}

///|
pub fn PeerConnection::add_transceiver(
  self : PeerConnection,
  kind : MediaKind,
  direction? : TransceiverDirection = SendRecv,
  now~ : Instant,
) -> RtpTransceiver raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if direction == Stopped {
    raise InvalidConfiguration("new RTP transceiver cannot start stopped")
  }
  let codec = default_media_codec(kind)
  let fallback = (96 + self.local_media_sections.length() % 32).to_byte()
  let payload_type = self.unused_payload_type(
    preferred_payload_type(codec, fallback),
  )
  let transceiver = RtpTransceiver::new(kind~, direction~)
  let rtx_payload_type : Byte? = if codec_uses_rtx(kind) {
    Some(self.unused_rtx_payload_type(payload_type))
  } else {
    None
  }
  let sender_parameters = media_rtp_parameters(
    codec,
    payload_type,
    None,
    rtx_payload_type,
    None,
  )
  transceiver.sender().set_parameters(Some(sender_parameters))
  self.local_media_sections.push({
    transceiver,
    remote_created: false,
    mid: None,
    track: None,
    codec,
    payload_type,
    ssrc: None,
    rtx_payload_type,
    rtx_ssrc: None,
    encodings: sender_parameters.encodings(),
    twcc_extension_id: if codec_uses_twcc(codec) {
      Some(3)
    } else {
      None
    },
    control: None,
    additional_controls: [],
  })
  self.enqueue_event(NegotiationNeeded)
  self.drive(now)
  transceiver
}

///|
pub fn PeerConnection::set_sender_encodings(
  self : PeerConnection,
  track_id : String,
  encodings : Array[@media.RtpEncodingParameters],
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  if encodings.is_empty() || encodings.length() > 8 {
    raise InvalidConfiguration(
      "an RTP sender requires between one and eight encodings",
    )
  }
  let mut selected : LocalMediaSection? = None
  for section in self.local_media_sections {
    match section.track {
      Some(track) if track.id() == track_id => {
        selected = Some(section)
        break
      }
      _ => ()
    }
  }
  guard selected is Some(section) else {
    raise InvalidState("track is not attached to this PeerConnection")
  }
  if encodings.length() > 1 && section.transceiver.kind() != Video {
    raise InvalidConfiguration("simulcast is only supported for video")
  }
  if encodings.length() > 1 && encodings.any(encoding => encoding.rid is None) {
    raise InvalidConfiguration("each simulcast encoding requires a RID")
  }
  let occupied : Array[UInt] = []
  for candidate in self.local_media_sections {
    match candidate.track {
      Some(track) if track.id() == track_id => continue
      _ => ()
    }
    for encoding in candidate.encodings {
      match encoding.ssrc {
        Some(ssrc) => occupied.push(ssrc)
        None => ()
      }
      match encoding.rtx_ssrc {
        Some(ssrc) => occupied.push(ssrc)
        None => ()
      }
    }
  }
  let normalized : Array[@media.RtpEncodingParameters] = []
  for requested in encodings {
    match requested.payload_type {
      Some(payload_type) if payload_type != section.payload_type =>
        raise InvalidConfiguration(
          "simulcast encoding payload type does not match its track",
        )
      _ => ()
    }
    match requested.rtx_payload_type {
      Some(payload_type) =>
        if section.rtx_payload_type != Some(payload_type) {
          raise InvalidConfiguration(
            "simulcast RTX payload type does not match its track",
          )
        }
      _ => ()
    }
    let ssrc = match requested.ssrc {
      Some(value) => value
      None => {
        let mut value = self.generate_media_ssrc()
        while occupied.contains(value) {
          value = self.generate_media_ssrc()
        }
        value
      }
    }
    if occupied.contains(ssrc) {
      raise InvalidConfiguration("simulcast SSRC is duplicated")
    }
    occupied.push(ssrc)
    let rtx_ssrc : UInt? = match section.rtx_payload_type {
      Some(_) => {
        let value = match requested.rtx_ssrc {
          Some(candidate) => candidate
          None => {
            let mut candidate = self.generate_media_ssrc()
            while occupied.contains(candidate) {
              candidate = self.generate_media_ssrc()
            }
            candidate
          }
        }
        if occupied.contains(value) {
          raise InvalidConfiguration("simulcast RTX SSRC is duplicated")
        }
        occupied.push(value)
        Some(value)
      }
      None => {
        if requested.rtx_ssrc is Some(_) {
          raise InvalidConfiguration(
            "RTP encoding provides RTX for a codec without RTX",
          )
        }
        None
      }
    }
    let rid = requested.rid
    let max_bitrate = requested.max_bitrate
    let scale_resolution_down_by = requested.scale_resolution_down_by
    let scalability_mode = requested.scalability_mode
    let rtx_payload_type = section.rtx_payload_type
    normalized.push(
      rtc_media(() => {
        @media.RtpEncodingParameters::new(
          ssrc~,
          payload_type=section.payload_type,
          rtx_ssrc?,
          rtx_payload_type?,
          rid?,
          active=requested.active,
          max_bitrate?,
          scale_resolution_down_by?,
          scalability_mode?,
        )
      }),
    )
  }
  ignore(
    rtc_media(() => {
      @media.RtpParameters::new(codec=section.codec, encodings=normalized)
    }),
  )
  section.encodings = normalized
  section.ssrc = normalized[0].ssrc
  section.rtx_ssrc = normalized[0].rtx_ssrc
  self.configure_local_media_controls(section)
  set_sender_parameters(section.transceiver, section.codec, section.encodings)
  self.enqueue_event(NegotiationNeeded)
  self.drive(now)
}

///|
pub fn PeerConnection::local_track_encodings(
  self : PeerConnection,
  track_id : String,
) -> Array[@media.RtpEncodingParameters] {
  for section in self.local_media_sections {
    match section.track {
      Some(track) if track.id() == track_id => return section.encodings.copy()
      _ => ()
    }
  }
  []
}

///|
pub fn PeerConnection::remove_track(
  self : PeerConnection,
  track_id : String,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  for section in self.local_media_sections {
    match section.track {
      Some(track) if track.id() == track_id => {
        section.track = None
        section.ssrc = None
        section.rtx_ssrc = None
        section.control = None
        let sender_parameters = media_rtp_parameters(
          section.codec,
          section.payload_type,
          None,
          section.rtx_payload_type,
          None,
        )
        section.encodings = sender_parameters.encodings()
        section.additional_controls.clear()
        rtc_media(() => {
          section.transceiver.sender().replace_track(None)
          section.transceiver.sender().set_parameters(Some(sender_parameters))
        })
        match section.transceiver.direction() {
          SendRecv =>
            rtc_media(() => section.transceiver.set_direction(RecvOnly))
          SendOnly =>
            rtc_media(() => section.transceiver.set_direction(Inactive))
          RecvOnly | Inactive | Stopped => ()
        }
        self.enqueue_event(NegotiationNeeded)
        self.drive(now)
        return
      }
      _ => ()
    }
  }
  raise InvalidState("track is not attached to this PeerConnection")
}

///|
pub fn PeerConnection::transceivers(
  self : PeerConnection,
) -> Array[RtpTransceiver] {
  self.local_media_sections.map(section => section.transceiver)
}

///|
pub fn PeerConnection::local_track_ssrc(
  self : PeerConnection,
  track_id : String,
) -> UInt? {
  for section in self.local_media_sections {
    match section.track {
      Some(track) if track.id() == track_id => return section.ssrc
      _ => ()
    }
  }
  None
}

///|
pub fn PeerConnection::local_track_payload_type(
  self : PeerConnection,
  track_id : String,
) -> Byte? {
  for section in self.local_media_sections {
    match section.track {
      Some(track) if track.id() == track_id => return Some(section.payload_type)
      _ => ()
    }
  }
  None
}

///|
fn PeerConnection::start_dtls(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.dtls_started {
    return
  }
  guard self.dtls_endpoint is Some(endpoint) else {
    raise InvalidState("DTLS endpoint is missing")
  }
  self.dtls_started = true
  rtc_dtls(() => endpoint.start(now))
}

///|
fn PeerConnection::start_data_transport(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.data_started {
    return
  }
  guard self.dtls_endpoint is Some(endpoint) else {
    raise InvalidState("DTLS endpoint is missing")
  }
  let role = stream_role_for_dtls(
    match endpoint.state() {
      Connected => {
        guard self.signaling.current_local_description()
          is Some(local_description) else {
          raise InvalidState("local description is missing")
        }
        guard self.signaling.current_remote_description() is Some(remote) else {
          raise InvalidState("remote description is missing")
        }
        self.resolved_dtls_role(local_description, remote)
      }
      _ => raise InvalidState("SCTP cannot start before DTLS connects")
    },
  )
  let manager = self.ensure_data_manager(role)
  let local_description = self.signaling.current_local_description().unwrap()
  let remote = self.signaling.current_remote_description().unwrap()
  let local_parameters = rtc_sdp(() => {
    local_description.datachannel_parameters()
  })
  let remote_parameters = rtc_sdp(() => remote.datachannel_parameters())
  let max_message_size = if self.configuration.max_message_size <
    remote_parameters.max_message_size() {
    self.configuration.max_message_size
  } else {
    remote_parameters.max_message_size()
  }
  let association_role : @sctp.AssociationRole = if role == DtlsClient {
    Active
  } else {
    Passive
  }
  let association_config = rtc_sctp(() => {
    @sctp.AssociationConfig::new(
      role=association_role,
      local_port=local_parameters.sctp_port(),
      remote_port=remote_parameters.sctp_port(),
      max_message_size~,
      max_payload_size=self.configuration.settings.sctp_max_payload_size,
      send_buffer_size=self.configuration.settings.sctp_send_buffer_size,
      receive_buffer_size=self.configuration.settings.sctp_receive_buffer_size,
      initial_rto=self.configuration.settings.sctp_initial_rto,
    )
  })
  let transport = rtc_datachannel(() => {
    @datachannel.Transport::with_manager(manager~, association_config~)
  })
  for entry in self.data_channel_buffered_amount_low_thresholds {
    let (stream, threshold) = entry
    transport.set_buffered_amount_low_threshold(stream, threshold)
  }
  self.data_transport = Some(transport)
  self.data_started = true
  rtc_datachannel(() => transport.start(now))
}

///|
fn srtp_profile_from_dtls(
  profile : @dtls.SrtpProtectionProfile,
) -> @srtp.ProtectionProfile {
  match profile {
    SrtpAes128CmHmacSha1_80 => Aes128CmHmacSha1_80
    SrtpAes128CmHmacSha1_32 => Aes128CmHmacSha1_32
    SrtpAeadAes128Gcm => AeadAes128Gcm
    SrtpAeadAes256Gcm => AeadAes256Gcm
  }
}

///|
fn PeerConnection::start_media_transport(
  self : PeerConnection,
  negotiated_profile : @dtls.SrtpProtectionProfile?,
  now : Instant,
) -> Unit raise RtcError {
  if self.media_started {
    return
  }
  guard negotiated_profile is Some(dtls_profile) else {
    if !self.local_media_sections.is_empty() ||
      !self.remote_media_sections.is_empty() {
      raise InvalidState("DTLS did not negotiate an SRTP protection profile")
    }
    return
  }
  guard self.dtls_endpoint is Some(endpoint) else {
    raise InvalidState("DTLS endpoint is missing")
  }
  let profile = srtp_profile_from_dtls(dtls_profile)
  let key_length = profile.key_length()
  let salt_length = profile.salt_length()
  let material = rtc_dtls(() => {
    endpoint.export_keying_material(
      "EXTRACTOR-dtls_srtp",
      2 * (key_length + salt_length),
    )
  })
  let client_key = material[:key_length].to_owned()
  let server_key = material[key_length:2 * key_length].to_owned()
  let client_salt = material[2 * key_length:2 * key_length + salt_length].to_owned()
  let server_salt = material[2 * key_length + salt_length:].to_owned()
  let (outbound_key, outbound_salt, inbound_key, inbound_salt) = match
    endpoint.role() {
    Client => (client_key, client_salt, server_key, server_salt)
    Server => (server_key, server_salt, client_key, client_salt)
    Auto => raise InvalidState("DTLS role is unresolved after the handshake")
  }
  self.outbound_srtp = Some(
    rtc_srtp(() => {
      @srtp.Context::new(
        profile~,
        master_key=outbound_key,
        master_salt=outbound_salt,
        rtp_replay_window=self.configuration.settings.srtp_replay_window,
        rtcp_replay_window=self.configuration.settings.srtcp_replay_window,
      )
    }),
  )
  self.inbound_srtp = Some(
    rtc_srtp(() => {
      @srtp.Context::new(
        profile~,
        master_key=inbound_key,
        master_salt=inbound_salt,
        rtp_replay_window=self.configuration.settings.srtp_replay_window,
        rtcp_replay_window=self.configuration.settings.srtcp_replay_window,
      )
    }),
  )
  self.media_started = true
  self.next_rtcp_report = Some(now.checked_add(Duration::milliseconds(1000L))) catch {
    _ => None
  }
}

///|
fn PeerConnection::remote_track_for_rtp(
  self : PeerConnection,
  packet : @rtp.Packet,
) -> MediaTrack? {
  for section in self.remote_media_sections {
    if section.encodings.any(encoding => encoding.ssrc == Some(packet.ssrc())) ||
      (
        section.encodings.all(encoding => encoding.ssrc is None) &&
        section.payload_type == packet.payload_type()
      ) {
      return section.track
    }
  }
  None
}

///|
fn PeerConnection::recover_remote_rtx(
  self : PeerConnection,
  packet : @rtp.Packet,
) -> @rtp.Packet? raise RtcError {
  for section in self.remote_media_sections {
    match remote_control_for_ssrc(section, packet.ssrc()) {
      Some(control) if control.rtx_ssrc == Some(packet.ssrc()) &&
        section.rtx_payload_type == Some(packet.payload_type()) => {
        guard control.rtx_receiver is Some(receiver) else { return None }
        return rtc_interceptor(() => receiver.recover(packet))
      }
      Some(control) if control.ssrc == packet.ssrc() &&
        section.payload_type == packet.payload_type() => {
        match control.rtx_receiver {
          Some(receiver) => receiver.observe_primary(packet)
          None => ()
        }
        return Some(packet)
      }
      _ => ()
    }
  }
  Some(packet)
}

///|
fn PeerConnection::observe_remote_rtp(
  self : PeerConnection,
  packet : @rtp.Packet,
  now : Instant,
) -> Unit raise RtcError {
  let mut feedback : @rtcp.TransportLayerNackPacket? = None
  for section in self.remote_media_sections {
    guard remote_control_for_ssrc(section, packet.ssrc()) is Some(control) else {
      continue
    }
    if control.ssrc != packet.ssrc() {
      continue
    }
    let clock_rate = section.track
      .map(track => track.codec().clock_rate())
      .unwrap_or(90000U)
    let arrival_ticks = (now.as_milliseconds() * clock_rate.to_int64() / 1000L)
      .to_int()
      .reinterpret_as_uint()
    control.receiver_report.observe(packet, arrival_ticks)
    control.nack_generator.observe(packet)
    match (self.remote_twcc_recorder, section.twcc_extension_id) {
      (Some(recorder), Some(extension_id)) =>
        rtc_interceptor(() => {
          recorder.observe_with_extension_id(
            packet,
            now.as_milliseconds() * 1000L,
            extension_id,
          )
        })
      _ => ()
    }
    feedback = control.nack_generator.poll_feedback()
    break
  }
  match feedback {
    Some(nack) =>
      self.send_media_through_interceptors(
        Rtcp(rtc_rtcp(() => nack.to_packet())),
        None,
      )
    None => ()
  }
}

///|
fn PeerConnection::handle_inbound_rtcp(
  self : PeerConnection,
  packet : @rtcp.Packet,
  now : Instant,
) -> Unit raise RtcError {
  match packet {
    SenderReport(_) =>
      try {
        let report = packet.as_sender_report()
        for section in self.remote_media_sections {
          match remote_control_for_ssrc(section, report.sender_ssrc) {
            Some(control) if control.ssrc == report.sender_ssrc =>
              control.receiver_report.observe_sender_report(
                report,
                now.as_milliseconds(),
              )
            _ => ()
          }
        }
      } catch {
        _ => ()
      }
    TransportFeedback(_) =>
      try {
        let nack = packet.as_transport_layer_nack()
        for section in self.local_media_sections {
          guard local_control_for_ssrc(section, nack.media_ssrc)
            is Some(control) &&
            control.ssrc == nack.media_ssrc &&
            control.rtx_sender is Some(sender) else {
            continue
          }
          let retransmissions = rtc_interceptor(() => sender.retransmit(nack))
          let stream_id = match section.track {
            Some(track) => Some(track.id())
            None => None
          }
          for retransmission in retransmissions {
            self.send_media_through_interceptors(Rtp(retransmission), stream_id)
          }
        }
      } catch {
        _ => ()
      }
    _ => ()
  }
  self.enqueue_message(Rtcp(packet))
  match packet {
    Goodbye(_) =>
      try {
        let goodbye = packet.as_goodbye()
        for source in goodbye.sources {
          for section in self.remote_media_sections {
            if section.encodings.any(encoding => encoding.ssrc == Some(source)) {
              match section.track {
                Some(track) => {
                  self.enqueue_event(TrackClosed(track.id()))
                  section.track = None
                }
                None => ()
              }
            }
          }
        }
      } catch {
        _ => ()
      }
    _ => ()
  }
}

///|
fn PeerConnection::handle_inbound_media_packet(
  self : PeerConnection,
  packet : @interceptor.Packet,
  now : Instant,
) -> Unit raise RtcError {
  match packet {
    Rtp(rtp_packet) =>
      match self.remote_track_for_rtp(rtp_packet) {
        Some(track) =>
          self.enqueue_message(Rtp(track_id=track.id(), packet=rtp_packet))
        None => ()
      }
    Rtcp(rtcp_packet) => self.handle_inbound_rtcp(rtcp_packet, now)
  }
}

///|
fn PeerConnection::handle_secure_media(
  self : PeerConnection,
  payload : Bytes,
  now : Instant,
) -> Unit raise RtcError {
  guard self.inbound_srtp is Some(context) else { return }
  if payload.length() < 2 {
    return
  }
  let is_rtcp = payload[1] >= 192 && payload[1] <= 223
  if is_rtcp {
    let packets = context.unprotect_rtcp(payload) catch {
      AuthenticationFailed | ReplayRejected | InvalidPacket(_) => return
      error => raise Srtp(error)
    }
    for packet in packets {
      let outputs = rtc_interceptor(() => {
        self.configuration.interceptor_pipeline.process(
          @interceptor.Context::new(direction=Inbound),
          Rtcp(packet),
        )
      })
      for output in outputs {
        self.handle_inbound_media_packet(output, now)
      }
    }
  } else {
    let encrypted_packet = context.unprotect_rtp(payload) catch {
      AuthenticationFailed | ReplayRejected | InvalidPacket(_) => return
      error => raise Srtp(error)
    }
    guard self.recover_remote_rtx(encrypted_packet) is Some(recovered) else {
      return
    }
    guard self.remote_track_for_rtp(recovered) is Some(track) else { return }
    let packet = self.transform_rtp_payload(
      recovered,
      TransformInbound,
      Some(track.id()),
      track.codec(),
    )
    self.observe_remote_rtp(packet, now)
    let stream_id = Some(track.id())
    let outputs = rtc_interceptor(() => {
      self.configuration.interceptor_pipeline.process(
        @interceptor.Context::new(direction=Inbound, stream_id?),
        Rtp(packet),
      )
    })
    for output in outputs {
      self.handle_inbound_media_packet(output, now)
    }
  }
}

///|
fn PeerConnection::handle_ice_event(
  self : PeerConnection,
  event : @ice.IceEvent,
  now : Instant,
) -> Unit raise RtcError {
  match event {
    ConnectionStateChanged(state) => {
      self.enqueue_event(IceConnectionStateChanged(state))
      match state {
        Checking | Connected | Completed =>
          if self.state == New {
            self.set_state(Connecting)
          } else if state == Completed &&
            self.state == Disconnected &&
            self.dtls_started &&
            self.data_started {
            self.set_state(Connected)
          }
        Failed => self.set_state(Failed)
        Disconnected => self.set_state(Disconnected)
        Closed => if self.state != Closed { self.set_state(Disconnected) }
        New => ()
      }
    }
    RoleChanged(_) => ()
    SelectedPair(_) =>
      if self.dtls_started && self.data_started {
        self.set_state(Connected)
      } else {
        self.start_dtls(now)
      }
    ApplicationDatagram(datagram) => {
      if datagram.payload.is_empty() {
        return
      }
      let first = datagram.payload[0]
      if first >= 20 && first <= 63 {
        guard self.dtls_endpoint is Some(endpoint) else {
          raise InvalidState("received DTLS before endpoint creation")
        }
        rtc_dtls(() => endpoint.handle_datagram(datagram.now, datagram.payload))
      } else if first >= 128 && first <= 191 {
        self.handle_secure_media(datagram.payload, datagram.now)
      } else {
        return
      }
    }
  }
}

///|
fn PeerConnection::handle_dtls_event(
  self : PeerConnection,
  event : @dtls.DtlsEvent,
  now : Instant,
) -> Unit raise RtcError {
  match event {
    StateChanged(Failed) => self.set_state(Failed)
    StateChanged(Closed) =>
      if self.state != Closed {
        self.set_state(Disconnected)
      }
    StateChanged(_) => ()
    ConnectedWithSrtp(profile) => {
      self.start_media_transport(profile, now)
      self.start_data_transport(now)
    }
    ApplicationDataReceived(payload) => {
      guard self.data_transport is Some(transport) else {
        raise InvalidState("received SCTP before data transport creation")
      }
      rtc_datachannel(() => transport.handle_datagram(now, payload))
    }
    AlertReceived(_, _) => ()
  }
}

///|
fn PeerConnection::handle_data_event(
  self : PeerConnection,
  event : @datachannel.DataChannelEvent,
) -> Unit raise RtcError {
  match event {
    Opened(channel) => {
      self.data_channels_opened += 1U
      self.enqueue_event(DataChannelOpened(channel))
    }
    MessageReceived(stream, message) =>
      self.enqueue_message(DataChannel(channel_id=stream, message~))
    ClosedEvent(stream) => {
      self.data_channels_closed += 1U
      self.enqueue_event(DataChannelClosed(stream))
    }
    BufferedAmountLowEvent(stream) =>
      self.enqueue_event(BufferedAmountLow(stream))
  }
}

///|
fn PeerConnection::queue_outbound(
  self : PeerConnection,
  datagram : OutboundDatagram,
) -> Unit {
  self.bytes_sent += datagram.payload.length().to_uint64()
  self.packets_sent += 1UL
  self.outbound.push(datagram)
}

///|
fn PeerConnection::next_stream_connection(
  self : PeerConnection,
) -> ConnectionId raise RtcError {
  // The low half of the identifier space belongs to connections initiated by
  // the core. Drivers use the high half for accepted connections.
  if self.next_connection_id == 0x8000000000000000UL {
    raise InvalidState("stream connection identifier space is exhausted")
  }
  let connection = ConnectionId(self.next_connection_id)
  self.next_connection_id += 1UL
  connection
}

///|
fn PeerConnection::next_stream_listener(
  self : PeerConnection,
) -> ListenerId raise RtcError {
  if self.next_listener_id == 0xffffffffffffffffUL {
    raise InvalidState("stream listener identifier space is exhausted")
  }
  let listener = ListenerId(self.next_listener_id)
  self.next_listener_id += 1UL
  listener
}

///|
fn PeerConnection::active_stream_for_owner(
  self : PeerConnection,
  owner : RtcStreamOwner,
  context : TransportContext,
) -> ActiveRtcStream? {
  for stream in self.active_streams {
    if stream.owner == owner && stream.logical_context == context {
      return Some(stream)
    }
  }
  None
}

///|
fn PeerConnection::pending_stream_for_owner(
  self : PeerConnection,
  owner : RtcStreamOwner,
  context : TransportContext,
) -> PendingRtcStream? {
  for stream in self.pending_streams {
    if stream.owner == owner && stream.logical_context == context {
      return Some(stream)
    }
  }
  None
}

///|
fn PeerConnection::ensure_stream_connection(
  self : PeerConnection,
  owner : RtcStreamOwner,
  context : TransportContext,
  tls : Bool,
) -> PendingRtcStream? raise RtcError {
  if self.active_stream_for_owner(owner, context) is Some(_) {
    return None
  }
  match self.pending_stream_for_owner(owner, context) {
    Some(stream) => return Some(stream)
    None => ()
  }
  let connection = self.next_stream_connection()
  let pending : PendingRtcStream = {
    connection,
    owner,
    logical_context: context,
    writes: Queue([]),
  }
  self.pending_streams.push(pending)
  let local_address = Some(context.local_address)
  let peer = context.peer
  self.io_actions.push(
    if tls {
      ConnectTls(connection~, local_address~, peer~, server_name=None)
    } else {
      ConnectTcp(connection~, local_address~, peer~)
    },
  )
  Some(pending)
}

///|
fn ice_stream_frame(payload : Bytes) -> Bytes raise RtcError {
  if payload.is_empty() || payload.length() > 0xffff {
    raise InvalidConfiguration("ICE TCP packet must contain 1..65535 bytes")
  }
  Bytes::from_array([
    (payload.length() >> 8).to_byte(),
    payload.length().to_byte(),
  ]) +
  payload
}

///|
fn PeerConnection::route_ice_stream_packet(
  self : PeerConnection,
  datagram : OutboundDatagram,
) -> Unit raise RtcError {
  let frame = ice_stream_frame(datagram.payload)
  match self.active_stream_for_owner(IceStream, datagram.context) {
    Some(stream) => stream.writes.push(frame)
    None => {
      let pending = match
        self.pending_stream_for_owner(IceStream, datagram.context) {
        Some(stream) => stream
        None => {
          guard self.ensure_stream_connection(
              IceStream,
              datagram.context,
              false,
            )
            is Some(stream) else {
            raise InvalidState("failed to create ICE TCP connection")
          }
          stream
        }
      }
      pending.writes.push(frame)
    }
  }
  self.bytes_sent += datagram.payload.length().to_uint64()
  self.packets_sent += 1UL
}

///|
fn PeerConnection::ensure_tcp_listeners(
  self : PeerConnection,
) -> Unit raise RtcError {
  for candidate in self.configuration.host_candidates {
    if candidate.protocol() != Tcp {
      continue
    }
    match candidate.tcp_type() {
      Some(Passive) | Some(SimultaneousOpen) => ()
      _ => continue
    }
    guard candidate.socket_address() is Some(local_address) else { continue }
    if self.active_listeners.any(listener => {
        listener.local_address == local_address
      }) {
      continue
    }
    let listener = self.next_stream_listener()
    self.active_listeners.push({ listener, local_address, })
    self.io_actions.push(ListenTcp(listener~, local_address~))
  }
}

///|
fn PeerConnection::flush_stream_writes(self : PeerConnection) -> Bool {
  for stream in self.active_streams {
    match stream.writes.pop() {
      Some(bytes) => {
        self.io_actions.push(WriteStream(connection=stream.connection, bytes~))
        return true
      }
      None => ()
    }
  }
  false
}

///|
fn PeerConnection::mdns_source_address(
  self : PeerConnection,
  destination : SocketAddress,
) -> SocketAddress? {
  for candidate in self.configuration.host_candidates {
    if candidate.protocol() != Udp {
      continue
    }
    guard candidate.socket_address() is Some(address) else { continue }
    match (address.address(), destination.address()) {
      (V4(_), V4(_)) | (V6(_), V6(_)) => return Some(address)
      _ => ()
    }
  }
  None
}

///|
fn PeerConnection::handle_mdns_event(
  self : PeerConnection,
  event : @mdns.MdnsEvent,
  now : Instant,
) -> Unit raise RtcError {
  match event {
    Resolved(query_id, resolution) => {
      guard self.pending_mdns_candidates.get(query_id) is Some(candidate) else {
        return
      }
      self.pending_mdns_candidates.remove(query_id)
      for address in resolution.addresses() {
        self.ingest_remote_candidate(
          rtc_ice(() => candidate.resolve_mdns(address)),
          now,
        )
      }
    }
    TimedOut(query_id) | Cancelled(query_id) =>
      self.pending_mdns_candidates.remove(query_id)
  }
}

///|
fn PeerConnection::maybe_complete_candidate_gathering(
  self : PeerConnection,
) -> Unit raise RtcError {
  if self.gathering_state != Gathering {
    return
  }
  let srflx_complete = self.srflx_gatherers.all(gatherer => {
    match gatherer.state() {
      SrflxComplete | SrflxFailed | SrflxClosed => true
      SrflxNew | SrflxGathering => false
    }
  })
  let turn_complete = self.turn_allocations.all(allocation => {
    match allocation.state() {
      Active | Failed | Closed => true
      New | Allocating | Refreshing => false
    }
  })
  if srflx_complete && turn_complete {
    self.set_gathering_state(Complete)
  }
}

///|
fn PeerConnection::handle_srflx_event(
  self : PeerConnection,
  event : @ice.SrflxEvent,
  now : Instant,
) -> Unit raise RtcError {
  match event {
    ServerReflexiveCandidate(candidate) =>
      if !self.local_transport_candidates.contains(candidate) {
        self.local_transport_candidates.push(candidate)
        self.local_advertised_candidates.push(candidate)
        self.enqueue_event(IceCandidateDiscovered(candidate))
        match self.ice_agent {
          Some(agent) =>
            rtc_ice(() => agent.add_local_candidate(candidate, now~))
          None => ()
        }
      }
    SrflxStateChanged(_) => ()
  }
  self.maybe_complete_candidate_gathering()
}

///|
fn PeerConnection::turn_allocation_for_relay(
  self : PeerConnection,
  local_address : SocketAddress,
) -> @turn.Allocation? {
  for allocation in self.turn_allocations {
    match allocation.relayed_address() {
      Some(relayed) if relayed.address() == local_address =>
        return Some(allocation)
      _ => ()
    }
  }
  None
}

///|
fn PeerConnection::route_ice_datagram(
  self : PeerConnection,
  datagram : OutboundDatagram,
  now : Instant,
) -> Unit raise RtcError {
  if datagram.context.protocol == Tcp {
    self.route_ice_stream_packet(datagram)
    return
  }
  match self.turn_allocation_for_relay(datagram.context.local_address) {
    None => self.queue_outbound(datagram)
    Some(allocation) =>
      allocation.send(datagram.context.peer, datagram.payload, now) catch {
        PermissionMissing => {
          let already_pending = self.pending_relay_datagrams.any(pending => {
            pending.datagram.context.local_address ==
            datagram.context.local_address &&
            pending.datagram.context.peer == datagram.context.peer
          })
          self.pending_relay_datagrams.push({ datagram, })
          if !already_pending {
            rtc_turn(() => {
              allocation.create_permission(datagram.context.peer, now)
            })
          }
        }
        error => raise Turn(error)
      }
  }
}

///|
fn PeerConnection::handle_turn_event(
  self : PeerConnection,
  allocation : @turn.Allocation,
  event : @turn.AllocationEvent,
  now : Instant,
) -> Unit raise RtcError {
  match event {
    AllocationCreated(relayed) => {
      let local_address = allocation.local_address()
      let mut foundation = "relay"
      for candidate in self.configuration.host_candidates {
        if candidate.socket_address() == Some(local_address) {
          foundation = candidate.foundation() + "-relay"
          break
        }
      }
      let related_address : @ice.CandidateAddress? = if self.configuration.ice_transport_policy ==
        Relay {
        None
      } else {
        Some(IpAddress(local_address.address()))
      }
      let related_port : UInt16? = if self.configuration.ice_transport_policy ==
        Relay {
        None
      } else {
        Some(local_address.port())
      }
      let candidate = rtc_ice(() => {
        IceCandidate::new(
          foundation~,
          component=1,
          protocol=Udp,
          priority=IceCandidate::priority_value(
            candidate_type=Relay,
            local_preference=65535,
            component=1,
          ),
          address=IpAddress(relayed.address().address()),
          port=relayed.address().port(),
          candidate_type=Relay,
          related_address?,
          related_port?,
        )
      })
      if !self.local_transport_candidates.contains(candidate) {
        self.local_transport_candidates.push(candidate)
        self.local_advertised_candidates.push(candidate)
        self.enqueue_event(IceCandidateDiscovered(candidate))
        match self.ice_agent {
          Some(agent) =>
            rtc_ice(() => agent.add_local_candidate(candidate, now~))
          None => ()
        }
      }
      if !self.transport_started && self.signaling.state() == Stable {
        self.begin_transport(now)
      }
    }
    PermissionCreated(peer) => {
      let ready : Array[Int] = []
      for index = 0
          index < self.pending_relay_datagrams.length()
          index = index + 1 {
        let pending = self.pending_relay_datagrams[index]
        match allocation.relayed_address() {
          Some(relayed) if pending.datagram.context.local_address ==
            relayed.address() &&
            pending.datagram.context.peer == peer => ready.push(index)
          _ => ()
        }
      }
      for offset = ready.length() - 1; offset >= 0; offset = offset - 1 {
        let index = ready[offset]
        let pending = self.pending_relay_datagrams[index]
        ignore(self.pending_relay_datagrams.remove(index))
        rtc_turn(() => {
          allocation.send(
            pending.datagram.context.peer,
            pending.datagram.payload,
            now,
          )
        })
      }
    }
    PeerData(peer~, payload~) => {
      guard allocation.relayed_address() is Some(relayed) else {
        raise InvalidState("TURN peer data arrived before allocation")
      }
      match self.ice_agent {
        Some(agent) =>
          rtc_ice(() => {
            agent.handle_datagram({
              now,
              context: {
                local_address: relayed.address(),
                peer,
                ecn: None,
                protocol: Udp,
              },
              payload,
            })
          })
        None => ()
      }
    }
    AllocationStateChanged(Failed) =>
      if self.configuration.ice_transport_policy == Relay {
        self.set_state(Failed)
      }
    AllocationStateChanged(_) | ChannelBound(_) => ()
  }
  self.maybe_complete_candidate_gathering()
}

///|
fn PeerConnection::drive(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  for iteration = 0; iteration < 8192; iteration = iteration + 1 {
    let mut progressed = false
    for index = 0; index < self.turn_allocations.length(); index = index + 1 {
      let allocation = self.turn_allocations[index]
      if allocation.transport() == Udp {
        match allocation.poll_datagram() {
          Some(datagram) => {
            self.queue_outbound(datagram)
            progressed = true
          }
          None => ()
        }
      } else {
        let context : TransportContext = {
          local_address: allocation.local_address(),
          peer: allocation.server(),
          ecn: None,
          protocol: Tcp,
        }
        match self.active_stream_for_owner(TurnStream(index), context) {
          Some(stream) =>
            match allocation.poll_stream_write() {
              Some(bytes) => {
                self.bytes_sent += bytes.length().to_uint64()
                self.packets_sent += 1UL
                stream.writes.push(bytes)
                progressed = true
              }
              None => ()
            }
          None => ()
        }
      }
      match allocation.poll_event() {
        Some(event) => {
          self.handle_turn_event(allocation, event, now)
          progressed = true
        }
        None => ()
      }
    }
    for gatherer in self.srflx_gatherers {
      match gatherer.poll_datagram() {
        Some(datagram) => {
          self.queue_outbound(datagram)
          progressed = true
        }
        None => ()
      }
      match gatherer.poll_event() {
        Some(event) => {
          self.handle_srflx_event(event, now)
          progressed = true
        }
        None => ()
      }
    }
    match self.mdns_resolver.poll_output() {
      Some(output) => {
        guard self.mdns_source_address(output.destination())
          is Some(local_address) else {
          raise InvalidConfiguration(
            "mDNS query has no local candidate in the destination address family",
          )
        }
        self.queue_outbound({
          context: {
            local_address,
            peer: output.destination(),
            ecn: None,
            protocol: Udp,
          },
          payload: output.payload(),
        })
        progressed = true
      }
      None => ()
    }
    match self.mdns_resolver.poll_event() {
      Some(event) => {
        self.handle_mdns_event(event, now)
        progressed = true
      }
      None => ()
    }
    match self.ice_agent {
      Some(agent) => {
        match agent.poll_datagram() {
          Some(datagram) => {
            self.route_ice_datagram(datagram, now)
            progressed = true
          }
          None => ()
        }
        match agent.poll_event() {
          Some(event) => {
            self.handle_ice_event(event, now)
            progressed = true
          }
          None => ()
        }
      }
      None => ()
    }
    match self.dtls_endpoint {
      Some(endpoint) => {
        match endpoint.poll_datagram() {
          Some(payload) => {
            guard self.ice_agent is Some(agent) else {
              raise InvalidState("DTLS output has no ICE transport")
            }
            rtc_ice(() => agent.send(payload))
            progressed = true
          }
          None => ()
        }
        match endpoint.poll_event() {
          Some(event) => {
            self.handle_dtls_event(event, now)
            progressed = true
          }
          None => ()
        }
      }
      None => ()
    }
    match self.data_transport {
      Some(transport) => {
        match transport.poll_datagram() {
          Some(payload) => {
            guard self.dtls_endpoint is Some(endpoint) else {
              raise InvalidState("SCTP output has no DTLS transport")
            }
            rtc_dtls(() => endpoint.send_application_data(payload))
            progressed = true
          }
          None => ()
        }
        match transport.poll_event() {
          Some(event) => {
            self.handle_data_event(event)
            progressed = true
          }
          None => ()
        }
        let ice_ready = match self.ice_agent {
          Some(agent) => agent.state() == Completed
          None => false
        }
        if transport.association_state() == Established &&
          ice_ready &&
          self.state != Connected {
          self.set_state(Connected)
          progressed = true
        }
      }
      None => ()
    }
    if self.flush_stream_writes() {
      progressed = true
    }
    if !progressed {
      return
    }
  }
  self.set_state(Failed)
  raise InvalidState("PeerConnection internal pipeline did not quiesce")
}

///|
fn PeerConnection::active_stream_index(
  self : PeerConnection,
  connection : ConnectionId,
) -> Int? {
  for index = 0; index < self.active_streams.length(); index = index + 1 {
    if self.active_streams[index].connection == connection {
      return Some(index)
    }
  }
  None
}

///|
fn PeerConnection::pending_stream_index(
  self : PeerConnection,
  connection : ConnectionId,
) -> Int? {
  for index = 0; index < self.pending_streams.length(); index = index + 1 {
    if self.pending_streams[index].connection == connection {
      return Some(index)
    }
  }
  None
}

///|
fn stream_context_matches_connection(
  expected : TransportContext,
  actual : TransportContext,
) -> Bool {
  expected.protocol == Tcp &&
  actual.protocol == Tcp &&
  expected.peer == actual.peer &&
  expected.local_address.address() == actual.local_address.address() &&
  (
    expected.local_address.port() == 0 ||
    expected.local_address.port() == actual.local_address.port()
  )
}

///|
fn PeerConnection::activate_connected_stream(
  self : PeerConnection,
  now : Instant,
  connection : ConnectionId,
  context : TransportContext,
) -> Unit raise RtcError {
  guard self.pending_stream_index(connection) is Some(index) else {
    self.io_actions.push(CloseStream(connection))
    raise InvalidState("stream connected with an unknown connection ID")
  }
  let pending = self.pending_streams[index]
  if !stream_context_matches_connection(pending.logical_context, context) {
    ignore(self.pending_streams.remove(index))
    self.io_actions.push(CloseStream(connection))
    raise InvalidState("stream connected with an unexpected transport context")
  }
  ignore(self.pending_streams.remove(index))
  self.active_streams.push({
    connection,
    owner: pending.owner,
    logical_context: pending.logical_context,
    writes: pending.writes,
    input: b"",
  })
  self.drive(now)
}

///|
fn PeerConnection::accept_stream(
  self : PeerConnection,
  now : Instant,
  listener : ListenerId,
  connection : ConnectionId,
  context : TransportContext,
) -> Unit raise RtcError {
  let mut expected_address : SocketAddress? = None
  for active_listener in self.active_listeners {
    if active_listener.listener == listener {
      expected_address = Some(active_listener.local_address)
      break
    }
  }
  guard expected_address is Some(expected) else {
    self.io_actions.push(CloseStream(connection))
    raise InvalidState("stream accepted by an unknown listener")
  }
  if context.protocol != Tcp ||
    context.local_address != expected ||
    self.active_stream_index(connection) is Some(_) ||
    self.pending_stream_index(connection) is Some(_) {
    self.io_actions.push(CloseStream(connection))
    raise InvalidState("accepted stream has an unexpected transport context")
  }
  self.active_streams.push({
    connection,
    owner: IceStream,
    logical_context: context,
    writes: Queue([]),
    input: b"",
  })
  self.drive(now)
}

///|
fn PeerConnection::handle_ice_stream_bytes(
  self : PeerConnection,
  stream : ActiveRtcStream,
  now : Instant,
  bytes : Bytes,
) -> Unit raise RtcError {
  if stream.input.length() + bytes.length() > 1048576 {
    self.io_actions.push(CloseStream(stream.connection))
    raise InvalidConfiguration("ICE TCP input buffer exceeded one MiB")
  }
  stream.input = stream.input + bytes
  for ;; {
    if stream.input.length() < 2 {
      return
    }
    let length = ((stream.input[0].to_uint() << 8) | stream.input[1].to_uint()).reinterpret_as_int()
    if length == 0 {
      self.io_actions.push(CloseStream(stream.connection))
      raise InvalidConfiguration("ICE TCP frame cannot be empty")
    }
    if stream.input.length() < 2 + length {
      return
    }
    let payload = stream.input[2:2 + length].to_owned()
    stream.input = stream.input[2 + length:].to_owned()
    guard self.ice_agent is Some(agent) else {
      raise InvalidState("ICE TCP bytes arrived before ICE started")
    }
    self.bytes_received += payload.length().to_uint64()
    self.packets_received += 1UL
    rtc_ice(() => {
      agent.handle_datagram({ now, context: stream.logical_context, payload, })
    })
    self.drive(now)
  }
}

///|
fn PeerConnection::handle_stream_bytes(
  self : PeerConnection,
  now : Instant,
  connection : ConnectionId,
  bytes : Bytes,
) -> Unit raise RtcError {
  guard self.active_stream_index(connection) is Some(index) else {
    self.io_actions.push(CloseStream(connection))
    raise InvalidState("stream bytes used an unknown connection ID")
  }
  let stream = self.active_streams[index]
  match stream.owner {
    IceStream => self.handle_ice_stream_bytes(stream, now, bytes)
    TurnStream(allocation_index) => {
      if allocation_index < 0 ||
        allocation_index >= self.turn_allocations.length() {
        raise InvalidState("TURN stream refers to an unknown allocation")
      }
      self.bytes_received += bytes.length().to_uint64()
      rtc_turn(() => {
        self.turn_allocations[allocation_index].handle_stream_bytes(now, bytes)
      })
      self.drive(now)
    }
  }
}

///|
fn PeerConnection::drop_stream(
  self : PeerConnection,
  connection : ConnectionId,
) -> Unit raise RtcError {
  match self.pending_stream_index(connection) {
    Some(index) => {
      let pending = self.pending_streams[index]
      ignore(self.pending_streams.remove(index))
      match pending.owner {
        TurnStream(allocation_index) =>
          if allocation_index >= 0 &&
            allocation_index < self.turn_allocations.length() {
            self.turn_allocations[allocation_index].handle_stream_closed()
          }
        IceStream => ()
      }
      return
    }
    None => ()
  }
  match self.active_stream_index(connection) {
    Some(index) => {
      let stream = self.active_streams[index]
      ignore(self.active_streams.remove(index))
      match stream.owner {
        TurnStream(allocation_index) =>
          if allocation_index >= 0 &&
            allocation_index < self.turn_allocations.length() {
            self.turn_allocations[allocation_index].handle_stream_closed()
          }
        IceStream => if self.state == Connected { self.set_state(Disconnected) }
      }
    }
    None => ()
  }
}

///|
pub fn PeerConnection::handle_io_event(
  self : PeerConnection,
  event : IoEvent,
) -> Unit raise RtcError {
  match event {
    DatagramReceived(datagram) => self.handle_datagram(datagram)
    StreamConnected(now~, connection~, context~) =>
      self.activate_connected_stream(now, connection, context)
    StreamAccepted(now~, listener~, connection~, context~) =>
      self.accept_stream(now, listener, connection, context)
    StreamBytes(now~, connection~, bytes~) =>
      self.handle_stream_bytes(now, connection, bytes)
    StreamWritable(now~, connection~) => {
      if self.active_stream_index(connection) is None {
        raise InvalidState("writable event used an unknown stream")
      }
      self.drive(now)
    }
    StreamEof(now=_, connection~) => {
      self.drop_stream(connection)
      self.io_actions.push(CloseStream(connection))
    }
    StreamError(now=_, connection~, reason=_) => {
      self.drop_stream(connection)
      self.io_actions.push(CloseStream(connection))
    }
    StreamClosed(now=_, connection~) => self.drop_stream(connection)
  }
}

///|
pub fn PeerConnection::poll_io_action(self : PeerConnection) -> IoAction? {
  match self.io_actions.pop() {
    Some(action) => Some(action)
    None =>
      match self.outbound.pop() {
        Some(datagram) => Some(SendDatagram(datagram))
        None => None
      }
  }
}

///|
pub fn PeerConnection::handle_mdns_datagram(
  self : PeerConnection,
  datagram : InboundDatagram,
) -> Unit raise RtcError {
  if datagram.payload.length() < 4 {
    raise InvalidConfiguration("mDNS datagram is shorter than its header")
  }
  if (datagram.payload[2] & 0x80) != 0 {
    rtc_mdns(() => {
      self.mdns_resolver.handle_response(datagram.now, datagram.payload)
    })
  } else {
    match rtc_mdns(() => self.mdns_resolver.answer_query(datagram.payload)) {
      Some(payload) => {
        let local_address = match
          self.mdns_source_address(datagram.context.peer) {
          Some(address) => address
          None => datagram.context.local_address
        }
        self.queue_outbound({
          context: {
            local_address,
            peer: datagram.context.peer,
            ecn: datagram.context.ecn,
            protocol: Udp,
          },
          payload,
        })
      }
      None => ()
    }
  }
  self.drive(datagram.now)
}

///|
pub fn PeerConnection::handle_datagram(
  self : PeerConnection,
  datagram : InboundDatagram,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  self.bytes_received += datagram.payload.length().to_uint64()
  self.packets_received += 1UL
  let pending_mdns_response = !self.pending_mdns_candidates.is_empty() &&
    datagram.payload.length() >= 12 &&
    (datagram.payload[2] & 0x80) != 0
  if datagram.context.peer.port() == 5353 ||
    datagram.context.local_address.port() == 5353 ||
    pending_mdns_response {
    self.handle_mdns_datagram(datagram)
    return
  }
  for allocation in self.turn_allocations {
    if allocation.handles_context(datagram.context) {
      rtc_turn(() => allocation.handle_datagram(datagram))
      self.drive(datagram.now)
      return
    }
  }
  for gatherer in self.srflx_gatherers {
    if gatherer.handles_context(datagram.context) {
      rtc_ice(() => gatherer.handle_datagram(datagram))
      self.drive(datagram.now)
      return
    }
  }
  guard self.ice_agent is Some(agent) else {
    raise InvalidState("ICE transport has not started")
  }
  rtc_ice(() => agent.handle_datagram(datagram))
  self.drive(datagram.now)
}

///|
pub fn PeerConnection::poll_datagram(
  self : PeerConnection,
) -> OutboundDatagram? {
  self.outbound.pop()
}

///|
fn PeerConnection::assign_transport_cc(
  self : PeerConnection,
  packet : @rtp.Packet,
) -> @rtp.Packet raise RtcError {
  let mut extension_id : Byte? = None
  let mut is_rtx = false
  for section in self.local_media_sections {
    for encoding in section.encodings {
      if encoding.ssrc == Some(packet.ssrc()) {
        extension_id = section.twcc_extension_id
        break
      }
      if encoding.rtx_ssrc == Some(packet.ssrc()) {
        extension_id = section.twcc_extension_id
        is_rtx = true
        break
      }
    }
    if extension_id is Some(_) {
      break
    }
  }
  guard extension_id is Some(id) else { return packet }
  let extensions : Array[@rtp.HeaderExtension] = []
  let mut existing_sequence : UInt16? = None
  for extension in packet.extensions() {
    if extension.id() == id {
      if !is_rtx {
        existing_sequence = Some(
          @rtp.TransportCcExtension::unmarshal(extension.payload()).transport_sequence(),
        ) catch {
          _ => None
        }
        extensions.push(extension)
      }
    } else {
      extensions.push(extension)
    }
  }
  match existing_sequence {
    Some(sequence) => {
      self.next_transport_sequence = sequence + 1
      return packet
    }
    None => ()
  }
  let sequence = self.next_transport_sequence
  self.next_transport_sequence += 1
  extensions.push(
    rtc_rtp(() => {
      @rtp.HeaderExtension::new(
        id~,
        payload=@rtp.TransportCcExtension::new(transport_sequence=sequence).marshal(),
      )
    }),
  )
  rtc_rtp(() => {
    @rtp.Packet::new(
      marker=packet.marker(),
      payload_type=packet.payload_type(),
      sequence_number=packet.sequence_number(),
      timestamp=packet.timestamp(),
      ssrc=packet.ssrc(),
      csrc=packet.csrc(),
      extensions~,
      payload=packet.payload(),
    )
  })
}

///|
fn PeerConnection::transform_rtp_payload(
  self : PeerConnection,
  packet : @rtp.Packet,
  direction : @media.TransformDirection,
  track_id : String?,
  codec : @media.CodecCapability,
) -> @rtp.Packet raise RtcError {
  if self.configuration.encoded_transform_pipeline.length() == 0 {
    return packet
  }
  let transformed = rtc_media(() => {
    self.configuration.encoded_transform_pipeline.process(
      @media.EncodedFrameContext::new(
        direction~,
        track_id?,
        codec~,
        ssrc=packet.ssrc(),
        sequence_number=packet.sequence_number(),
        timestamp=packet.timestamp(),
        marker=packet.marker(),
      ),
      packet.payload(),
    )
  })
  rtc_rtp(() => {
    @rtp.Packet::new(
      marker=packet.marker(),
      payload_type=packet.payload_type(),
      sequence_number=packet.sequence_number(),
      timestamp=packet.timestamp(),
      ssrc=packet.ssrc(),
      csrc=packet.csrc(),
      extensions=packet.extensions(),
      payload=transformed,
    )
  })
}

///|
fn PeerConnection::send_media_through_interceptors(
  self : PeerConnection,
  packet : @interceptor.Packet,
  stream_id : String?,
) -> Unit raise RtcError {
  guard self.outbound_srtp is Some(context) && self.ice_agent is Some(agent) else {
    raise InvalidState("secure media transport is not connected")
  }
  let outputs = rtc_interceptor(() => {
    self.configuration.interceptor_pipeline.process(
      @interceptor.Context::new(direction=Outbound, stream_id?),
      packet,
    )
  })
  for output in outputs {
    let prepared : @interceptor.Packet = match output {
      Rtp(rtp_packet) => Rtp(self.assign_transport_cc(rtp_packet))
      Rtcp(_) => output
    }
    let encrypted = match prepared {
      Rtp(rtp_packet) => rtc_srtp(() => context.protect_rtp(rtp_packet))
      Rtcp(rtcp_packet) => rtc_srtp(() => context.protect_rtcp([rtcp_packet]))
    }
    rtc_ice(() => agent.send(encrypted))
  }
}

///|
fn wall_time_to_ntp(timestamp : WallTime) -> UInt64 {
  let nanoseconds = timestamp.as_unix_nanoseconds()
  if nanoseconds < 0L {
    return 0UL
  }
  let unix_seconds = nanoseconds / 1000000000L
  let remainder = nanoseconds % 1000000000L
  let ntp_seconds = unix_seconds + 2208988800L
  let fraction = remainder * 4294967296L / 1000000000L
  (ntp_seconds.reinterpret_as_uint64() << 32) | fraction.reinterpret_as_uint64()
}

///|
fn PeerConnection::emit_rtcp_reports(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if !self.media_started {
    return
  }
  let wall = self.clock_sample.wall_at(now) catch {
    _ => self.clock_sample.wall()
  }
  let ntp_timestamp = wall_time_to_ntp(wall)
  for section in self.local_media_sections {
    match section.control {
      Some(control) if control.sender_report.packet_count() > 0U => {
        let report = rtc_interceptor(() => {
          control.sender_report.report(ntp_timestamp)
        })
        self.send_media_through_interceptors(
          Rtcp(rtc_rtcp(() => report.to_packet())),
          None,
        )
      }
      _ => ()
    }
    for control in section.additional_controls {
      if control.sender_report.packet_count() > 0U {
        let report = rtc_interceptor(() => {
          control.sender_report.report(ntp_timestamp)
        })
        self.send_media_through_interceptors(
          Rtcp(rtc_rtcp(() => report.to_packet())),
          None,
        )
      }
    }
  }
  for section in self.remote_media_sections {
    match section.control {
      Some(control) => {
        let report = rtc_interceptor(() => {
          control.receiver_report.report(now.as_milliseconds())
        })
        self.send_media_through_interceptors(
          Rtcp(rtc_rtcp(() => report.to_packet())),
          None,
        )
      }
      None => ()
    }
    for control in section.additional_controls {
      let report = rtc_interceptor(() => {
        control.receiver_report.report(now.as_milliseconds())
      })
      self.send_media_through_interceptors(
        Rtcp(rtc_rtcp(() => report.to_packet())),
        None,
      )
    }
  }
  match self.remote_twcc_recorder {
    Some(recorder) =>
      match rtc_interceptor(() => recorder.poll_feedback()) {
        Some(feedback) =>
          self.send_media_through_interceptors(
            Rtcp(rtc_rtcp(() => feedback.to_packet())),
            None,
          )
        None => ()
      }
    None => ()
  }
  self.next_rtcp_report = Some(now.checked_add(Duration::milliseconds(1000L))) catch {
    _ => None
  }
}

///|
pub fn PeerConnection::handle_message(
  self : PeerConnection,
  message : RtcMessage,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    raise Closed
  }
  match message {
    DataChannel(channel_id~, message~) => {
      guard self.data_transport is Some(transport) else {
        raise InvalidState("data transport is not connected")
      }
      rtc_datachannel(() => transport.send(channel_id, message, now))
      self.drive(now)
    }
    Rtp(track_id~, packet~) => {
      let mut matched = false
      let mut outbound_packet = packet
      for section in self.local_media_sections {
        match section.track {
          Some(track) if track.id() == track_id => {
            let mut selected_encoding : @media.RtpEncodingParameters? = None
            for encoding in section.encodings {
              if encoding.ssrc == Some(packet.ssrc()) &&
                encoding.payload_type == Some(packet.payload_type()) {
                selected_encoding = Some(encoding)
                break
              }
            }
            guard selected_encoding is Some(encoding) else {
              raise InvalidConfiguration(
                "RTP packet SSRC or payload type does not match its track",
              )
            }
            if !encoding.active {
              raise InvalidState("RTP encoding is paused")
            }
            outbound_packet = self.transform_rtp_payload(
              packet,
              TransformOutbound,
              Some(track_id),
              section.codec,
            )
            match local_control_for_ssrc(section, packet.ssrc()) {
              Some(control) => {
                control.sender_report.observe(outbound_packet)
                match control.rtx_sender {
                  Some(sender) => sender.remember(outbound_packet)
                  None => ()
                }
              }
              None => ()
            }
            matched = true
            break
          }
          _ => ()
        }
      }
      if !matched {
        raise InvalidState("RTP track is not attached")
      }
      self.send_media_through_interceptors(Rtp(outbound_packet), Some(track_id))
      self.drive(now)
    }
    Rtcp(packet) => {
      self.send_media_through_interceptors(Rtcp(packet), None)
      self.drive(now)
    }
  }
}

///|
pub fn PeerConnection::poll_message(self : PeerConnection) -> RtcMessage? {
  self.messages.pop()
}

///|
pub fn PeerConnection::poll_event(self : PeerConnection) -> PeerEvent? {
  self.events.pop()
}

///|
pub fn PeerConnection::poll_timeout(self : PeerConnection) -> Instant? {
  let mut result = self.mdns_resolver.poll_timeout()
  for gatherer in self.srflx_gatherers {
    result = minimum_instant(result, gatherer.poll_timeout())
  }
  for allocation in self.turn_allocations {
    result = minimum_instant(result, allocation.poll_timeout())
  }
  match self.ice_agent {
    Some(agent) => result = minimum_instant(result, agent.poll_timeout())
    None => ()
  }
  match self.dtls_endpoint {
    Some(endpoint) => result = minimum_instant(result, endpoint.poll_timeout())
    None => ()
  }
  match self.data_transport {
    Some(transport) =>
      result = minimum_instant(result, transport.poll_timeout())
    None => ()
  }
  result = minimum_instant(result, self.next_rtcp_report)
  result
}

///|
pub fn PeerConnection::handle_timeout(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    return
  }
  rtc_mdns(() => self.mdns_resolver.handle_timeout(now))
  for gatherer in self.srflx_gatherers {
    gatherer.handle_timeout(now) catch {
      ChecklistFailed => ()
      error => raise Ice(error)
    }
  }
  for allocation in self.turn_allocations {
    allocation.handle_timeout(now) catch {
      error =>
        if self.configuration.ice_transport_policy == Relay {
          raise Turn(error)
        }
    }
  }
  match self.ice_agent {
    Some(agent) => rtc_ice(() => agent.handle_timeout(now))
    None => ()
  }
  match self.dtls_endpoint {
    Some(endpoint) => rtc_dtls(() => endpoint.handle_timeout(now))
    None => ()
  }
  match self.data_transport {
    Some(transport) => rtc_datachannel(() => transport.handle_timeout(now))
    None => ()
  }
  match self.next_rtcp_report {
    Some(deadline) if deadline <= now => self.emit_rtcp_reports(now)
    _ => ()
  }
  self.drive(now)
}

///|
pub fn PeerConnection::stats(
  self : PeerConnection,
  now : Instant,
) -> StatsReport {
  let timestamp = self.clock_sample.wall_at(now) catch {
    _ => self.clock_sample.wall()
  }
  let mut packets_lost = 0UL
  for section in self.remote_media_sections {
    match section.control {
      Some(control) => packets_lost += control.receiver_report.packets_lost()
      None => ()
    }
    for control in section.additional_controls {
      packets_lost += control.receiver_report.packets_lost()
    }
  }
  {
    timestamp,
    bytes_sent: self.bytes_sent,
    bytes_received: self.bytes_received,
    packets_sent: self.packets_sent,
    packets_received: self.packets_received,
    packets_lost,
    data_channels_opened: self.data_channels_opened,
    data_channels_closed: self.data_channels_closed,
  }
}

///|
pub fn PeerConnection::detailed_stats(
  self : PeerConnection,
  now : Instant,
) -> DetailedStatsReport {
  let timestamp = self.clock_sample.wall_at(now) catch {
    _ => self.clock_sample.wall()
  }
  let codecs : Array[CodecStats] = []
  let outbound_rtp : Array[RtpStreamStats] = []
  for section in self.local_media_sections {
    guard section.track is Some(track) else { continue }
    let codec_id = "codec-out-" + section.payload_type.to_uint().to_string()
    if !codecs.any(codec => codec.id == codec_id) {
      codecs.push({
        id: codec_id,
        payload_type: section.payload_type,
        mime_type: section.codec.mime_type(),
        clock_rate: section.codec.clock_rate(),
        channels: section.codec.channels(),
        fmtp: section.codec.fmtp(),
      })
    }
    for encoding in section.encodings {
      guard encoding.ssrc is Some(ssrc) else { continue }
      let (packets, bytes, retransmitted_packets, retransmitted_bytes) = match
        local_control_for_ssrc(section, ssrc) {
        Some(control) => {
          let (rtx_packets, rtx_bytes) = match control.rtx_sender {
            Some(sender) =>
              (sender.retransmitted_packets(), sender.retransmitted_bytes())
            None => (0UL, 0UL)
          }
          (
            control.sender_report.packet_count().to_uint64(),
            control.sender_report.octet_count().to_uint64(),
            rtx_packets,
            rtx_bytes,
          )
        }
        None => (0UL, 0UL, 0UL, 0UL)
      }
      outbound_rtp.push({
        id: "outbound-rtp-" + ssrc.to_string(),
        track_id: track.id(),
        kind: track.kind(),
        outbound: true,
        ssrc,
        rid: encoding.rid,
        codec_id,
        packets,
        bytes,
        packets_lost: 0UL,
        jitter: 0UL,
        retransmitted_packets,
        retransmitted_bytes,
        active: encoding.active,
      })
    }
  }
  let inbound_rtp : Array[RtpStreamStats] = []
  for section in self.remote_media_sections {
    guard section.track is Some(track) else { continue }
    let codec_id = "codec-in-" + section.payload_type.to_uint().to_string()
    if !codecs.any(codec => codec.id == codec_id) {
      codecs.push({
        id: codec_id,
        payload_type: section.payload_type,
        mime_type: track.codec().mime_type(),
        clock_rate: track.codec().clock_rate(),
        channels: track.codec().channels(),
        fmtp: track.codec().fmtp(),
      })
    }
    for encoding in section.encodings {
      guard encoding.ssrc is Some(ssrc) else { continue }
      let (packets, bytes, lost, jitter) = match
        remote_control_for_ssrc(section, ssrc) {
        Some(control) =>
          (
            control.receiver_report.packet_count().to_uint64(),
            control.receiver_report.octet_count(),
            control.receiver_report.packets_lost(),
            control.receiver_report.jitter(),
          )
        None => (0UL, 0UL, 0UL, 0UL)
      }
      inbound_rtp.push({
        id: "inbound-rtp-" + ssrc.to_string(),
        track_id: track.id(),
        kind: track.kind(),
        outbound: false,
        ssrc,
        rid: encoding.rid,
        codec_id,
        packets,
        bytes,
        packets_lost: lost,
        jitter,
        retransmitted_packets: 0UL,
        retransmitted_bytes: 0UL,
        active: encoding.active,
      })
    }
  }
  let candidate_pairs : Array[CandidatePairStats] = []
  let mut selected_candidate_pair_id : String? = None
  let ice_state = match self.ice_agent {
    Some(agent) => {
      let selected = agent.selected_pair()
      let pairs = agent.candidate_pairs()
      for index = 0; index < pairs.length(); index = index + 1 {
        let pair = pairs[index]
        let id = "candidate-pair-" + index.to_string()
        let is_selected = selected == Some(pair)
        if is_selected {
          selected_candidate_pair_id = Some(id)
        }
        candidate_pairs.push({
          id,
          local_candidate: pair.local_candidate(),
          remote_candidate: pair.remote_candidate(),
          priority: pair.priority(),
          state: pair.state(),
          nominated: pair.is_nominated(),
          selected: is_selected,
        })
      }
      agent.state()
    }
    None => New
  }
  let data_channels : Array[DataChannelStats] = []
  match self.data_manager {
    Some(manager) =>
      for channel in manager.all_channels() {
        data_channels.push({
          id: "data-channel-" + channel.id().value().to_string(),
          stream_id: channel.id(),
          label: channel.label(),
          protocol: channel.protocol(),
          state: channel.state(),
          buffered_amount: self.data_channel_buffered_amount(channel.id()),
        })
      }
    None => ()
  }
  let dtls_state = self.dtls_endpoint.map(endpoint => endpoint.state())
  {
    timestamp,
    codecs,
    outbound_rtp,
    inbound_rtp,
    candidate_pairs,
    data_channels,
    transport: {
      id: "transport-0",
      ice_state,
      dtls_state,
      selected_candidate_pair_id,
      bytes_sent: self.bytes_sent,
      bytes_received: self.bytes_received,
      packets_sent: self.packets_sent,
      packets_received: self.packets_received,
    },
  }
}

///|
pub fn PeerConnection::close(
  self : PeerConnection,
  now : Instant,
) -> Unit raise RtcError {
  if self.state == Closed {
    return
  }
  self.closing = true
  self.next_rtcp_report = None
  self.remote_twcc_recorder = None
  match self.data_transport {
    Some(transport) => rtc_datachannel(() => transport.close(now))
    None => ()
  }
  match self.outbound_srtp {
    Some(context) => context.close()
    None => ()
  }
  match self.inbound_srtp {
    Some(context) => context.close()
    None => ()
  }
  self.drive(now)
  match self.dtls_endpoint {
    Some(endpoint) => rtc_dtls(() => endpoint.close())
    None => ()
  }
  self.drive(now)
  match self.ice_agent {
    Some(agent) => agent.close()
    None => ()
  }
  for gatherer in self.srflx_gatherers {
    gatherer.close()
  }
  for allocation in self.turn_allocations {
    rtc_turn(() => allocation.close(now))
  }
  self.drive(now)
  for stream in self.pending_streams {
    self.io_actions.push(CloseStream(stream.connection))
  }
  for stream in self.active_streams {
    self.io_actions.push(CloseStream(stream.connection))
  }
  for listener in self.active_listeners {
    self.io_actions.push(CloseListener(listener.listener))
  }
  self.pending_streams.clear()
  self.active_streams.clear()
  self.active_listeners.clear()
  self.signaling.close()
  self.state = Closed
  self.enqueue_event(SignalingStateChanged(Closed))
  self.enqueue_event(ConnectionStateChanged(Closed))
  self.enqueue_event(Closed)
}

///|
pub fn PeerConnection::connection_state(
  self : PeerConnection,
) -> PeerConnectionState {
  self.state
}

///|
pub fn PeerConnection::signaling_state(self : PeerConnection) -> SignalingState {
  self.signaling.state()
}

///|
pub fn PeerConnection::local_description(
  self : PeerConnection,
) -> SessionDescription? {
  self.signaling.local_description()
}

///|
pub fn PeerConnection::remote_description(
  self : PeerConnection,
) -> SessionDescription? {
  self.signaling.remote_description()
}

///|
pub fn PeerConnection::local_host_candidates(
  self : PeerConnection,
) -> Array[IceCandidate] {
  self.configuration.host_candidates()
}

///|
pub fn PeerConnection::driver_command_capacity(self : PeerConnection) -> Int {
  self.configuration.command_capacity()
}

///|
pub fn PeerConnection::driver_event_capacity(self : PeerConnection) -> Int {
  self.configuration.event_capacity()
}

///|
pub fn PeerConnection::driver_message_capacity(self : PeerConnection) -> Int {
  self.configuration.message_capacity()
}

///|
pub fn PeerConnection::driver_receive_mtu(self : PeerConnection) -> Int {
  self.configuration.settings.receive_mtu
}
