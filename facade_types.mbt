///|
pub using @transport {
  type ClockSample,
  type ConnectionId,
  type Duration,
  type EcnCodepoint,
  type InboundDatagram,
  type Instant,
  type IoAction,
  type IoEvent,
  type IpAddress,
  type ListenerId,
  type ManualClock,
  type OutboundDatagram,
  type SocketAddress,
  type TransportContext,
  type TransportProtocol,
  type WallTime,
}

///|
pub using @sdp {type SdpType, type SessionDescription, type SignalingState}

///|
pub using @ice {
  type CandidateType,
  type IceCandidate,
  type IceConnectionState,
  type IceGatheringState,
  type IceRole,
  type IceTransportPolicy,
  type TcpCandidateType,
}

///|
pub using @turn {type TurnTransport}

///|
pub using @datachannel {
  type DataChannel,
  type DataChannelConfig,
  type DataChannelMessage,
  type DataChannelState,
}

///|
pub using @media {
  type CodecCapability,
  type EncodedFrameContext,
  type EncodedTransform,
  type EncodedTransformPipeline,
  type MediaKind,
  type MediaTrack,
  type RtpEncodingParameters,
  type RtpParameters,
  type RtpReceiver,
  type RtpSender,
  type RtpTransceiver,
  type TransformDirection,
  type TransceiverDirection,
}

///|
pub using @interceptor {type Context, type Direction, type Pipeline, type Stage}

///|
pub(all) suberror RtcError {
  InvalidConfiguration(String)
  InvalidState(String)
  BackpressureExceeded
  CryptoUnavailable(String)
  Sdp(@sdp.SdpError)
  Stun(@stun.StunError)
  Turn(@turn.TurnError)
  Mdns(@mdns.MdnsError)
  Ice(@ice.IceError)
  Dtls(@dtls.DtlsError)
  Srtp(@srtp.SrtpError)
  Sctp(@sctp.SctpError)
  DataChannel(@datachannel.DataChannelError)
  Interceptor(@interceptor.InterceptorError)
  Closed
} derive(Debug, Eq)

///|
pub(all) enum PeerConnectionState {
  New
  Connecting
  Connected
  Disconnected
  Failed
  Closed
} derive(Debug, Eq)

///|
pub(all) enum OfferCollisionPolicy {
  Polite
  Impolite
} derive(Debug, Eq)

///|
pub(all) struct IceServer {
  urls : Array[String]
  username : String?
  credential : String?
} derive(Debug, Eq)

///|
pub fn IceServer::new(
  urls~ : Array[String],
  username? : String,
  credential? : String,
) -> IceServer raise RtcError {
  if urls.is_empty() || urls.any(url => url.is_empty()) {
    raise InvalidConfiguration("ICE server URLs must be nonempty")
  }
  if (username is Some(_)) != (credential is Some(_)) {
    raise InvalidConfiguration(
      "ICE server username and credential must appear together",
    )
  }
  { urls: urls.copy(), username, credential }
}

///|
pub fn IceServer::urls(self : IceServer) -> Array[String] {
  self.urls.copy()
}

///|
pub fn IceServer::username(self : IceServer) -> String? {
  self.username
}

///|
pub fn IceServer::credential(self : IceServer) -> String? {
  self.credential
}

///|
fn settings_duration(
  milliseconds : Int64,
  name : String,
) -> Duration raise RtcError {
  Duration::milliseconds(milliseconds) catch {
    _ => raise InvalidConfiguration("\{name} is outside the supported range")
  }
}

///|
pub struct Settings {
  ice_credentials : @ice.IceCredentials?
  ice_check_interval : Duration
  ice_initial_rto : Duration
  ice_reliable_timeout : Duration
  ice_max_retransmissions : Int
  ice_disconnected_timeout : Duration
  ice_failed_timeout : Duration
  ice_keepalive_interval : Duration
  mdns_retry_interval : Duration
  mdns_query_timeout : Duration
  mdns_local_name : String?
  answering_dtls_role : @dtls.Role?
  verify_peer_fingerprint : Bool
  dtls_certificate_key_type : @dtls.CertificateKeyType
  dtls_cipher_suites : Array[@dtls.CipherSuite]
  dtls_psk : Bytes?
  dtls_psk_identity : Bytes?
  dtls_srtp_profiles : Array[@dtls.SrtpProtectionProfile]
  dtls_flight_interval : Duration
  dtls_mtu : Int
  dtls_replay_window : Int
  srtp_replay_window : Int
  srtcp_replay_window : Int
  sctp_max_payload_size : Int
  sctp_send_buffer_size : UInt64
  sctp_receive_buffer_size : UInt
  sctp_initial_rto : Duration
  receive_mtu : Int
  ignore_rid_pause_for_recv : Bool
  write_ssrc_attributes_for_simulcast : Bool
}

///|
pub fn Settings::new(
  ice_credentials? : @ice.IceCredentials,
  ice_check_interval? : Duration,
  ice_initial_rto? : Duration,
  ice_reliable_timeout? : Duration,
  ice_max_retransmissions? : Int = 7,
  ice_disconnected_timeout? : Duration,
  ice_failed_timeout? : Duration,
  ice_keepalive_interval? : Duration,
  mdns_retry_interval? : Duration,
  mdns_query_timeout? : Duration,
  mdns_local_name? : String,
  answering_dtls_role? : @dtls.Role,
  verify_peer_fingerprint? : Bool = true,
  dtls_certificate_key_type? : @dtls.CertificateKeyType = EcdsaCertificate,
  dtls_cipher_suites? : Array[@dtls.CipherSuite] = [],
  dtls_psk? : Bytes,
  dtls_psk_identity? : Bytes,
  dtls_srtp_profiles? : Array[@dtls.SrtpProtectionProfile] = [
    @dtls.SrtpProtectionProfile::aes128_cm_hmac_sha1_80(),
  ],
  dtls_flight_interval? : Duration,
  dtls_mtu? : Int = 1200,
  dtls_replay_window? : Int = 64,
  srtp_replay_window? : Int = 64,
  srtcp_replay_window? : Int = 64,
  sctp_max_payload_size? : Int = 1000,
  sctp_send_buffer_size? : UInt64 = 1048576UL,
  sctp_receive_buffer_size? : UInt = 1048576U,
  sctp_initial_rto? : Duration,
  receive_mtu? : Int = 1460,
  ignore_rid_pause_for_recv? : Bool = false,
  write_ssrc_attributes_for_simulcast? : Bool = true,
) -> Settings raise RtcError {
  let ice_check_interval = ice_check_interval.unwrap_or(
    settings_duration(50L, "ICE check interval"),
  )
  let ice_initial_rto = ice_initial_rto.unwrap_or(
    settings_duration(500L, "ICE initial RTO"),
  )
  let ice_reliable_timeout = ice_reliable_timeout.unwrap_or(
    settings_duration(39500L, "ICE reliable transport timeout"),
  )
  let ice_disconnected_timeout = ice_disconnected_timeout.unwrap_or(
    settings_duration(5000L, "ICE disconnected timeout"),
  )
  let ice_failed_timeout = ice_failed_timeout.unwrap_or(
    settings_duration(25000L, "ICE failed timeout"),
  )
  let ice_keepalive_interval = ice_keepalive_interval.unwrap_or(
    settings_duration(2000L, "ICE keepalive interval"),
  )
  let mdns_retry_interval = mdns_retry_interval.unwrap_or(
    settings_duration(1000L, "mDNS retry interval"),
  )
  let mdns_query_timeout = mdns_query_timeout.unwrap_or(
    settings_duration(5000L, "mDNS query timeout"),
  )
  let dtls_flight_interval = dtls_flight_interval.unwrap_or(
    settings_duration(1000L, "DTLS flight interval"),
  )
  let sctp_initial_rto = sctp_initial_rto.unwrap_or(
    settings_duration(1000L, "SCTP initial RTO"),
  )
  if ice_check_interval.as_milliseconds() <= 0L ||
    ice_initial_rto.as_milliseconds() <= 0L ||
    ice_reliable_timeout.as_milliseconds() <= 0L ||
    ice_disconnected_timeout.as_milliseconds() <= 0L ||
    ice_failed_timeout.as_milliseconds() <= 0L ||
    ice_keepalive_interval.as_milliseconds() <= 0L ||
    mdns_retry_interval.as_milliseconds() <= 0L ||
    mdns_query_timeout.as_milliseconds() <= 0L ||
    dtls_flight_interval.as_milliseconds() <= 0L ||
    sctp_initial_rto.as_milliseconds() <= 0L {
    raise InvalidConfiguration("settings durations must be positive")
  }
  if ice_max_retransmissions < 0 || ice_max_retransmissions > 32 {
    raise InvalidConfiguration(
      "ICE maximum retransmissions must be between 0 and 32",
    )
  }
  match mdns_local_name {
    Some(name) =>
      if name.is_empty() || !name.to_lower().has_suffix(".local") {
        raise InvalidConfiguration(
          "the static mDNS local name must end in .local",
        )
      }
    None => ()
  }
  match answering_dtls_role {
    Some(Auto) =>
      raise InvalidConfiguration("the answering DTLS role cannot be Auto")
    _ => ()
  }
  if (dtls_psk is Some(_)) != (dtls_psk_identity is Some(_)) {
    raise InvalidConfiguration("DTLS PSK and PSK identity must appear together")
  }
  match (dtls_psk, dtls_psk_identity) {
    (Some(key), Some(identity)) =>
      if key.is_empty() || identity.is_empty() {
        raise InvalidConfiguration("DTLS PSK and PSK identity must be nonempty")
      }
    _ => ()
  }
  let dtls_cipher_suites = if dtls_cipher_suites.is_empty() {
    if dtls_psk is Some(_) {
      [@dtls.PskAes128GcmSha256, PskAes128Ccm, PskAes128Ccm8]
    } else {
      match dtls_certificate_key_type {
        EcdsaCertificate =>
          [
            EcdheEcdsaAes128GcmSha256,
            EcdheEcdsaAes256CbcSha,
            EcdheEcdsaChacha20Poly1305Sha256,
            EcdheEcdsaAes128Ccm,
            EcdheEcdsaAes128Ccm8,
          ]
        RsaCertificate =>
          [
            EcdheRsaAes128GcmSha256,
            EcdheRsaAes256CbcSha,
            EcdheRsaChacha20Poly1305Sha256,
          ]
      }
    }
  } else {
    dtls_cipher_suites.copy()
  }
  let seen_cipher_suites : Array[@dtls.CipherSuite] = []
  for suite in dtls_cipher_suites {
    if seen_cipher_suites.contains(suite) {
      raise InvalidConfiguration("DTLS cipher suites must be unique")
    }
    seen_cipher_suites.push(suite)
    if suite.is_psk() != (dtls_psk is Some(_)) {
      raise InvalidConfiguration(
        "DTLS PSK credentials and cipher suites do not match",
      )
    }
    if !suite.is_psk() {
      let certificate_matches = match dtls_certificate_key_type {
        EcdsaCertificate => !suite.uses_rsa()
        RsaCertificate => suite.uses_rsa()
      }
      if !certificate_matches {
        raise InvalidConfiguration(
          "DTLS certificate key type and cipher suites do not match",
        )
      }
    }
  }
  let seen_srtp_profiles : Array[@dtls.SrtpProtectionProfile] = []
  for profile in dtls_srtp_profiles {
    if seen_srtp_profiles.contains(profile) {
      raise InvalidConfiguration("DTLS SRTP profiles must be unique")
    }
    seen_srtp_profiles.push(profile)
  }
  if dtls_mtu < 256 || dtls_mtu > 65535 {
    raise InvalidConfiguration("DTLS MTU must be between 256 and 65535")
  }
  if dtls_replay_window < 1 ||
    dtls_replay_window > 64 ||
    srtp_replay_window < 1 ||
    srtp_replay_window > 64 ||
    srtcp_replay_window < 1 ||
    srtcp_replay_window > 64 {
    raise InvalidConfiguration(
      "replay protection windows must be between 1 and 64",
    )
  }
  if sctp_max_payload_size < 1 || sctp_max_payload_size > 0xffef {
    raise InvalidConfiguration("SCTP payload size is outside its wire bounds")
  }
  if sctp_send_buffer_size == 0UL {
    raise InvalidConfiguration("SCTP send buffer size must be nonzero")
  }
  if sctp_receive_buffer_size < 1500U {
    raise InvalidConfiguration(
      "SCTP receive buffer must be at least 1500 bytes",
    )
  }
  if receive_mtu < 256 || receive_mtu > 65535 {
    raise InvalidConfiguration("receive MTU must be between 256 and 65535")
  }
  {
    ice_credentials,
    ice_check_interval,
    ice_initial_rto,
    ice_reliable_timeout,
    ice_max_retransmissions,
    ice_disconnected_timeout,
    ice_failed_timeout,
    ice_keepalive_interval,
    mdns_retry_interval,
    mdns_query_timeout,
    mdns_local_name,
    answering_dtls_role,
    verify_peer_fingerprint,
    dtls_certificate_key_type,
    dtls_cipher_suites,
    dtls_psk,
    dtls_psk_identity,
    dtls_srtp_profiles: dtls_srtp_profiles.copy(),
    dtls_flight_interval,
    dtls_mtu,
    dtls_replay_window,
    srtp_replay_window,
    srtcp_replay_window,
    sctp_max_payload_size,
    sctp_send_buffer_size,
    sctp_receive_buffer_size,
    sctp_initial_rto,
    receive_mtu,
    ignore_rid_pause_for_recv,
    write_ssrc_attributes_for_simulcast,
  }
}

///|
pub fn Settings::ice_credentials(self : Settings) -> @ice.IceCredentials? {
  self.ice_credentials
}

///|
pub fn Settings::ice_check_interval(self : Settings) -> Duration {
  self.ice_check_interval
}

///|
pub fn Settings::ice_initial_rto(self : Settings) -> Duration {
  self.ice_initial_rto
}

///|
pub fn Settings::ice_reliable_timeout(self : Settings) -> Duration {
  self.ice_reliable_timeout
}

///|
pub fn Settings::ice_max_retransmissions(self : Settings) -> Int {
  self.ice_max_retransmissions
}

///|
pub fn Settings::ice_disconnected_timeout(self : Settings) -> Duration {
  self.ice_disconnected_timeout
}

///|
pub fn Settings::ice_failed_timeout(self : Settings) -> Duration {
  self.ice_failed_timeout
}

///|
pub fn Settings::ice_keepalive_interval(self : Settings) -> Duration {
  self.ice_keepalive_interval
}

///|
pub fn Settings::mdns_retry_interval(self : Settings) -> Duration {
  self.mdns_retry_interval
}

///|
pub fn Settings::mdns_query_timeout(self : Settings) -> Duration {
  self.mdns_query_timeout
}

///|
pub fn Settings::mdns_local_name(self : Settings) -> String? {
  self.mdns_local_name
}

///|
pub fn Settings::answering_dtls_role(self : Settings) -> @dtls.Role? {
  self.answering_dtls_role
}

///|
pub fn Settings::verify_peer_fingerprint(self : Settings) -> Bool {
  self.verify_peer_fingerprint
}

///|
pub fn Settings::dtls_certificate_key_type(
  self : Settings,
) -> @dtls.CertificateKeyType {
  self.dtls_certificate_key_type
}

///|
pub fn Settings::dtls_cipher_suites(
  self : Settings,
) -> Array[@dtls.CipherSuite] {
  self.dtls_cipher_suites.copy()
}

///|
pub fn Settings::dtls_psk(self : Settings) -> Bytes? {
  self.dtls_psk
}

///|
pub fn Settings::dtls_psk_identity(self : Settings) -> Bytes? {
  self.dtls_psk_identity
}

///|
pub fn Settings::dtls_srtp_profiles(
  self : Settings,
) -> Array[@dtls.SrtpProtectionProfile] {
  self.dtls_srtp_profiles.copy()
}

///|
pub fn Settings::dtls_flight_interval(self : Settings) -> Duration {
  self.dtls_flight_interval
}

///|
pub fn Settings::dtls_mtu(self : Settings) -> Int {
  self.dtls_mtu
}

///|
pub fn Settings::dtls_replay_window(self : Settings) -> Int {
  self.dtls_replay_window
}

///|
pub fn Settings::srtp_replay_window(self : Settings) -> Int {
  self.srtp_replay_window
}

///|
pub fn Settings::srtcp_replay_window(self : Settings) -> Int {
  self.srtcp_replay_window
}

///|
pub fn Settings::sctp_max_payload_size(self : Settings) -> Int {
  self.sctp_max_payload_size
}

///|
pub fn Settings::sctp_send_buffer_size(self : Settings) -> UInt64 {
  self.sctp_send_buffer_size
}

///|
pub fn Settings::sctp_receive_buffer_size(self : Settings) -> UInt {
  self.sctp_receive_buffer_size
}

///|
pub fn Settings::sctp_initial_rto(self : Settings) -> Duration {
  self.sctp_initial_rto
}

///|
pub fn Settings::receive_mtu(self : Settings) -> Int {
  self.receive_mtu
}

///|
pub fn Settings::ignore_rid_pause_for_recv(self : Settings) -> Bool {
  self.ignore_rid_pause_for_recv
}

///|
pub fn Settings::write_ssrc_attributes_for_simulcast(self : Settings) -> Bool {
  self.write_ssrc_attributes_for_simulcast
}

///|
pub struct Configuration {
  ice_servers : Array[IceServer]
  ice_transport_policy : @ice.IceTransportPolicy
  mdns_mode : @mdns.Mode
  host_candidates : Array[IceCandidate]
  sctp_port : UInt16
  max_message_size : UInt64
  command_capacity : Int
  event_capacity : Int
  message_capacity : Int
  settings : Settings
  interceptor_pipeline : @interceptor.Pipeline
  encoded_transform_pipeline : @media.EncodedTransformPipeline
}

///|
pub fn Configuration::new(
  ice_servers? : Array[IceServer] = [],
  ice_transport_policy? : @ice.IceTransportPolicy = All,
  mdns_mode? : @mdns.Mode = QueryOnly,
  host_candidates? : Array[IceCandidate] = [],
  sctp_port? : UInt16 = 5000,
  max_message_size? : UInt64 = 262144UL,
  command_capacity? : Int = 64,
  event_capacity? : Int = 256,
  message_capacity? : Int = 1024,
  settings? : Settings,
  interceptor_pipeline? : @interceptor.Pipeline = @interceptor.Pipeline::new(),
  encoded_transform_pipeline? : @media.EncodedTransformPipeline = @media.EncodedTransformPipeline::new(),
) -> Configuration raise RtcError {
  let settings = settings.unwrap_or(Settings::new())
  if command_capacity < 1 || event_capacity < 1 || message_capacity < 1 {
    raise InvalidConfiguration(
      "command, event, and message capacities must be positive",
    )
  }
  if sctp_port == 0 || max_message_size == 0UL {
    raise InvalidConfiguration(
      "SCTP port and maximum message size must be nonzero",
    )
  }
  for candidate in host_candidates {
    if candidate.candidate_type() != Host || candidate.socket_address() is None {
      raise InvalidConfiguration(
        "host candidates must be resolved host transport candidates",
      )
    }
  }
  {
    ice_servers,
    ice_transport_policy,
    mdns_mode,
    host_candidates: host_candidates.copy(),
    sctp_port,
    max_message_size,
    command_capacity,
    event_capacity,
    message_capacity,
    settings,
    interceptor_pipeline,
    encoded_transform_pipeline,
  }
}

///|
pub fn Configuration::command_capacity(self : Configuration) -> Int {
  self.command_capacity
}

///|
pub fn Configuration::ice_servers(self : Configuration) -> Array[IceServer] {
  self.ice_servers.copy()
}

///|
pub fn Configuration::ice_transport_policy(
  self : Configuration,
) -> @ice.IceTransportPolicy {
  self.ice_transport_policy
}

///|
pub fn Configuration::mdns_mode(self : Configuration) -> @mdns.Mode {
  self.mdns_mode
}

///|
pub fn Configuration::event_capacity(self : Configuration) -> Int {
  self.event_capacity
}

///|
pub fn Configuration::message_capacity(self : Configuration) -> Int {
  self.message_capacity
}

///|
pub fn Configuration::settings(self : Configuration) -> Settings {
  self.settings
}

///|
pub fn Configuration::host_candidates(
  self : Configuration,
) -> Array[IceCandidate] {
  self.host_candidates.copy()
}

///|
pub fn Configuration::sctp_port(self : Configuration) -> UInt16 {
  self.sctp_port
}

///|
pub fn Configuration::max_message_size(self : Configuration) -> UInt64 {
  self.max_message_size
}

///|
pub fn Configuration::interceptor_pipeline(
  self : Configuration,
) -> @interceptor.Pipeline {
  self.interceptor_pipeline
}

///|
pub fn Configuration::encoded_transform_pipeline(
  self : Configuration,
) -> @media.EncodedTransformPipeline {
  self.encoded_transform_pipeline
}

///|
pub(all) enum RtcMessage {
  Rtp(track_id~ : String, packet~ : @rtp.Packet)
  Rtcp(@rtcp.Packet)
  DataChannel(channel_id~ : @sctp.StreamId, message~ : DataChannelMessage)
} derive(Debug, Eq)

///|
pub(all) enum PeerEvent {
  SignalingStateChanged(SignalingState)
  IceGatheringStateChanged(@ice.IceGatheringState)
  IceConnectionStateChanged(@ice.IceConnectionState)
  ConnectionStateChanged(PeerConnectionState)
  IceCandidateDiscovered(IceCandidate)
  TrackOpened(MediaTrack)
  TrackClosed(String)
  DataChannelOpened(DataChannel)
  DataChannelClosed(@sctp.StreamId)
  BufferedAmountLow(@sctp.StreamId)
  NegotiationNeeded
  Closed
} derive(Debug)

///|
pub(all) struct StatsReport {
  timestamp : WallTime
  bytes_sent : UInt64
  bytes_received : UInt64
  packets_sent : UInt64
  packets_received : UInt64
  packets_lost : UInt64
  data_channels_opened : UInt
  data_channels_closed : UInt
} derive(Debug, Eq)

///|
pub(all) struct CodecStats {
  id : String
  payload_type : Byte
  mime_type : String
  clock_rate : UInt
  channels : UInt16
  fmtp : String
} derive(Debug, Eq)

///|
pub(all) struct RtpStreamStats {
  id : String
  track_id : String
  kind : MediaKind
  outbound : Bool
  ssrc : UInt
  rid : String?
  codec_id : String
  packets : UInt64
  bytes : UInt64
  packets_lost : UInt64
  jitter : UInt64
  retransmitted_packets : UInt64
  retransmitted_bytes : UInt64
  active : Bool
} derive(Debug, Eq)

///|
pub(all) struct CandidatePairStats {
  id : String
  local_candidate : IceCandidate
  remote_candidate : IceCandidate
  priority : UInt64
  state : @ice.CandidatePairState
  nominated : Bool
  selected : Bool
} derive(Debug, Eq)

///|
pub(all) struct DataChannelStats {
  id : String
  stream_id : @sctp.StreamId
  label : String
  protocol : String
  state : DataChannelState
  buffered_amount : UInt64
} derive(Debug, Eq)

///|
pub(all) struct TransportStats {
  id : String
  ice_state : @ice.IceConnectionState
  dtls_state : @dtls.State?
  selected_candidate_pair_id : String?
  bytes_sent : UInt64
  bytes_received : UInt64
  packets_sent : UInt64
  packets_received : UInt64
} derive(Debug, Eq)

///|
pub(all) struct DetailedStatsReport {
  timestamp : WallTime
  codecs : Array[CodecStats]
  outbound_rtp : Array[RtpStreamStats]
  inbound_rtp : Array[RtpStreamStats]
  candidate_pairs : Array[CandidatePairStats]
  data_channels : Array[DataChannelStats]
  transport : TransportStats
} derive(Debug, Eq)
