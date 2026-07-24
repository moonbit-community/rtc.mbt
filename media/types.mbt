///|
pub(all) suberror MediaError {
  InvalidCodec(String)
  InvalidTrack(String)
  InvalidMedia(String)
  EndOfStream
} derive(Debug, Eq)

///|
pub(all) enum MediaKind {
  Audio
  Video
} derive(Debug, Eq)

///|
pub(all) enum TransceiverDirection {
  SendRecv
  SendOnly
  RecvOnly
  Inactive
  Stopped
} derive(Debug, Eq)

///|
pub(all) struct CodecCapability {
  mime_type : String
  clock_rate : UInt
  channels : UInt16
  fmtp : String
  rtcp_feedback : Array[String]
} derive(Debug, Eq)

///|
pub fn CodecCapability::new(
  mime_type~ : String,
  clock_rate~ : UInt,
  channels? : UInt16 = 1,
  fmtp? : String = "",
  rtcp_feedback? : Array[String] = [],
) -> CodecCapability raise MediaError {
  let normalized = mime_type.to_lower()
  if !(normalized.has_prefix("audio/") || normalized.has_prefix("video/")) ||
    normalized.length() <= 6 ||
    clock_rate == 0U ||
    channels == 0 {
    raise InvalidCodec("invalid media codec capability")
  }
  if fmtp.contains("\r") ||
    fmtp.contains("\n") ||
    rtcp_feedback.any(value => {
      value.is_empty() || value.contains("\r") || value.contains("\n")
    }) {
    raise InvalidCodec("codec parameters contain invalid line breaks")
  }
  {
    mime_type: normalized,
    clock_rate,
    channels,
    fmtp,
    rtcp_feedback: rtcp_feedback.copy(),
  }
}

///|
pub fn CodecCapability::mime_type(self : CodecCapability) -> String {
  self.mime_type
}

///|
pub fn CodecCapability::encoding_name(self : CodecCapability) -> String {
  match self.mime_type.split_once("/") {
    Some((_, encoding)) => encoding.to_owned()
    None => self.mime_type
  }
}

///|
pub fn CodecCapability::clock_rate(self : CodecCapability) -> UInt {
  self.clock_rate
}

///|
pub fn CodecCapability::channels(self : CodecCapability) -> UInt16 {
  self.channels
}

///|
pub fn CodecCapability::fmtp(self : CodecCapability) -> String {
  self.fmtp
}

///|
pub fn CodecCapability::rtcp_feedback(self : CodecCapability) -> Array[String] {
  self.rtcp_feedback.copy()
}

///|
pub struct MediaTrack {
  id : String
  stream_id : String
  kind : MediaKind
  codec : CodecCapability
} derive(Debug)

///|
pub fn MediaTrack::new(
  id~ : String,
  stream_id~ : String,
  kind~ : MediaKind,
  codec~ : CodecCapability,
) -> MediaTrack {
  { id, stream_id, kind, codec }
}

///|
pub fn MediaTrack::id(self : MediaTrack) -> String {
  self.id
}

///|
pub fn MediaTrack::stream_id(self : MediaTrack) -> String {
  self.stream_id
}

///|
pub fn MediaTrack::kind(self : MediaTrack) -> MediaKind {
  self.kind
}

///|
pub fn MediaTrack::codec(self : MediaTrack) -> CodecCapability {
  self.codec
}

///|
pub(all) struct RtpEncodingParameters {
  ssrc : UInt?
  payload_type : Byte?
  rtx_ssrc : UInt?
  rtx_payload_type : Byte?
  rid : String?
  active : Bool
  max_bitrate : UInt64?
  scale_resolution_down_by : Double?
  scalability_mode : String?
} derive(Debug, Eq)

///|
pub fn RtpEncodingParameters::new(
  ssrc? : UInt,
  payload_type? : Byte,
  rtx_ssrc? : UInt,
  rtx_payload_type? : Byte,
  rid? : String,
  active? : Bool = true,
  max_bitrate? : UInt64,
  scale_resolution_down_by? : Double,
  scalability_mode? : String,
) -> RtpEncodingParameters raise MediaError {
  if ssrc == Some(0U) || rtx_ssrc == Some(0U) {
    raise InvalidMedia("RTP encoding SSRC must be nonzero")
  }
  match rid {
    Some(value) if value.is_empty() ||
      value.contains(" ") ||
      value.contains("\r") ||
      value.contains("\n") => raise InvalidMedia("RTP encoding RID is invalid")
    _ => ()
  }
  match max_bitrate {
    Some(0UL) =>
      raise InvalidMedia("RTP encoding maximum bitrate must be positive")
    _ => ()
  }
  match scale_resolution_down_by {
    Some(value) if value < 1.0 =>
      raise InvalidMedia("RTP encoding resolution scale must be at least one")
    _ => ()
  }
  match scalability_mode {
    Some(value) if value.is_empty() ||
      value.contains(" ") ||
      value.contains("\r") ||
      value.contains("\n") =>
      raise InvalidMedia("RTP encoding scalability mode is invalid")
    _ => ()
  }
  {
    ssrc,
    payload_type,
    rtx_ssrc,
    rtx_payload_type,
    rid,
    active,
    max_bitrate,
    scale_resolution_down_by,
    scalability_mode,
  }
}

///|
pub struct RtpParameters {
  codec : CodecCapability
  encodings : Array[RtpEncodingParameters]
} derive(Debug, Eq)

///|
pub fn RtpParameters::new(
  codec~ : CodecCapability,
  encodings? : Array[RtpEncodingParameters] = [],
) -> RtpParameters raise MediaError {
  let rids : Array[String] = []
  let ssrcs : Array[UInt] = []
  for encoding in encodings {
    match encoding.rid {
      Some(rid) => {
        if rids.contains(rid) {
          raise InvalidMedia("RTP encoding RID is duplicated")
        }
        rids.push(rid)
      }
      None => ()
    }
    match encoding.ssrc {
      Some(ssrc) => {
        if ssrcs.contains(ssrc) {
          raise InvalidMedia("RTP encoding SSRC is duplicated")
        }
        ssrcs.push(ssrc)
      }
      None => ()
    }
  }
  { codec, encodings: encodings.copy() }
}

///|
pub fn RtpParameters::codec(self : RtpParameters) -> CodecCapability {
  self.codec
}

///|
pub fn RtpParameters::encodings(
  self : RtpParameters,
) -> Array[RtpEncodingParameters] {
  self.encodings.copy()
}

///|
pub struct RtpSender {
  kind : MediaKind
  mut track : MediaTrack?
  mut parameters : RtpParameters?
} derive(Debug)

///|
pub fn RtpSender::new(kind~ : MediaKind) -> RtpSender {
  { kind, track: None, parameters: None }
}

///|
pub fn RtpSender::kind(self : RtpSender) -> MediaKind {
  self.kind
}

///|
pub fn RtpSender::track(self : RtpSender) -> MediaTrack? {
  self.track
}

///|
pub fn RtpSender::parameters(self : RtpSender) -> RtpParameters? {
  self.parameters
}

///|
pub fn RtpSender::replace_track(
  self : RtpSender,
  track : MediaTrack?,
) -> Unit raise MediaError {
  match track {
    Some(next) if next.kind() != self.kind =>
      raise InvalidTrack("replacement track kind does not match sender")
    _ => self.track = track
  }
}

///|
pub fn RtpSender::set_parameters(
  self : RtpSender,
  parameters : RtpParameters?,
) -> Unit {
  self.parameters = parameters
}

///|
pub struct RtpReceiver {
  kind : MediaKind
  mut track : MediaTrack?
  mut parameters : RtpParameters?
} derive(Debug)

///|
pub fn RtpReceiver::new(kind~ : MediaKind) -> RtpReceiver {
  { kind, track: None, parameters: None }
}

///|
pub fn RtpReceiver::kind(self : RtpReceiver) -> MediaKind {
  self.kind
}

///|
pub fn RtpReceiver::track(self : RtpReceiver) -> MediaTrack? {
  self.track
}

///|
pub fn RtpReceiver::parameters(self : RtpReceiver) -> RtpParameters? {
  self.parameters
}

///|
pub fn RtpReceiver::set_track(
  self : RtpReceiver,
  track : MediaTrack?,
) -> Unit raise MediaError {
  match track {
    Some(next) if next.kind() != self.kind =>
      raise InvalidTrack("received track kind does not match receiver")
    _ => self.track = track
  }
}

///|
pub fn RtpReceiver::set_parameters(
  self : RtpReceiver,
  parameters : RtpParameters?,
) -> Unit {
  self.parameters = parameters
}

///|
pub struct RtpTransceiver {
  mut mid : String?
  kind : MediaKind
  mut direction : TransceiverDirection
  mut current_direction : TransceiverDirection?
  sender : RtpSender
  receiver : RtpReceiver
} derive(Debug)

///|
pub fn RtpTransceiver::new(
  kind~ : MediaKind,
  direction? : TransceiverDirection = SendRecv,
) -> RtpTransceiver {
  {
    mid: None,
    kind,
    direction,
    current_direction: None,
    sender: RtpSender::new(kind~),
    receiver: RtpReceiver::new(kind~),
  }
}

///|
pub fn RtpTransceiver::mid(self : RtpTransceiver) -> String? {
  self.mid
}

///|
pub fn RtpTransceiver::kind(self : RtpTransceiver) -> MediaKind {
  self.kind
}

///|
pub fn RtpTransceiver::direction(self : RtpTransceiver) -> TransceiverDirection {
  self.direction
}

///|
pub fn RtpTransceiver::current_direction(
  self : RtpTransceiver,
) -> TransceiverDirection? {
  self.current_direction
}

///|
pub fn RtpTransceiver::sender(self : RtpTransceiver) -> RtpSender {
  self.sender
}

///|
pub fn RtpTransceiver::receiver(self : RtpTransceiver) -> RtpReceiver {
  self.receiver
}

///|
pub fn RtpTransceiver::set_direction(
  self : RtpTransceiver,
  direction : TransceiverDirection,
) -> Unit raise MediaError {
  if self.direction == Stopped {
    raise InvalidTrack("cannot change the direction of a stopped transceiver")
  }
  self.direction = direction
}

///|
pub fn RtpTransceiver::assign_mid(
  self : RtpTransceiver,
  mid : String,
) -> Unit raise MediaError {
  if mid.is_empty() || mid.contains(" ") {
    raise InvalidTrack("invalid RTP transceiver MID")
  }
  match self.mid {
    Some(previous) if previous != mid =>
      raise InvalidTrack("RTP transceiver MID cannot be reassigned")
    _ => self.mid = Some(mid)
  }
}

///|
pub fn RtpTransceiver::set_current_direction(
  self : RtpTransceiver,
  direction : TransceiverDirection,
) -> Unit {
  self.current_direction = Some(direction)
}

///|
pub fn RtpTransceiver::stop(self : RtpTransceiver) -> Unit {
  self.direction = Stopped
  self.current_direction = Some(Stopped)
  self.sender.track = None
  self.sender.parameters = None
  self.receiver.track = None
  self.receiver.parameters = None
}
