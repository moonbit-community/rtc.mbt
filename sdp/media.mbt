///|
pub(all) enum MediaDirection {
  SendRecv
  SendOnly
  RecvOnly
  Inactive
} derive(Debug, Eq)

///|
pub fn MediaDirection::to_string(self : MediaDirection) -> String {
  match self {
    SendRecv => "sendrecv"
    SendOnly => "sendonly"
    RecvOnly => "recvonly"
    Inactive => "inactive"
  }
}

///|
pub fn MediaDirection::parse(value : String) -> MediaDirection raise SdpError {
  match value {
    "sendrecv" => SendRecv
    "sendonly" => SendOnly
    "recvonly" => RecvOnly
    "inactive" => Inactive
    _ => raise InvalidSyntax("unknown RTP media direction")
  }
}

///|
pub(all) struct RtpCodecParameters {
  payload_type : Byte
  encoding_name : String
  clock_rate : UInt
  channels : UInt16
  fmtp : String
  rtcp_feedback : Array[String]
} derive(Debug, Eq)

///|
pub fn RtpCodecParameters::new(
  payload_type~ : Byte,
  encoding_name~ : String,
  clock_rate~ : UInt,
  channels? : UInt16 = 1,
  fmtp? : String = "",
  rtcp_feedback? : Array[String] = [],
) -> RtpCodecParameters raise SdpError {
  if payload_type > 127 ||
    encoding_name.is_empty() ||
    encoding_name.contains(" ") ||
    encoding_name.contains("/") ||
    clock_rate == 0U ||
    channels == 0 {
    raise InvalidSyntax("invalid RTP codec parameters")
  }
  if fmtp.contains("\r") ||
    fmtp.contains("\n") ||
    rtcp_feedback.any(value => {
      value.is_empty() || value.contains("\r") || value.contains("\n")
    }) {
    raise InvalidSyntax("invalid RTP codec feedback or FMTP")
  }
  {
    payload_type,
    encoding_name,
    clock_rate,
    channels,
    fmtp,
    rtcp_feedback: rtcp_feedback.copy(),
  }
}

///|
pub fn RtpCodecParameters::payload_type(self : RtpCodecParameters) -> Byte {
  self.payload_type
}

///|
pub fn RtpCodecParameters::encoding_name(self : RtpCodecParameters) -> String {
  self.encoding_name
}

///|
pub fn RtpCodecParameters::clock_rate(self : RtpCodecParameters) -> UInt {
  self.clock_rate
}

///|
pub fn RtpCodecParameters::channels(self : RtpCodecParameters) -> UInt16 {
  self.channels
}

///|
pub fn RtpCodecParameters::fmtp(self : RtpCodecParameters) -> String {
  self.fmtp
}

///|
pub fn RtpCodecParameters::rtcp_feedback(
  self : RtpCodecParameters,
) -> Array[String] {
  self.rtcp_feedback.copy()
}

///|
pub(all) struct RtpHeaderExtensionParameters {
  id : Byte
  uri : String
} derive(Debug, Eq)

///|
pub fn RtpHeaderExtensionParameters::new(
  id~ : Byte,
  uri~ : String,
) -> RtpHeaderExtensionParameters raise SdpError {
  if id == 0 ||
    uri.is_empty() ||
    uri.contains(" ") ||
    uri.contains("\r") ||
    uri.contains("\n") {
    raise InvalidSyntax("invalid RTP header extension parameters")
  }
  { id, uri, }
}

///|
pub fn RtpHeaderExtensionParameters::id(
  self : RtpHeaderExtensionParameters,
) -> Byte {
  self.id
}

///|
pub fn RtpHeaderExtensionParameters::uri(
  self : RtpHeaderExtensionParameters,
) -> String {
  self.uri
}

///|
pub(all) enum RidDirection {
  RidSend
  RidRecv
} derive(Debug, Eq)

///|
pub(all) struct RtpStreamParameters {
  ssrc : UInt?
  rtx_ssrc : UInt?
  rid : String?
  paused : Bool
  rid_direction : RidDirection
} derive(Debug, Eq)

///|
pub fn RtpStreamParameters::new(
  ssrc? : UInt,
  rtx_ssrc? : UInt,
  rid? : String,
  paused? : Bool = false,
  rid_direction? : RidDirection = RidSend,
) -> RtpStreamParameters raise SdpError {
  if ssrc is None && rid is None {
    raise InvalidSyntax("RTP stream requires an SSRC or RID")
  }
  if ssrc == Some(0U) || rtx_ssrc == Some(0U) {
    raise InvalidSyntax("RTP stream SSRC must be nonzero")
  }
  match (ssrc, rtx_ssrc) {
    (None, Some(_)) =>
      raise InvalidSyntax("RTP RTX SSRC requires a primary SSRC")
    (Some(primary), Some(rtx)) if primary == rtx =>
      raise InvalidSyntax("RTP primary and RTX SSRC must differ")
    _ => ()
  }
  match rid {
    Some(value) if value.is_empty() ||
      value.contains(" ") ||
      value.contains(";") ||
      value.contains(",") ||
      value.contains("\r") ||
      value.contains("\n") => raise InvalidSyntax("RTP stream RID is invalid")
    _ => ()
  }
  { ssrc, rtx_ssrc, rid, paused, rid_direction, }
}

///|
pub(all) struct RtpMediaParameters {
  kind : String
  mid : String
  direction : MediaDirection
  codecs : Array[RtpCodecParameters]
  header_extensions : Array[RtpHeaderExtensionParameters]
  stream_id : String?
  track_id : String?
  ssrc : UInt?
  rtx_ssrc : UInt?
  streams : Array[RtpStreamParameters]
  cname : String?
} derive(Debug, Eq)

///|
pub fn RtpMediaParameters::new(
  kind~ : String,
  mid~ : String,
  direction? : MediaDirection = SendRecv,
  codecs~ : Array[RtpCodecParameters],
  header_extensions? : Array[RtpHeaderExtensionParameters] = [],
  stream_id? : String,
  track_id? : String,
  ssrc? : UInt,
  rtx_ssrc? : UInt,
  streams? : Array[RtpStreamParameters] = [],
  cname? : String,
) -> RtpMediaParameters raise SdpError {
  if kind != "audio" && kind != "video" {
    raise InvalidSyntax("RTP media kind must be audio or video")
  }
  if mid.is_empty() || mid.contains(" ") || codecs.is_empty() {
    raise InvalidSyntax("RTP media section requires a MID and codecs")
  }
  if (stream_id is Some(_)) != (track_id is Some(_)) {
    raise InvalidSyntax("RTP media stream and track ids must appear together")
  }
  let extension_ids : Array[Byte] = []
  let extension_uris : Array[String] = []
  for extension in header_extensions {
    if extension_ids.contains(extension.id) ||
      extension_uris.contains(extension.uri) {
      raise InvalidSyntax("duplicate RTP header extension")
    }
    extension_ids.push(extension.id)
    extension_uris.push(extension.uri)
  }
  let normalized_streams = if streams.is_empty() {
    match ssrc {
      Some(_) => [RtpStreamParameters::new(ssrc?, rtx_ssrc?)]
      None => []
    }
  } else {
    streams.copy()
  }
  let mut normalized_ssrc = ssrc
  let mut normalized_rtx_ssrc = rtx_ssrc
  if !normalized_streams.is_empty() {
    match normalized_streams[0].ssrc {
      Some(value) =>
        match normalized_ssrc {
          Some(explicit) if explicit != value =>
            raise InvalidSyntax(
              "primary RTP SSRC disagrees with the first stream",
            )
          _ => normalized_ssrc = Some(value)
        }
      None => ()
    }
    match normalized_streams[0].rtx_ssrc {
      Some(value) =>
        match normalized_rtx_ssrc {
          Some(explicit) if explicit != value =>
            raise InvalidSyntax("RTX SSRC disagrees with the first stream")
          _ => normalized_rtx_ssrc = Some(value)
        }
      None => ()
    }
  }
  let stream_ssrcs : Array[UInt] = []
  let stream_rtx_ssrcs : Array[UInt] = []
  let stream_rids : Array[String] = []
  for stream in normalized_streams {
    match stream.ssrc {
      Some(value) => {
        if stream_ssrcs.contains(value) || stream_rtx_ssrcs.contains(value) {
          raise InvalidSyntax("duplicate RTP stream SSRC")
        }
        stream_ssrcs.push(value)
      }
      None => ()
    }
    match stream.rtx_ssrc {
      Some(value) => {
        if stream_ssrcs.contains(value) || stream_rtx_ssrcs.contains(value) {
          raise InvalidSyntax("duplicate RTP RTX SSRC")
        }
        stream_rtx_ssrcs.push(value)
      }
      None => ()
    }
    match stream.rid {
      Some(value) => {
        let key = (match stream.rid_direction {
            RidSend => "send:"
            RidRecv => "recv:"
          }) +
          value
        if stream_rids.contains(key) {
          raise InvalidSyntax("duplicate RTP stream RID")
        }
        stream_rids.push(key)
      }
      None => ()
    }
  }
  let has_stream_ssrc = normalized_streams.any(stream => stream.ssrc is Some(_))
  match (has_stream_ssrc, cname) {
    (true, None) =>
      raise InvalidSyntax("RTP SSRC and CNAME must appear together")
    _ => ()
  }
  match (normalized_ssrc, cname) {
    (Some(_), None) | (None, Some(_)) =>
      if !has_stream_ssrc {
        raise InvalidSyntax("RTP SSRC and CNAME must appear together")
      }
    _ => ()
  }
  match (normalized_ssrc, normalized_rtx_ssrc) {
    (None, Some(_)) =>
      raise InvalidSyntax("RTP RTX SSRC requires a primary SSRC")
    (Some(primary), Some(rtx)) if primary == rtx =>
      raise InvalidSyntax("RTP primary and RTX SSRC must differ")
    _ => ()
  }
  {
    kind,
    mid,
    direction,
    codecs: codecs.copy(),
    header_extensions: header_extensions.copy(),
    stream_id,
    track_id,
    ssrc: normalized_ssrc,
    rtx_ssrc: normalized_rtx_ssrc,
    streams: normalized_streams,
    cname,
  }
}

///|
pub fn RtpMediaParameters::kind(self : RtpMediaParameters) -> String {
  self.kind
}

///|
pub fn RtpMediaParameters::mid(self : RtpMediaParameters) -> String {
  self.mid
}

///|
pub fn RtpMediaParameters::direction(
  self : RtpMediaParameters,
) -> MediaDirection {
  self.direction
}

///|
pub fn RtpMediaParameters::codecs(
  self : RtpMediaParameters,
) -> Array[RtpCodecParameters] {
  self.codecs.copy()
}

///|
pub fn RtpMediaParameters::header_extensions(
  self : RtpMediaParameters,
) -> Array[RtpHeaderExtensionParameters] {
  self.header_extensions.copy()
}

///|
pub fn RtpMediaParameters::stream_id(self : RtpMediaParameters) -> String? {
  self.stream_id
}

///|
pub fn RtpMediaParameters::track_id(self : RtpMediaParameters) -> String? {
  self.track_id
}

///|
pub fn RtpMediaParameters::ssrc(self : RtpMediaParameters) -> UInt? {
  self.ssrc
}

///|
pub fn RtpMediaParameters::rtx_ssrc(self : RtpMediaParameters) -> UInt? {
  self.rtx_ssrc
}

///|
pub fn RtpMediaParameters::streams(
  self : RtpMediaParameters,
) -> Array[RtpStreamParameters] {
  self.streams.copy()
}

///|
pub fn RtpMediaParameters::cname(self : RtpMediaParameters) -> String? {
  self.cname
}

///|
fn parse_payload_type(value : StringView) -> Byte raise SdpError {
  let parsed = decimal_uint(value, "RTP payload type")
  if parsed > 127U {
    raise InvalidSyntax("RTP payload type exceeds 127")
  }
  parsed.to_byte()
}

///|
fn media_direction(media : MediaDescription) -> MediaDirection raise SdpError {
  let directions : Array[MediaDirection] = []
  for name in ["sendrecv", "sendonly", "recvonly", "inactive"] {
    if media.attribute(name) is Some(_) {
      directions.push(MediaDirection::parse(name))
    }
  }
  if directions.length() > 1 {
    raise InvalidSyntax("RTP media section has multiple directions")
  }
  if directions.is_empty() {
    SendRecv
  } else {
    directions[0]
  }
}

///|
fn parse_header_extensions(
  media : MediaDescription,
) -> Array[RtpHeaderExtensionParameters] raise SdpError {
  let extensions : Array[RtpHeaderExtensionParameters] = []
  for attribute in media.attributes("extmap") {
    guard attribute.value() is Some(value) &&
      value.split_once(" ") is Some((encoded_id, remainder)) else {
      raise InvalidSyntax("invalid RTP extmap attribute")
    }
    let id_token = match encoded_id.split_once("/") {
      Some((id, direction)) => {
        ignore(MediaDirection::parse(direction.to_owned()))
        id
      }
      None => encoded_id
    }
    let id_value = decimal_uint(id_token, "RTP extension id")
    if id_value == 0U || id_value > 255U {
      raise InvalidSyntax("RTP extension id is outside 1..255")
    }
    let uri = match remainder.split_once(" ") {
      Some((value, _)) => value.to_owned()
      None => remainder.to_owned()
    }
    extensions.push(
      RtpHeaderExtensionParameters::new(id=id_value.to_byte(), uri~),
    )
  }
  extensions
}

///|
fn keyed_attribute_values(
  media : MediaDescription,
  key : String,
  payload_type : Byte,
) -> Array[String] raise SdpError {
  let result : Array[String] = []
  for attribute in media.attributes(key) {
    guard attribute.value() is Some(value) else {
      raise InvalidSyntax("a=\{key} requires a value")
    }
    let tokens = value.split_once(" ")
    guard tokens is Some((encoded_payload_type, remainder)) else {
      raise InvalidSyntax("invalid a=\{key} value")
    }
    if parse_payload_type(encoded_payload_type) == payload_type {
      result.push(remainder.to_owned())
    }
  }
  result
}

///|
fn parse_rtp_codec(
  media : MediaDescription,
  format : String,
) -> RtpCodecParameters raise SdpError {
  let payload_type = parse_payload_type(format)
  let rtpmap = keyed_attribute_values(media, "rtpmap", payload_type)
  if rtpmap.length() != 1 {
    raise InvalidSyntax("dynamic RTP payload type requires one rtpmap")
  }
  let parts = rtpmap[0].split("/").to_array()
  if parts.length() < 2 || parts.length() > 3 {
    raise InvalidSyntax("invalid RTP rtpmap encoding")
  }
  let clock_rate = decimal_uint(parts[1], "RTP clock rate")
  let channels = if parts.length() == 3 {
    let value = decimal_uint(parts[2], "RTP channel count")
    if value == 0U || value > 0xffffU {
      raise InvalidSyntax("invalid RTP channel count")
    }
    value.to_uint16()
  } else {
    1
  }
  let fmtp_values = keyed_attribute_values(media, "fmtp", payload_type)
  if fmtp_values.length() > 1 {
    raise InvalidSyntax("duplicate RTP fmtp attribute")
  }
  RtpCodecParameters::new(
    payload_type~,
    encoding_name=parts[0].to_owned(),
    clock_rate~,
    channels~,
    fmtp=fmtp_values.get(0).unwrap_or(""),
    rtcp_feedback=keyed_attribute_values(media, "rtcp-fb", payload_type),
  )
}

///|
fn parse_stream_groups(
  media : MediaDescription,
) -> (Array[UInt], Map[UInt, UInt]) raise SdpError {
  let simulcast_ssrcs : Array[UInt] = []
  let fid : Map[UInt, UInt] = Map([])
  for attribute in media.attributes("ssrc-group") {
    guard attribute.value() is Some(value) else {
      raise InvalidSyntax("a=ssrc-group requires a value")
    }
    let tokens = space_tokens(value)
    if tokens.is_empty() {
      raise InvalidSyntax("invalid SDP SSRC group")
    }
    match tokens[0] {
      "FID" => {
        if tokens.length() != 3 {
          raise InvalidSyntax("invalid SDP FID SSRC group")
        }
        let primary = decimal_uint(tokens[1], "primary RTP SSRC")
        let rtx = decimal_uint(tokens[2], "RTX SSRC")
        if primary == 0U || rtx == 0U || primary == rtx || fid.contains(primary) {
          raise InvalidSyntax("invalid or duplicate SDP FID SSRC group")
        }
        fid[primary] = rtx
      }
      "SIM" => {
        if tokens.length() < 3 || !simulcast_ssrcs.is_empty() {
          raise InvalidSyntax("invalid or duplicate SDP SIM SSRC group")
        }
        for token in tokens[1:] {
          let ssrc = decimal_uint(token, "simulcast RTP SSRC")
          if ssrc == 0U || simulcast_ssrcs.contains(ssrc) {
            raise InvalidSyntax("duplicate simulcast RTP SSRC")
          }
          simulcast_ssrcs.push(ssrc)
        }
      }
      _ => ()
    }
  }
  (simulcast_ssrcs, fid)
}

///|
fn parse_simulcast_rids(
  media : MediaDescription,
) -> Array[(String, Bool, RidDirection)] raise SdpError {
  let declared : Array[(String, RidDirection)] = []
  for attribute in media.attributes("rid") {
    guard attribute.value() is Some(value) else {
      raise InvalidSyntax("a=rid requires a value")
    }
    let tokens = space_tokens(value)
    if tokens.length() < 2 || (tokens[1] != "send" && tokens[1] != "recv") {
      raise InvalidSyntax("invalid RTP RID attribute")
    }
    let rid = tokens[0]
    ignore(RtpStreamParameters::new(rid~))
    let rid_direction = if tokens[1] == "send" { RidSend } else { RidRecv }
    if declared.any(entry => entry.0 == rid && entry.1 == rid_direction) {
      raise InvalidSyntax("duplicate RTP RID attribute")
    }
    declared.push((rid, rid_direction))
  }
  let ordered : Array[(String, Bool, RidDirection)] = []
  let mut saw_send = false
  let mut saw_recv = false
  for attribute in media.attributes("simulcast") {
    guard attribute.value() is Some(value) &&
      value.split_once(" ") is Some((direction, layers)) else {
      raise InvalidSyntax("invalid simulcast attribute")
    }
    if direction != "send" && direction != "recv" {
      raise InvalidSyntax("invalid simulcast direction")
    }
    let rid_direction = if direction == "send" { RidSend } else { RidRecv }
    if (rid_direction == RidSend && saw_send) ||
      (rid_direction == RidRecv && saw_recv) {
      raise InvalidSyntax("duplicate simulcast direction")
    }
    if rid_direction == RidSend {
      saw_send = true
    } else {
      saw_recv = true
    }
    for layer in layers.split(";") {
      let alternatives = layer.split(",").to_array()
      if alternatives.is_empty() {
        raise InvalidSyntax("empty simulcast layer")
      }
      let encoded = alternatives[0]
      let stripped = encoded.strip_prefix("~")
      let paused = stripped is Some(_)
      let rid = stripped.unwrap_or(encoded).to_owned()
      if !declared.any(entry => entry.0 == rid && entry.1 == rid_direction) ||
        ordered.any(entry => entry.0 == rid && entry.2 == rid_direction) {
        raise InvalidSyntax("simulcast references an unknown or duplicate RID")
      }
      ordered.push((rid, paused, rid_direction))
    }
  }
  if ordered.is_empty() {
    for entry in declared {
      ordered.push((entry.0, false, entry.1))
    }
  }
  ordered
}

///|
fn parse_ssrc_attribute(
  media : MediaDescription,
) -> (UInt?, UInt?, Array[RtpStreamParameters], String?, String?, String?) raise SdpError {
  let (simulcast_ssrcs, fid) = parse_stream_groups(media)
  let all_ssrcs : Array[UInt] = []
  let mut cname : String? = None
  let mut stream_id : String? = None
  let mut track_id : String? = None
  for attribute in media.attributes("ssrc") {
    guard attribute.value() is Some(value) &&
      value.split_once(" ") is Some((encoded_ssrc, description)) else {
      raise InvalidSyntax("invalid SDP SSRC attribute")
    }
    let parsed_ssrc = decimal_uint(encoded_ssrc, "RTP SSRC")
    if parsed_ssrc == 0U {
      raise InvalidSyntax("RTP SSRC must be nonzero")
    }
    if !all_ssrcs.contains(parsed_ssrc) {
      all_ssrcs.push(parsed_ssrc)
    }
    match description.split_once(":") {
      Some(("cname", value)) =>
        match cname {
          Some(previous) if previous != value.to_owned() =>
            raise InvalidSyntax("RTP streams use different CNAME values")
          _ => cname = Some(value.to_owned())
        }
      Some(("msid", value)) => {
        let is_rtx = fid.values().contains(parsed_ssrc)
        if !is_rtx {
          let ids = space_tokens(value.to_owned())
          if ids.length() != 2 {
            raise InvalidSyntax("invalid SSRC msid attribute")
          }
          match (stream_id, track_id) {
            (Some(previous_stream), Some(previous_track)) =>
              if previous_stream != ids[0] || previous_track != ids[1] {
                raise InvalidSyntax(
                  "simulcast SSRCs use different media stream ids",
                )
              }
            _ => {
              stream_id = Some(ids[0])
              track_id = Some(ids[1])
            }
          }
        }
      }
      _ => ()
    }
  }
  match media.attribute("msid") {
    Some(attribute) =>
      match attribute.value() {
        Some(value) => {
          let ids = space_tokens(value)
          if ids.length() != 2 {
            raise InvalidSyntax("invalid media msid attribute")
          }
          stream_id = Some(ids[0])
          track_id = Some(ids[1])
        }
        None => raise InvalidSyntax("a=msid requires stream and track ids")
      }
    None => ()
  }
  let primary_ssrcs = if !simulcast_ssrcs.is_empty() {
    simulcast_ssrcs
  } else {
    let values : Array[UInt] = []
    for primary in fid.keys() {
      if !values.contains(primary) {
        values.push(primary)
      }
    }
    for ssrc in all_ssrcs {
      if !fid.values().contains(ssrc) && !values.contains(ssrc) {
        values.push(ssrc)
      }
    }
    values
  }
  for primary in primary_ssrcs {
    if !all_ssrcs.contains(primary) && !fid.contains(primary) {
      raise InvalidSyntax("SIM group references an unknown RTP SSRC")
    }
  }
  let rid_layers = parse_simulcast_rids(media)
  let streams : Array[RtpStreamParameters] = []
  for index = 0; index < primary_ssrcs.length(); index = index + 1 {
    let primary = primary_ssrcs[index]
    let rid = if index < rid_layers.length() {
      Some(rid_layers[index].0)
    } else {
      None
    }
    let paused = if index < rid_layers.length() {
      rid_layers[index].1
    } else {
      false
    }
    let rid_direction = if index < rid_layers.length() {
      rid_layers[index].2
    } else {
      RidSend
    }
    let rtx_ssrc = fid.get(primary)
    streams.push(
      RtpStreamParameters::new(
        ssrc=primary,
        rtx_ssrc?,
        rid?,
        paused~,
        rid_direction~,
      ),
    )
  }
  for index = primary_ssrcs.length()
      index < rid_layers.length()
      index = index + 1 {
    streams.push(
      RtpStreamParameters::new(
        rid=rid_layers[index].0,
        paused=rid_layers[index].1,
        rid_direction=rid_layers[index].2,
      ),
    )
  }
  let (first_ssrc, first_rtx) = match streams.get(0) {
    Some(stream) => (stream.ssrc, stream.rtx_ssrc)
    None => (None, None)
  }
  (first_ssrc, first_rtx, streams, cname, stream_id, track_id)
}

///|
pub fn SdpDocument::rtp_media_parameters(
  self : SdpDocument,
) -> Array[RtpMediaParameters] raise SdpError {
  let result : Array[RtpMediaParameters] = []
  for media in self.media_descriptions() {
    if media.media_kind() != "audio" && media.media_kind() != "video" {
      continue
    }
    if media.protocol() != "UDP/TLS/RTP/SAVPF" {
      raise UnsupportedAttribute("unsupported RTP media protocol")
    }
    let mid = attribute_value(self, media, "mid")
    let codecs : Array[RtpCodecParameters] = []
    for format in media.formats() {
      codecs.push(parse_rtp_codec(media, format))
    }
    let (ssrc, rtx_ssrc, streams, cname, stream_id, track_id) = parse_ssrc_attribute(
      media,
    )
    let header_extensions = parse_header_extensions(media)
    result.push(
      RtpMediaParameters::new(
        kind=media.media_kind(),
        mid~,
        direction=media_direction(media),
        codecs~,
        header_extensions~,
        stream_id?,
        track_id?,
        ssrc?,
        rtx_ssrc?,
        streams~,
        cname?,
      ),
    )
  }
  result
}

///|
pub fn SessionDescription::rtp_media_parameters(
  self : SessionDescription,
) -> Array[RtpMediaParameters] raise SdpError {
  self.document().rtp_media_parameters()
}
