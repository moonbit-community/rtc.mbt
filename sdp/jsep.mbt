///|
pub(all) enum DtlsSetup {
  ActPass
  Active
  Passive
  HoldConn
} derive(Debug, Eq)

///|
pub fn DtlsSetup::parse(value : String) -> DtlsSetup raise SdpError {
  match value {
    "actpass" => ActPass
    "active" => Active
    "passive" => Passive
    "holdconn" => HoldConn
    _ => raise InvalidSyntax("unknown DTLS setup role")
  }
}

///|
pub fn DtlsSetup::to_string(self : DtlsSetup) -> String {
  match self {
    ActPass => "actpass"
    Active => "active"
    Passive => "passive"
    HoldConn => "holdconn"
  }
}

///|
fn is_hex_digit(value : UInt16) -> Bool {
  (value >= '0' && value <= '9') ||
  (value >= 'a' && value <= 'f') ||
  (value >= 'A' && value <= 'F')
}

///|
pub struct DtlsFingerprint {
  algorithm : String
  value : String
} derive(Debug, Eq)

///|
pub fn DtlsFingerprint::new(
  algorithm~ : String,
  value~ : String,
) -> DtlsFingerprint raise SdpError {
  let octets = match algorithm.to_lower() {
    "sha-256" => 32
    "sha-384" => 48
    "sha-512" => 64
    _ => raise UnsupportedAttribute("unsupported DTLS fingerprint algorithm")
  }
  if value.length() != octets * 3 - 1 {
    raise InvalidSyntax("DTLS fingerprint has the wrong number of octets")
  }
  for index = 0; index < value.length(); index = index + 1 {
    if index % 3 == 2 {
      if value[index] != ':' {
        raise InvalidSyntax("DTLS fingerprint octets must use colons")
      }
    } else if !is_hex_digit(value[index]) {
      raise InvalidSyntax("DTLS fingerprint contains a non-hex digit")
    }
  }
  { algorithm: algorithm.to_lower(), value, }
}

///|
pub fn DtlsFingerprint::algorithm(self : DtlsFingerprint) -> String {
  self.algorithm
}

///|
pub fn DtlsFingerprint::value(self : DtlsFingerprint) -> String {
  self.value
}

///|
fn DtlsFingerprint::marshal(self : DtlsFingerprint) -> String {
  self.algorithm + " " + self.value
}

///|
fn DtlsFingerprint::parse(value : String) -> DtlsFingerprint raise SdpError {
  let tokens = space_tokens(value)
  if tokens.length() != 2 {
    raise InvalidSyntax("DTLS fingerprint requires algorithm and value")
  }
  DtlsFingerprint::new(algorithm=tokens[0], value=tokens[1])
}

///|
pub struct DataChannelParameters {
  mid : String
  bundle_mids : Array[String]
  ice_credentials : @ice.IceCredentials
  fingerprint : DtlsFingerprint
  setup : DtlsSetup
  candidates : Array[String]
  end_of_candidates : Bool
  sctp_port : UInt16
  max_message_size : UInt64
} derive(Debug, Eq)

///|
pub fn DataChannelParameters::mid(self : DataChannelParameters) -> String {
  self.mid
}

///|
pub fn DataChannelParameters::bundle_mids(
  self : DataChannelParameters,
) -> Array[String] {
  self.bundle_mids.copy()
}

///|
pub fn DataChannelParameters::ice_credentials(
  self : DataChannelParameters,
) -> @ice.IceCredentials {
  self.ice_credentials
}

///|
pub fn DataChannelParameters::fingerprint(
  self : DataChannelParameters,
) -> DtlsFingerprint {
  self.fingerprint
}

///|
pub fn DataChannelParameters::setup(self : DataChannelParameters) -> DtlsSetup {
  self.setup
}

///|
pub fn DataChannelParameters::candidates(
  self : DataChannelParameters,
) -> Array[String] {
  self.candidates.copy()
}

///|
pub fn DataChannelParameters::end_of_candidates(
  self : DataChannelParameters,
) -> Bool {
  self.end_of_candidates
}

///|
pub fn DataChannelParameters::sctp_port(self : DataChannelParameters) -> UInt16 {
  self.sctp_port
}

///|
pub fn DataChannelParameters::max_message_size(
  self : DataChannelParameters,
) -> UInt64 {
  self.max_message_size
}

///|
pub fn DataChannelParameters::validate_for_type(
  self : DataChannelParameters,
  sdp_type : SdpType,
) -> Unit raise SdpError {
  match sdp_type {
    Offer if self.setup != ActPass =>
      raise InvalidSyntax("initial data-channel offer must use setup:actpass")
    Answer | Pranswer if self.setup != Active && self.setup != Passive =>
      raise InvalidSyntax("data-channel answer must choose active or passive")
    Rollback =>
      raise InvalidSyntax("rollback descriptions must not contain SDP")
    _ => ()
  }
}

///|
fn attribute_value(
  document : SdpDocument,
  media : MediaDescription,
  key : String,
) -> String raise SdpError {
  let media_attributes = media.attributes(key)
  if media_attributes.length() > 1 {
    raise InvalidSyntax("duplicate media-level a=\{key} attribute")
  }
  if media_attributes.length() == 1 {
    return match media_attributes[0].value {
      Some(value) => value
      None => raise InvalidSyntax("a=\{key} requires a value")
    }
  }
  let session_attributes = document.session_attributes(key)
  if session_attributes.length() > 1 {
    raise InvalidSyntax("duplicate session-level a=\{key} attribute")
  }
  if session_attributes.length() == 1 {
    return match session_attributes[0].value {
      Some(value) => value
      None => raise InvalidSyntax("a=\{key} requires a value")
    }
  }
  raise InvalidSyntax("missing a=\{key} attribute")
}

///|
pub fn SdpDocument::datachannel_parameters(
  self : SdpDocument,
) -> DataChannelParameters raise SdpError {
  let applications = self.media_descriptions.filter(media => {
    media.media_kind == "application"
  })
  if applications.length() != 1 {
    raise InvalidSyntax(
      "JSEP data channel requires one application media section",
    )
  }
  let media = applications[0]
  if media.protocol != "UDP/DTLS/SCTP" && media.protocol != "TCP/DTLS/SCTP" {
    raise UnsupportedAttribute("unsupported data-channel media protocol")
  }
  if !media.formats.contains("webrtc-datachannel") {
    raise UnsupportedAttribute("missing webrtc-datachannel media format")
  }
  let mid = attribute_value(self, media, "mid")
  if mid.is_empty() || mid.contains(" ") {
    raise InvalidSyntax("invalid data-channel MID")
  }
  let groups = self.session_attributes("group")
  let mut bundle_mids : Array[String] = []
  for group in groups {
    match group.value {
      Some(value) => {
        let tokens = space_tokens(value)
        if !tokens.is_empty() && tokens[0] == "BUNDLE" {
          if bundle_mids.length() > 0 {
            raise InvalidSyntax("duplicate BUNDLE group")
          }
          bundle_mids = tokens[1:].to_owned()
        }
      }
      None => raise InvalidSyntax("a=group requires a value")
    }
  }
  if bundle_mids.is_empty() || !bundle_mids.contains(mid) {
    raise InvalidSyntax("data-channel MID is not present in a BUNDLE group")
  }
  let ice_credentials = @ice.IceCredentials::new(
    username_fragment=attribute_value(self, media, "ice-ufrag"),
    password=attribute_value(self, media, "ice-pwd"),
  ) catch {
    _ => raise InvalidSyntax("invalid ICE credentials")
  }
  let fingerprint = DtlsFingerprint::parse(
    attribute_value(self, media, "fingerprint"),
  )
  let setup = DtlsSetup::parse(attribute_value(self, media, "setup"))
  let sctp_port = decimal_uint64(
    attribute_value(self, media, "sctp-port"),
    "SCTP port",
  )
  if sctp_port == 0UL || sctp_port > 0xffffUL {
    raise InvalidSyntax("SCTP port must be between 1 and 65535")
  }
  let max_message_size = match media.attribute("max-message-size") {
    Some(attribute) =>
      match attribute.value {
        Some(value) => decimal_uint64(value, "maximum message size")
        None => raise InvalidSyntax("a=max-message-size requires a value")
      }
    None => 65536UL
  }
  let candidates : Array[String] = []
  for candidate in media.attributes("candidate") {
    match candidate.value {
      Some(value) if !value.is_empty() => candidates.push(value)
      _ => raise InvalidSyntax("a=candidate requires a value")
    }
  }
  let end_of_candidates = media.attribute("end-of-candidates") is Some(_)
  {
    mid,
    bundle_mids,
    ice_credentials,
    fingerprint,
    setup,
    candidates,
    end_of_candidates,
    sctp_port: sctp_port.to_uint16(),
    max_message_size,
  }
}

///|
pub fn SdpDocument::new_datachannel(
  session_id~ : UInt64,
  session_version~ : UInt64,
  mid~ : String,
  ice_credentials~ : @ice.IceCredentials,
  fingerprint~ : DtlsFingerprint,
  setup~ : DtlsSetup,
  candidates? : Array[String] = [],
  end_of_candidates? : Bool = false,
  sctp_port? : UInt16 = 5000,
  max_message_size? : UInt64 = 65536UL,
  media_sections? : Array[RtpMediaParameters] = [],
  application_index? : Int = 0,
) -> SdpDocument raise SdpError {
  if mid.is_empty() || mid.contains(" ") {
    raise InvalidSyntax("invalid data-channel MID")
  }
  if sctp_port == 0 {
    raise InvalidSyntax("SCTP port must be nonzero")
  }
  if application_index < 0 || application_index > media_sections.length() {
    raise InvalidSyntax("data-channel media index is outside the SDP")
  }
  let bundle_mids : Array[String] = []
  for index = 0; index <= media_sections.length(); index = index + 1 {
    let next_mid = if index == application_index {
      mid
    } else {
      let media_index = if index < application_index {
        index
      } else {
        index - 1
      }
      media_sections[media_index].mid
    }
    if bundle_mids.contains(next_mid) {
      raise InvalidSyntax("duplicate BUNDLE MID")
    }
    bundle_mids.push(next_mid)
  }
  let session_fields = [
    SdpField::new(kind=b'v', value="0"),
    SdpField::new(
      kind=b'o',
      value="- \{session_id} \{session_version} IN IP4 0.0.0.0",
    ),
    SdpField::new(kind=b's', value="-"),
    SdpField::new(kind=b't', value="0 0"),
    SdpField::new(kind=b'a', value="group:BUNDLE " + bundle_mids.join(" ")),
    SdpField::new(kind=b'a', value="msid-semantic: WMS"),
  ]
  let media = MediaDescription::new(
    media_kind="application",
    port=9,
    protocol="UDP/DTLS/SCTP",
    formats=["webrtc-datachannel"],
    fields=[SdpField::new(kind=b'c', value="IN IP4 0.0.0.0")],
  )
  media.add_attribute(SdpAttribute::new(key="mid", value=mid))
  media.add_attribute(
    SdpAttribute::new(
      key="ice-ufrag",
      value=ice_credentials.username_fragment(),
    ),
  )
  media.add_attribute(
    SdpAttribute::new(key="ice-pwd", value=ice_credentials.password()),
  )
  media.add_attribute(SdpAttribute::new(key="ice-options", value="trickle"))
  media.add_attribute(
    SdpAttribute::new(key="fingerprint", value=fingerprint.marshal()),
  )
  media.add_attribute(SdpAttribute::new(key="setup", value=setup.to_string()))
  media.add_attribute(
    SdpAttribute::new(key="sctp-port", value=sctp_port.to_string()),
  )
  media.add_attribute(
    SdpAttribute::new(
      key="max-message-size",
      value=max_message_size.to_string(),
    ),
  )
  for candidate in candidates {
    if candidate.is_empty() ||
      candidate.contains("\r") ||
      candidate.contains("\n") {
      raise InvalidSyntax("invalid ICE candidate attribute")
    }
    media.add_attribute(SdpAttribute::new(key="candidate", value=candidate))
  }
  if end_of_candidates {
    media.add_attribute(SdpAttribute::new(key="end-of-candidates"))
  }
  let media_descriptions : Array[MediaDescription] = []
  let mut media_index = 0
  for section in media_sections {
    if media_index == application_index {
      media_descriptions.push(media)
    }
    let formats = section.codecs.map(codec => {
      codec.payload_type.to_uint().to_string()
    })
    let rtp_media = MediaDescription::new(
      media_kind=section.kind,
      port=9,
      protocol="UDP/TLS/RTP/SAVPF",
      formats~,
      fields=[SdpField::new(kind=b'c', value="IN IP4 0.0.0.0")],
    )
    rtp_media.add_attribute(SdpAttribute::new(key="mid", value=section.mid))
    rtp_media.add_attribute(
      SdpAttribute::new(
        key="ice-ufrag",
        value=ice_credentials.username_fragment(),
      ),
    )
    rtp_media.add_attribute(
      SdpAttribute::new(key="ice-pwd", value=ice_credentials.password()),
    )
    rtp_media.add_attribute(
      SdpAttribute::new(key="ice-options", value="trickle"),
    )
    rtp_media.add_attribute(
      SdpAttribute::new(key="fingerprint", value=fingerprint.marshal()),
    )
    rtp_media.add_attribute(
      SdpAttribute::new(key="setup", value=setup.to_string()),
    )
    rtp_media.add_attribute(SdpAttribute::new(key="rtcp-mux"))
    rtp_media.add_attribute(SdpAttribute::new(key="rtcp-rsize"))
    rtp_media.add_attribute(
      SdpAttribute::new(key=section.direction.to_string()),
    )
    match (section.stream_id, section.track_id) {
      (Some(stream_id), Some(track_id)) =>
        rtp_media.add_attribute(
          SdpAttribute::new(key="msid", value=stream_id + " " + track_id),
        )
      _ => ()
    }
    for extension in section.header_extensions {
      rtp_media.add_attribute(
        SdpAttribute::new(
          key="extmap",
          value=extension.id.to_uint().to_string() + " " + extension.uri,
        ),
      )
    }
    for codec in section.codecs {
      let encoded_payload_type = codec.payload_type.to_uint().to_string()
      let mut mapping = encoded_payload_type +
        " " +
        codec.encoding_name +
        "/" +
        codec.clock_rate.to_string()
      if codec.channels != 1 {
        mapping = mapping + "/" + codec.channels.to_string()
      }
      rtp_media.add_attribute(SdpAttribute::new(key="rtpmap", value=mapping))
      if !codec.fmtp.is_empty() {
        rtp_media.add_attribute(
          SdpAttribute::new(
            key="fmtp",
            value=encoded_payload_type + " " + codec.fmtp,
          ),
        )
      }
      for feedback in codec.rtcp_feedback {
        rtp_media.add_attribute(
          SdpAttribute::new(
            key="rtcp-fb",
            value=encoded_payload_type + " " + feedback,
          ),
        )
      }
    }
    let send_simulcast_rids : Array[String] = []
    let receive_simulcast_rids : Array[String] = []
    let simulcast_ssrcs : Array[String] = []
    for stream in section.streams {
      match stream.rid {
        Some(rid) => {
          let direction = match stream.rid_direction {
            RidSend => "send"
            RidRecv => "recv"
          }
          rtp_media.add_attribute(
            SdpAttribute::new(key="rid", value=rid + " " + direction),
          )
          let encoded_rid = if stream.paused { "~" + rid } else { rid }
          match stream.rid_direction {
            RidSend => send_simulcast_rids.push(encoded_rid)
            RidRecv => receive_simulcast_rids.push(encoded_rid)
          }
        }
        None => ()
      }
      match (stream.rid_direction, stream.ssrc) {
        (RidSend, Some(ssrc)) => simulcast_ssrcs.push(ssrc.to_string())
        _ => ()
      }
    }
    if send_simulcast_rids.length() > 1 {
      rtp_media.add_attribute(
        SdpAttribute::new(
          key="simulcast",
          value="send " + send_simulcast_rids.join(";"),
        ),
      )
    }
    if receive_simulcast_rids.length() > 1 {
      rtp_media.add_attribute(
        SdpAttribute::new(
          key="simulcast",
          value="recv " + receive_simulcast_rids.join(";"),
        ),
      )
    }
    if simulcast_ssrcs.length() > 1 {
      rtp_media.add_attribute(
        SdpAttribute::new(
          key="ssrc-group",
          value="SIM " + simulcast_ssrcs.join(" "),
        ),
      )
    }
    match section.cname {
      Some(cname) =>
        for stream in section.streams {
          match stream.ssrc {
            Some(ssrc) => {
              match stream.rtx_ssrc {
                Some(rtx_ssrc) =>
                  rtp_media.add_attribute(
                    SdpAttribute::new(
                      key="ssrc-group",
                      value="FID " +
                        ssrc.to_string() +
                        " " +
                        rtx_ssrc.to_string(),
                    ),
                  )
                None => ()
              }
              rtp_media.add_attribute(
                SdpAttribute::new(
                  key="ssrc",
                  value=ssrc.to_string() + " cname:" + cname,
                ),
              )
              match (section.stream_id, section.track_id) {
                (Some(stream_id), Some(track_id)) =>
                  rtp_media.add_attribute(
                    SdpAttribute::new(
                      key="ssrc",
                      value=ssrc.to_string() +
                        " msid:" +
                        stream_id +
                        " " +
                        track_id,
                    ),
                  )
                _ => ()
              }
              match stream.rtx_ssrc {
                Some(rtx_ssrc) => {
                  rtp_media.add_attribute(
                    SdpAttribute::new(
                      key="ssrc",
                      value=rtx_ssrc.to_string() + " cname:" + cname,
                    ),
                  )
                  match (section.stream_id, section.track_id) {
                    (Some(stream_id), Some(track_id)) =>
                      rtp_media.add_attribute(
                        SdpAttribute::new(
                          key="ssrc",
                          value=rtx_ssrc.to_string() +
                            " msid:" +
                            stream_id +
                            " " +
                            track_id,
                        ),
                      )
                    _ => ()
                  }
                }
                None => ()
              }
            }
            None => ()
          }
        }
      None => ()
    }
    for candidate in candidates {
      rtp_media.add_attribute(
        SdpAttribute::new(key="candidate", value=candidate),
      )
    }
    if end_of_candidates {
      rtp_media.add_attribute(SdpAttribute::new(key="end-of-candidates"))
    }
    media_descriptions.push(rtp_media)
    media_index += 1
  }
  if application_index == media_sections.length() {
    media_descriptions.push(media)
  }
  SdpDocument::new(session_fields~, media_descriptions~)
}

///|
pub fn SessionDescription::document(
  self : SessionDescription,
) -> SdpDocument raise SdpError {
  if self.sdp_type == Rollback {
    if !self.sdp.is_empty() {
      raise InvalidSyntax("rollback description must have empty SDP")
    }
    raise InvalidSyntax("rollback description has no SDP document")
  }
  SdpDocument::parse(self.sdp)
}

///|
pub fn SessionDescription::datachannel_parameters(
  self : SessionDescription,
) -> DataChannelParameters raise SdpError {
  let parameters = self.document().datachannel_parameters()
  parameters.validate_for_type(self.sdp_type)
  parameters
}

///|
pub fn SessionDescription::from_document(
  sdp_type~ : SdpType,
  document : SdpDocument,
) -> SessionDescription raise SdpError {
  let parameters = document.datachannel_parameters()
  parameters.validate_for_type(sdp_type)
  SessionDescription::new(sdp_type~, sdp=document.marshal())
}
