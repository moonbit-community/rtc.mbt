///|
fn test_fingerprint() -> @sdp.DtlsFingerprint raise @sdp.SdpError {
  @sdp.DtlsFingerprint::new(
    algorithm="sha-256",
    value="00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F",
  )
}

///|
fn test_ice() -> @sdp.IceCredentials {
  try
    @sdp.IceCredentials::new(
      username_fragment="ufrag123",
      password="abcdefghijklmnopqrstuvwx",
    )
  catch {
    _ => abort("static ICE test credentials must be valid")
  } noraise {
    credentials => credentials
  }
}

///|
test "data-channel JSEP SDP generates, parses, and normalizes to CRLF" {
  let document = @sdp.SdpDocument::new_datachannel(
    session_id=123456789UL,
    session_version=7UL,
    mid="data",
    ice_credentials=test_ice(),
    fingerprint=test_fingerprint(),
    setup=ActPass,
    candidates=["0 1 UDP 2122252543 192.0.2.1 5000 typ host generation 0"],
    end_of_candidates=true,
    sctp_port=5000,
    max_message_size=262144UL,
  )
  let wire = document.marshal()
  assert_true(wire.has_suffix("\r\n"))
  let parsed = @sdp.SdpDocument::parse(wire)
  assert_eq(parsed.marshal(), wire)
  let parameters = parsed.datachannel_parameters()
  assert_eq(parameters.mid(), "data")
  assert_eq(parameters.bundle_mids(), ["data"])
  assert_eq(parameters.ice_credentials(), test_ice())
  assert_eq(parameters.fingerprint(), test_fingerprint())
  assert_eq(parameters.setup(), ActPass)
  assert_eq(parameters.sctp_port(), 5000)
  assert_eq(parameters.max_message_size(), 262144UL)
  assert_true(parameters.end_of_candidates())
  assert_eq(parameters.candidates(), [
    "0 1 UDP 2122252543 192.0.2.1 5000 typ host generation 0",
  ])
  let offer = @sdp.SessionDescription::from_document(sdp_type=Offer, parsed)
  assert_eq(offer.datachannel_parameters(), parameters)
}

///|
test "session-level transport attributes are inherited by application media" {
  let sdp = "v=0\n" +
    "o=- 1 2 IN IP4 0.0.0.0\n" +
    "s=-\n" +
    "t=0 0\n" +
    "a=group:BUNDLE 0\n" +
    "a=ice-ufrag:abcd\n" +
    "a=ice-pwd:abcdefghijklmnopqrstuv\n" +
    "a=fingerprint:sha-256 00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F\n" +
    "a=setup:passive\n" +
    "x=preserve-this-session-field\n" +
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\n" +
    "c=IN IP4 0.0.0.0\n" +
    "a=mid:0\n" +
    "a=sctp-port:5000\n" +
    "a=x-unknown:preserve-this-too"
  let document = @sdp.SdpDocument::parse(sdp)
  let parameters = document.datachannel_parameters()
  assert_eq(parameters.setup(), Passive)
  assert_eq(parameters.max_message_size(), 65536UL)
  assert_eq(document.marshal(), sdp.replace_all(old="\n", new="\r\n") + "\r\n")
  let answer = @sdp.SessionDescription::from_document(sdp_type=Answer, document)
  assert_eq(answer.datachannel_parameters().setup(), Passive)
}

///|
test "SDP rejects malformed framing and invalid JSEP singleton attributes" {
  let malformed = "v=0\r\n" +
    "o=- 1 2 IN IP4 0.0.0.0\r\n" +
    "s=-\r\n" +
    "t=0 0\r\n" +
    "\r\n"
  try @sdp.SdpDocument::parse(malformed) catch {
    InvalidSyntax(_) => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("empty SDP line was accepted")
  }
  let duplicate_mid = @sdp.SdpDocument::new_datachannel(
    session_id=1UL,
    session_version=1UL,
    mid="0",
    ice_credentials=test_ice(),
    fingerprint=test_fingerprint(),
    setup=ActPass,
  )
  let media = duplicate_mid.media_descriptions()[0]
  media.add_attribute(@sdp.SdpAttribute::new(key="mid", value="1"))
  try duplicate_mid.datachannel_parameters() catch {
    InvalidSyntax(_) => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("duplicate MID was accepted")
  }
}

///|
test "fingerprints and ICE credentials enforce WebRTC bounds" {
  try @sdp.DtlsFingerprint::new(algorithm="md5", value="00") catch {
    UnsupportedAttribute(_) => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("unsupported fingerprint algorithm was accepted")
  }
  try
    @sdp.IceCredentials::new(
      username_fragment="abc",
      password="abcdefghijklmnopqrstuv",
    )
  catch {
    InvalidCredentials => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("short ICE username fragment was accepted")
  }
}
