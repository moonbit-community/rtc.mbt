///|
fn media_test_fingerprint() -> DtlsFingerprint raise SdpError {
  DtlsFingerprint::new(
    algorithm="sha-256",
    value="00:01:02:03:04:05:06:07:08:09:0A:0B:0C:0D:0E:0F:10:11:12:13:14:15:16:17:18:19:1A:1B:1C:1D:1E:1F",
  )
}

///|
test "JSEP document marshals and parses bundled audio and video sections" {
  let opus = RtpCodecParameters::new(
    payload_type=111,
    encoding_name="opus",
    clock_rate=48000U,
    channels=2,
    fmtp="minptime=10;useinbandfec=1",
    rtcp_feedback=["transport-cc"],
  )
  let vp8 = RtpCodecParameters::new(
    payload_type=96,
    encoding_name="VP8",
    clock_rate=90000U,
    rtcp_feedback=["nack", "nack pli", "goog-remb", "transport-cc"],
  )
  let document = SdpDocument::new_datachannel(
    session_id=1UL,
    session_version=2UL,
    mid="data",
    ice_credentials=@ice.IceCredentials::new(
      username_fragment="abcd",
      password="abcdefghijklmnopqrstuvwxyz",
    ),
    fingerprint=media_test_fingerprint(),
    setup=ActPass,
    candidates=["1 1 udp 2130706431 192.0.2.10 5000 typ host"],
    media_sections=[
      RtpMediaParameters::new(
        kind="audio",
        mid="0",
        direction=SendRecv,
        codecs=[opus],
        stream_id="stream",
        track_id="audio",
        ssrc=0x10203040U,
        cname="rtc.mbt",
      ),
      RtpMediaParameters::new(kind="video", mid="1", direction=RecvOnly, codecs=[
        vp8,
      ]),
    ],
  )
  let wire = document.marshal()
  assert_true(wire.contains("a=group:BUNDLE data 0 1\r\n"))
  assert_true(wire.contains("a=rtpmap:111 opus/48000/2\r\n"))
  assert_true(wire.contains("a=ssrc:270544960 cname:rtc.mbt\r\n"))
  let parsed = SdpDocument::parse(wire)
  assert_eq(parsed.rtp_media_parameters(), [
    RtpMediaParameters::new(
      kind="audio",
      mid="0",
      direction=SendRecv,
      codecs=[opus],
      stream_id="stream",
      track_id="audio",
      ssrc=0x10203040U,
      cname="rtc.mbt",
    ),
    RtpMediaParameters::new(kind="video", mid="1", direction=RecvOnly, codecs=[
      vp8,
    ]),
  ])
  assert_eq(parsed.marshal(), wire)
}

///|
test "RTP SDP rejects conflicting directions and malformed rtpmap" {
  let base = SdpDocument::new_datachannel(
    session_id=1UL,
    session_version=1UL,
    mid="data",
    ice_credentials=@ice.IceCredentials::new(
      username_fragment="abcd",
      password="abcdefghijklmnopqrstuvwxyz",
    ),
    fingerprint=media_test_fingerprint(),
    setup=ActPass,
    media_sections=[
      RtpMediaParameters::new(kind="audio", mid="0", codecs=[
        RtpCodecParameters::new(
          payload_type=111,
          encoding_name="opus",
          clock_rate=48000U,
          channels=2,
        ),
      ]),
    ],
  ).marshal()
  let conflicting = base.replace(
    old="a=sendrecv\r\n",
    new="a=sendrecv\r\na=recvonly\r\n",
  )
  ignore(SdpDocument::parse(conflicting).rtp_media_parameters()) catch {
    InvalidSyntax(_) => ()
    _ => fail("unexpected RTP SDP error")
  }
  let malformed = base.replace(
    old="a=rtpmap:111 opus/48000/2",
    new="a=rtpmap:111 opus",
  )
  ignore(SdpDocument::parse(malformed).rtp_media_parameters()) catch {
    InvalidSyntax(_) => return
    _ => fail("unexpected RTP SDP error")
  }
  fail("malformed RTP rtpmap was accepted")
}

///|
test "RTP SDP preserves RTX apt and FID SSRC groups" {
  let vp8 = RtpCodecParameters::new(
    payload_type=96,
    encoding_name="VP8",
    clock_rate=90000U,
    rtcp_feedback=["nack", "nack pli"],
  )
  let rtx = RtpCodecParameters::new(
    payload_type=97,
    encoding_name="rtx",
    clock_rate=90000U,
    fmtp="apt=96",
  )
  let section = RtpMediaParameters::new(
    kind="video",
    mid="0",
    direction=SendOnly,
    codecs=[vp8, rtx],
    header_extensions=[
      RtpHeaderExtensionParameters::new(
        id=3,
        uri="http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
      ),
    ],
    stream_id="stream",
    track_id="video",
    ssrc=100U,
    rtx_ssrc=200U,
    cname="rtc.mbt",
  )
  let document = SdpDocument::new_datachannel(
    session_id=1UL,
    session_version=1UL,
    mid="data",
    ice_credentials=@ice.IceCredentials::new(
      username_fragment="abcd",
      password="abcdefghijklmnopqrstuvwxyz",
    ),
    fingerprint=media_test_fingerprint(),
    setup=ActPass,
    media_sections=[section],
  )
  let wire = document.marshal()
  assert_true(wire.contains("a=fmtp:97 apt=96\r\n"))
  assert_true(
    wire.contains(
      "a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n",
    ),
  )
  assert_true(wire.contains("a=ssrc-group:FID 100 200\r\n"))
  assert_true(wire.contains("a=ssrc:200 cname:rtc.mbt\r\n"))
  assert_eq(SdpDocument::parse(wire).rtp_media_parameters(), [section])
}

///|
test "RTP SDP preserves RID and SSRC simulcast streams" {
  let vp9 = RtpCodecParameters::new(
    payload_type=98,
    encoding_name="VP9",
    clock_rate=90000U,
    rtcp_feedback=["nack", "transport-cc"],
  )
  let section = RtpMediaParameters::new(
    kind="video",
    mid="video",
    direction=SendOnly,
    codecs=[vp9],
    stream_id="stream",
    track_id="simulcast",
    streams=[
      RtpStreamParameters::new(ssrc=100U, rtx_ssrc=200U, rid="high"),
      RtpStreamParameters::new(ssrc=101U, rtx_ssrc=201U, rid="medium"),
      RtpStreamParameters::new(ssrc=102U, rtx_ssrc=202U, rid="low", paused=true),
    ],
    cname="rtc.mbt",
  )
  let wire = SdpDocument::new_datachannel(
    session_id=3UL,
    session_version=1UL,
    mid="data",
    ice_credentials=@ice.IceCredentials::new(
      username_fragment="abcd",
      password="abcdefghijklmnopqrstuvwxyz",
    ),
    fingerprint=media_test_fingerprint(),
    setup=ActPass,
    media_sections=[section],
  ).marshal()
  assert_true(wire.contains("a=rid:high send\r\n"))
  assert_true(wire.contains("a=simulcast:send high;medium;~low\r\n"))
  assert_true(wire.contains("a=ssrc-group:SIM 100 101 102\r\n"))
  assert_true(wire.contains("a=ssrc-group:FID 101 201\r\n"))
  assert_eq(SdpDocument::parse(wire).rtp_media_parameters(), [section])
}

///|
test "data-channel media may follow RTP media in an answer" {
  let credentials = @ice.IceCredentials::new(
    username_fragment="ordered",
    password="0123456789012345678901",
  )
  let fingerprint = media_test_fingerprint()
  let audio = RtpMediaParameters::new(
    kind="audio",
    mid="0",
    direction=RecvOnly,
    codecs=[
      RtpCodecParameters::new(
        payload_type=111,
        encoding_name="opus",
        clock_rate=48000U,
        channels=2,
      ),
    ],
  )
  let video = RtpMediaParameters::new(
    kind="video",
    mid="1",
    direction=RecvOnly,
    codecs=[
      RtpCodecParameters::new(
        payload_type=96,
        encoding_name="VP8",
        clock_rate=90000U,
      ),
    ],
  )
  let document = SdpDocument::new_datachannel(
    session_id=1UL,
    session_version=1UL,
    mid="2",
    ice_credentials=credentials,
    fingerprint~,
    setup=Active,
    media_sections=[audio, video],
    application_index=2,
  )
  let media = document.media_descriptions()
  assert_eq(media.map(section => section.media_kind()), [
    "audio", "video", "application",
  ])
  assert_eq(
    document.session_attribute("group").unwrap().value(),
    Some("BUNDLE 0 1 2"),
  )
}
