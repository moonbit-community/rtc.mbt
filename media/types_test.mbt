///|
test "RTP transceiver exposes shared sender and receiver state" {
  let codec = @media.CodecCapability::new(
    mime_type="video/vp8",
    clock_rate=90000U,
    rtcp_feedback=["nack", "transport-cc"],
  )
  let track = @media.MediaTrack::new(
    id="video",
    stream_id="stream",
    kind=Video,
    codec~,
  )
  let encoding = @media.RtpEncodingParameters::new(
    ssrc=10U,
    payload_type=96,
    rtx_ssrc=20U,
    rtx_payload_type=97,
    rid="high",
    max_bitrate=2000000UL,
    scalability_mode="L1T3",
  )
  let parameters = @media.RtpParameters::new(codec~, encodings=[encoding])
  let transceiver = @media.RtpTransceiver::new(kind=Video)
  transceiver.sender().replace_track(Some(track))
  transceiver.sender().set_parameters(Some(parameters))
  transceiver.receiver().set_track(Some(track))
  transceiver.receiver().set_parameters(Some(parameters))
  assert_eq(
    transceiver.sender().track().map(value => value.id()),
    Some("video"),
  )
  assert_eq(transceiver.sender().parameters().unwrap().encodings(), [encoding])
  assert_eq(
    transceiver.receiver().track().map(value => value.id()),
    Some("video"),
  )
  transceiver.stop()
  assert_eq(transceiver.direction(), Stopped)
  assert_true(transceiver.sender().track() is None)
  assert_eq(transceiver.receiver().parameters(), None)
}

///|
test "RTP encoding parameters reject duplicate stream identities" {
  let codec = @media.CodecCapability::new(
    mime_type="video/vp9",
    clock_rate=90000U,
  )
  let first = @media.RtpEncodingParameters::new(
    ssrc=10U,
    payload_type=98,
    rid="layer",
  )
  let second = @media.RtpEncodingParameters::new(
    ssrc=11U,
    payload_type=98,
    rid="layer",
  )
  let mut rejected = false
  ignore(@media.RtpParameters::new(codec~, encodings=[first, second])) catch {
    InvalidMedia(_) => rejected = true
    _ => fail("unexpected RTP parameter error")
  }
  assert_true(rejected)
}
