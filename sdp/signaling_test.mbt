///|
fn description_for_test(
  sdp_type : @sdp.SdpType,
  setup : @sdp.DtlsSetup,
  version : UInt64,
) -> @sdp.SessionDescription raise @sdp.SdpError {
  let document = @sdp.SdpDocument::new_datachannel(
    session_id=42UL,
    session_version=version,
    mid="data",
    ice_credentials=test_ice(),
    fingerprint=test_fingerprint(),
    setup~,
  )
  @sdp.SessionDescription::from_document(sdp_type~, document)
}

///|
test "local offer, remote provisional answer, and final answer commit atomically" {
  let signaling = @sdp.SignalingStateMachine::new()
  let offer = description_for_test(Offer, ActPass, 1UL)
  let provisional = description_for_test(Pranswer, Passive, 1UL)
  let answer = description_for_test(Answer, Passive, 1UL)
  signaling.set_local_description(offer)
  assert_eq(signaling.state(), HaveLocalOffer)
  assert_eq(signaling.pending_local_description(), Some(offer))
  signaling.set_remote_description(provisional)
  assert_eq(signaling.state(), HaveRemotePranswer)
  assert_eq(signaling.pending_remote_description(), Some(provisional))
  signaling.set_remote_description(answer)
  assert_eq(signaling.state(), Stable)
  assert_eq(signaling.current_local_description(), Some(offer))
  assert_eq(signaling.current_remote_description(), Some(answer))
  assert_eq(signaling.pending_local_description(), None)
  assert_eq(signaling.pending_remote_description(), None)
}

///|
test "remote offer and local answer commit, while rollback discards pending state" {
  let signaling = @sdp.SignalingStateMachine::new()
  let offer = description_for_test(Offer, ActPass, 1UL)
  let answer = description_for_test(Answer, Active, 1UL)
  signaling.set_remote_description(offer)
  assert_eq(signaling.state(), HaveRemoteOffer)
  signaling.set_local_description(answer)
  assert_eq(signaling.state(), Stable)
  assert_eq(signaling.current_remote_description(), Some(offer))
  assert_eq(signaling.current_local_description(), Some(answer))
  let next_offer = description_for_test(Offer, ActPass, 2UL)
  signaling.set_local_description(next_offer)
  signaling.set_local_description(
    @sdp.SessionDescription::new(sdp_type=Rollback, sdp=""),
  )
  assert_eq(signaling.state(), Stable)
  assert_eq(signaling.pending_local_description(), None)
  assert_eq(signaling.current_local_description(), Some(answer))
}

///|
test "invalid signaling transitions fail and close is idempotent" {
  let signaling = @sdp.SignalingStateMachine::new()
  let answer = description_for_test(Answer, Passive, 1UL)
  try signaling.set_remote_description(answer) catch {
    InvalidState(_) => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("answer in stable state was accepted")
  }
  signaling.close()
  signaling.close()
  assert_eq(signaling.state(), Closed)
  let offer = description_for_test(Offer, ActPass, 2UL)
  try signaling.set_local_description(offer) catch {
    InvalidState(_) => ()
    _ => fail("unexpected SDP error")
  } noraise {
    _ => fail("closed signaling state accepted an offer")
  }
}
