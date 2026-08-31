///|
pub(all) suberror SdpError {
  InvalidSyntax(String)
  UnsupportedAttribute(String)
  InvalidState(String)
} derive(Debug, Eq)

///|
pub using @ice {type IceCredentials}

///|
pub(all) enum SdpType {
  Offer
  Pranswer
  Answer
  Rollback
} derive(Debug, Eq)

///|
pub(all) enum SignalingState {
  Stable
  HaveLocalOffer
  HaveRemoteOffer
  HaveLocalPranswer
  HaveRemotePranswer
  Closed
} derive(Debug, Eq)

///|
pub struct SessionDescription {
  sdp_type : SdpType
  sdp : String
} derive(Debug, Eq)

///|
pub fn SessionDescription::new(
  sdp_type~ : SdpType,
  sdp~ : String,
) -> SessionDescription {
  { sdp_type, sdp, }
}

///|
pub fn SessionDescription::sdp_type(self : SessionDescription) -> SdpType {
  self.sdp_type
}

///|
pub fn SessionDescription::sdp(self : SessionDescription) -> String {
  self.sdp
}
