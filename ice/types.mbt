///|
pub(all) suberror IceError {
  InvalidCandidate(String)
  InvalidCredentials
  InvalidState(String)
  RoleConflict
  ChecklistFailed
  Time(@transport.TimeError)
  Stun(@stun.StunError)
  Turn(@turn.TurnError)
  Mdns(@mdns.MdnsError)
} derive(Debug, Eq)

///|
pub(all) enum CandidateType {
  Host
  ServerReflexive
  PeerReflexive
  Relay
} derive(Debug, Eq)

///|
pub(all) enum IceTransportPolicy {
  All
  Relay
} derive(Debug, Eq)

///|
pub(all) enum IceRole {
  Controlling
  Controlled
} derive(Debug, Eq)

///|
pub(all) enum TcpCandidateType {
  Active
  Passive
  SimultaneousOpen
} derive(Debug, Eq)

///|
pub(all) enum CandidateAddress {
  IpAddress(@transport.IpAddress)
  MdnsName(String)
} derive(Debug, Eq)

///|
pub(all) enum IceGatheringState {
  New
  Gathering
  Complete
} derive(Debug, Eq)

///|
pub(all) enum IceConnectionState {
  New
  Checking
  Connected
  Completed
  Disconnected
  Failed
  Closed
} derive(Debug, Eq)

///|
pub(all) enum SrflxGatheringState {
  SrflxNew
  SrflxGathering
  SrflxComplete
  SrflxFailed
  SrflxClosed
} derive(Debug, Eq)

///|
pub(all) enum SrflxEvent {
  ServerReflexiveCandidate(IceCandidate)
  SrflxStateChanged(SrflxGatheringState)
} derive(Debug, Eq)

///|
pub struct IceCandidate {
  foundation : String
  component : UInt16
  protocol : @transport.TransportProtocol
  priority : UInt
  address : CandidateAddress
  port : UInt16
  candidate_type : CandidateType
  related_address : CandidateAddress?
  related_port : UInt16?
  tcp_type : TcpCandidateType?
  extensions : Array[(String, String)]
} derive(Debug, Eq)
