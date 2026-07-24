///|
pub(all) suberror TurnError {
  InvalidConfiguration(String)
  InvalidState(String)
  InvalidPacket(String)
  InvalidResponse(String)
  AuthenticationFailed
  AllocationExpired
  PermissionMissing
  ChannelBindingMissing
  Transaction(@stun.StunError)
  Time(@transport.TimeError)
} derive(Debug, Eq)

///|
pub(all) enum TurnTransport {
  Udp
  Tcp
  Tls
} derive(Debug, Eq)

///|
pub(all) enum AllocationState {
  New
  Allocating
  Active
  Refreshing
  Closed
  Failed
} derive(Debug, Eq)

///|
pub(all) struct AllocationId(UInt64) derive(Debug, Eq, Hash)

///|
pub(all) struct RelayedAddress {
  address : @transport.SocketAddress
  server : @transport.SocketAddress
  transport : TurnTransport
} derive(Debug, Eq)

///|
pub fn RelayedAddress::address(
  self : RelayedAddress,
) -> @transport.SocketAddress {
  self.address
}

///|
pub fn RelayedAddress::server(
  self : RelayedAddress,
) -> @transport.SocketAddress {
  self.server
}

///|
pub fn RelayedAddress::transport(self : RelayedAddress) -> TurnTransport {
  self.transport
}

///|
pub struct TurnCredentials {
  username : String
  password : String
} derive(Debug, Eq)

///|
pub fn TurnCredentials::new(
  username~ : String,
  password~ : String,
) -> TurnCredentials raise TurnError {
  if username.is_empty() || password.is_empty() {
    raise InvalidConfiguration("TURN username and password must be nonempty")
  }
  { username, password }
}

///|
pub fn TurnCredentials::username(self : TurnCredentials) -> String {
  self.username
}

///|
pub fn TurnCredentials::password(self : TurnCredentials) -> String {
  self.password
}

///|
pub(all) enum AllocationEvent {
  AllocationStateChanged(AllocationState)
  AllocationCreated(RelayedAddress)
  PermissionCreated(@transport.SocketAddress)
  ChannelBound(peer~ : @transport.SocketAddress, channel~ : UInt16)
  PeerData(peer~ : @transport.SocketAddress, payload~ : Bytes)
} derive(Debug, Eq)
