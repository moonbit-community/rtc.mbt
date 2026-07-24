///|
pub(all) suberror MdnsError {
  InvalidName(String)
  InvalidPacket(String)
  QueryTimedOut
  NameConflict(String)
  UnsupportedMode
  Time(@transport.TimeError)
} derive(Debug, Eq)

///|
pub(all) enum Mode {
  QueryOnly
  QueryAndGather
} derive(Debug, Eq)

///|
pub(all) struct Query {
  name : String
  now : @transport.Instant
} derive(Debug, Eq)

///|
pub(all) struct Resolution {
  name : String
  addresses : Array[@transport.IpAddress]
  expires_at : @transport.Instant
} derive(Debug, Eq)

///|
pub(all) struct QueryId(UInt64) derive(Debug, Eq, Hash)

///|
pub(all) enum MdnsEvent {
  Resolved(QueryId, Resolution)
  TimedOut(QueryId)
  Cancelled(QueryId)
} derive(Debug, Eq)

///|
pub struct OutboundQuery {
  query_id : QueryId
  destination : @transport.SocketAddress
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn OutboundQuery::query_id(self : OutboundQuery) -> QueryId {
  self.query_id
}

///|
pub fn OutboundQuery::destination(
  self : OutboundQuery,
) -> @transport.SocketAddress {
  self.destination
}

///|
pub fn OutboundQuery::payload(self : OutboundQuery) -> Bytes {
  self.payload
}

///|
pub fn Resolution::name(self : Resolution) -> String {
  self.name
}

///|
pub fn Resolution::addresses(self : Resolution) -> Array[@transport.IpAddress] {
  self.addresses.copy()
}

///|
pub fn Resolution::expires_at(self : Resolution) -> @transport.Instant {
  self.expires_at
}
