///|
pub(all) struct ConnectionId(UInt64) derive(Debug, Eq, Hash)

///|
pub(all) struct ListenerId(UInt64) derive(Debug, Eq, Hash)

///|
pub(all) struct TransportContext {
  local_address : SocketAddress
  peer : SocketAddress
  ecn : EcnCodepoint?
  protocol : TransportProtocol
} derive(Debug, Eq)

///|
pub(all) struct InboundDatagram {
  now : Instant
  context : TransportContext
  payload : Bytes
} derive(Debug, Eq)

///|
pub(all) struct OutboundDatagram {
  context : TransportContext
  payload : Bytes
} derive(Debug, Eq)

///|
pub(all) enum IoEvent {
  DatagramReceived(InboundDatagram)
  StreamConnected(
    now~ : Instant,
    connection~ : ConnectionId,
    context~ : TransportContext
  )
  StreamAccepted(
    now~ : Instant,
    listener~ : ListenerId,
    connection~ : ConnectionId,
    context~ : TransportContext
  )
  StreamBytes(now~ : Instant, connection~ : ConnectionId, bytes~ : Bytes)
  StreamWritable(now~ : Instant, connection~ : ConnectionId)
  StreamEof(now~ : Instant, connection~ : ConnectionId)
  StreamError(now~ : Instant, connection~ : ConnectionId, reason~ : String)
  StreamClosed(now~ : Instant, connection~ : ConnectionId)
} derive(Debug, Eq)

///|
pub(all) enum IoAction {
  SendDatagram(OutboundDatagram)
  ConnectTcp(
    connection~ : ConnectionId,
    local_address~ : SocketAddress?,
    peer~ : SocketAddress
  )
  ConnectTls(
    connection~ : ConnectionId,
    local_address~ : SocketAddress?,
    peer~ : SocketAddress,
    server_name~ : String?
  )
  ListenTcp(listener~ : ListenerId, local_address~ : SocketAddress)
  WriteStream(connection~ : ConnectionId, bytes~ : Bytes)
  CloseStream(ConnectionId)
  CloseListener(ListenerId)
} derive(Debug, Eq)
