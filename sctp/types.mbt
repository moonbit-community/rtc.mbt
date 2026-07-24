///|
pub(all) suberror SctpError {
  InvalidPacket(String)
  ChecksumMismatch
  InvalidState(String)
  AssociationFailed(String)
  StreamResetFailed(UInt16)
  MessageTooLarge(UInt64)
  BufferFull
  Time(@transport.TimeError)
  CryptoUnavailable(String)
  Closed
} derive(Debug, Eq)

///|
pub(all) enum Reliability {
  Reliable
  RetransmitCount(UInt16)
  Timed(UInt)
} derive(Debug, Eq)

///|
pub(all) enum Ordering {
  Ordered
  Unordered
} derive(Debug, Eq)

///|
pub(all) struct StreamId(UInt16) derive(Debug, Eq, Hash)

///|
pub fn StreamId::value(self : StreamId) -> UInt16 {
  let StreamId(value) = self
  value
}

///|
pub struct Message {
  stream : StreamId
  protocol_id : UInt
  unordered : Bool
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn Message::new(
  stream~ : StreamId,
  protocol_id~ : UInt,
  unordered? : Bool = false,
  payload~ : Bytes,
) -> Message {
  { stream, protocol_id, unordered, payload }
}

///|
pub fn Message::stream(self : Message) -> StreamId {
  self.stream
}

///|
pub fn Message::protocol_id(self : Message) -> UInt {
  self.protocol_id
}

///|
pub fn Message::is_unordered(self : Message) -> Bool {
  self.unordered
}

///|
pub fn Message::payload(self : Message) -> Bytes {
  self.payload
}

///|
pub(all) enum AssociationRole {
  Active
  Passive
} derive(Debug, Eq)

///|
pub(all) enum AssociationState {
  ClosedState
  CookieWait
  CookieEchoed
  Established
  ShutdownPending
  ShutdownSent
  ShutdownReceived
  ShutdownAckSent
} derive(Debug, Eq)

///|
pub(all) enum AssociationEvent {
  StateChanged(AssociationState)
  MessageReceived(Message)
  StreamReset(StreamId)
  StreamResetAcknowledged(StreamId)
  BufferedAmountLow(StreamId)
} derive(Debug, Eq)

///|
pub(all) enum Parameter {
  StateCookieParameter(Bytes)
  SupportedExtensionsParameter(Bytes)
  ForwardTsnSupportedParameter
  UnknownParameter(UInt16, Bytes)
} derive(Debug, Eq)

///|
pub struct InitChunk {
  acknowledgement : Bool
  initiate_tag : UInt
  advertised_receiver_window : UInt
  outbound_streams : UInt16
  inbound_streams : UInt16
  initial_tsn : UInt
  parameters : Array[Parameter]
} derive(Debug, Eq)

///|
pub fn InitChunk::new(
  acknowledgement? : Bool = false,
  initiate_tag~ : UInt,
  advertised_receiver_window? : UInt = 1048576U,
  outbound_streams? : UInt16 = 65535,
  inbound_streams? : UInt16 = 65535,
  initial_tsn~ : UInt,
  parameters? : Array[Parameter] = [],
) -> InitChunk raise SctpError {
  if initiate_tag == 0U {
    raise InvalidPacket("SCTP initiate tag must be nonzero")
  }
  if outbound_streams == 0 || inbound_streams == 0 {
    raise InvalidPacket("SCTP stream counts must be nonzero")
  }
  {
    acknowledgement,
    initiate_tag,
    advertised_receiver_window,
    outbound_streams,
    inbound_streams,
    initial_tsn,
    parameters: parameters.copy(),
  }
}

///|
pub fn InitChunk::is_acknowledgement(self : InitChunk) -> Bool {
  self.acknowledgement
}

///|
pub fn InitChunk::initiate_tag(self : InitChunk) -> UInt {
  self.initiate_tag
}

///|
pub fn InitChunk::initial_tsn(self : InitChunk) -> UInt {
  self.initial_tsn
}

///|
pub fn InitChunk::advertised_receiver_window(self : InitChunk) -> UInt {
  self.advertised_receiver_window
}

///|
pub fn InitChunk::outbound_streams(self : InitChunk) -> UInt16 {
  self.outbound_streams
}

///|
pub fn InitChunk::inbound_streams(self : InitChunk) -> UInt16 {
  self.inbound_streams
}

///|
pub fn InitChunk::parameters(self : InitChunk) -> Array[Parameter] {
  self.parameters.copy()
}

///|
pub struct DataChunk {
  unordered : Bool
  beginning : Bool
  ending : Bool
  immediate_sack : Bool
  tsn : UInt
  stream : StreamId
  stream_sequence : UInt16
  protocol_id : UInt
  user_data : Bytes
} derive(Debug, Eq)

///|
pub fn DataChunk::new(
  unordered? : Bool = false,
  beginning? : Bool = true,
  ending? : Bool = true,
  immediate_sack? : Bool = false,
  tsn~ : UInt,
  stream~ : StreamId,
  stream_sequence~ : UInt16,
  protocol_id~ : UInt,
  user_data~ : Bytes,
) -> DataChunk {
  {
    unordered,
    beginning,
    ending,
    immediate_sack,
    tsn,
    stream,
    stream_sequence,
    protocol_id,
    user_data,
  }
}

///|
pub fn DataChunk::tsn(self : DataChunk) -> UInt {
  self.tsn
}

///|
pub fn DataChunk::stream(self : DataChunk) -> StreamId {
  self.stream
}

///|
pub fn DataChunk::stream_sequence(self : DataChunk) -> UInt16 {
  self.stream_sequence
}

///|
pub fn DataChunk::protocol_id(self : DataChunk) -> UInt {
  self.protocol_id
}

///|
pub fn DataChunk::is_unordered(self : DataChunk) -> Bool {
  self.unordered
}

///|
pub fn DataChunk::is_beginning(self : DataChunk) -> Bool {
  self.beginning
}

///|
pub fn DataChunk::is_ending(self : DataChunk) -> Bool {
  self.ending
}

///|
pub fn DataChunk::user_data(self : DataChunk) -> Bytes {
  self.user_data
}

///|
pub(all) struct GapAckBlock {
  start : UInt16
  end : UInt16
} derive(Debug, Eq)

///|
pub struct SackChunk {
  cumulative_tsn_ack : UInt
  advertised_receiver_window : UInt
  gap_ack_blocks : Array[GapAckBlock]
  duplicate_tsns : Array[UInt]
} derive(Debug, Eq)

///|
pub fn SackChunk::new(
  cumulative_tsn_ack~ : UInt,
  advertised_receiver_window? : UInt = 1048576U,
  gap_ack_blocks? : Array[GapAckBlock] = [],
  duplicate_tsns? : Array[UInt] = [],
) -> SackChunk {
  {
    cumulative_tsn_ack,
    advertised_receiver_window,
    gap_ack_blocks: gap_ack_blocks.copy(),
    duplicate_tsns: duplicate_tsns.copy(),
  }
}

///|
pub fn SackChunk::cumulative_tsn_ack(self : SackChunk) -> UInt {
  self.cumulative_tsn_ack
}

///|
pub fn SackChunk::gap_ack_blocks(self : SackChunk) -> Array[GapAckBlock] {
  self.gap_ack_blocks.copy()
}

///|
pub fn SackChunk::duplicate_tsns(self : SackChunk) -> Array[UInt] {
  self.duplicate_tsns.copy()
}

///|
pub(all) enum ReconfigParameter {
  OutgoingResetRequest(
    request_sequence~ : UInt,
    response_sequence~ : UInt,
    sender_last_tsn~ : UInt,
    streams~ : Array[StreamId]
  )
  ReconfigResponse(request_sequence~ : UInt, result~ : UInt)
  UnknownReconfigParameter(UInt16, Bytes)
} derive(Debug, Eq)

///|
pub(all) struct ForwardTsnStream {
  stream : StreamId
  sequence : UInt16
} derive(Debug, Eq)

///|
pub fn ForwardTsnStream::new(
  stream~ : StreamId,
  sequence~ : UInt16,
) -> ForwardTsnStream {
  { stream, sequence }
}

///|
pub fn ForwardTsnStream::stream(self : ForwardTsnStream) -> StreamId {
  self.stream
}

///|
pub fn ForwardTsnStream::sequence(self : ForwardTsnStream) -> UInt16 {
  self.sequence
}

///|
pub struct ForwardTsn {
  new_cumulative_tsn : UInt
  streams : Array[ForwardTsnStream]
} derive(Debug, Eq)

///|
pub fn ForwardTsn::new(
  new_cumulative_tsn~ : UInt,
  streams? : Array[ForwardTsnStream] = [],
) -> ForwardTsn {
  { new_cumulative_tsn, streams: streams.copy() }
}

///|
pub fn ForwardTsn::new_cumulative_tsn(self : ForwardTsn) -> UInt {
  self.new_cumulative_tsn
}

///|
pub fn ForwardTsn::streams(self : ForwardTsn) -> Array[ForwardTsnStream] {
  self.streams.copy()
}

///|
pub(all) enum Chunk {
  InitChunkValue(InitChunk)
  DataChunkValue(DataChunk)
  SackChunkValue(SackChunk)
  HeartbeatChunk(Bytes)
  HeartbeatAckChunk(Bytes)
  AbortChunk(Bytes)
  ShutdownChunk(UInt)
  ShutdownAckChunk
  ErrorChunk(Bytes)
  CookieEchoChunk(Bytes)
  CookieAckChunk
  ShutdownCompleteChunk
  ReconfigChunk(Array[ReconfigParameter])
  ForwardTsnChunk(ForwardTsn)
  UnknownChunk(Byte, Byte, Bytes)
} derive(Debug, Eq)

///|
pub struct Packet {
  source_port : UInt16
  destination_port : UInt16
  verification_tag : UInt
  chunks : Array[Chunk]
} derive(Debug, Eq)

///|
pub fn Packet::new(
  source_port~ : UInt16,
  destination_port~ : UInt16,
  verification_tag~ : UInt,
  chunks~ : Array[Chunk],
) -> Packet raise SctpError {
  if source_port == 0 || destination_port == 0 {
    raise InvalidPacket("SCTP ports must be nonzero")
  }
  { source_port, destination_port, verification_tag, chunks: chunks.copy() }
}

///|
pub fn Packet::source_port(self : Packet) -> UInt16 {
  self.source_port
}

///|
pub fn Packet::destination_port(self : Packet) -> UInt16 {
  self.destination_port
}

///|
pub fn Packet::verification_tag(self : Packet) -> UInt {
  self.verification_tag
}

///|
pub fn Packet::chunks(self : Packet) -> Array[Chunk] {
  self.chunks.copy()
}
