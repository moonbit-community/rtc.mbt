///|
pub(all) suberror DataChannelError {
  InvalidConfiguration(String)
  ProtocolViolation(String)
  BufferFull
  Sctp(@sctp.SctpError)
  Closed
} derive(Debug, Eq)

///|
pub(all) enum DataChannelState {
  Connecting
  Open
  Closing
  Closed
} derive(Debug, Eq)

///|
pub(all) enum DataChannelMessage {
  Text(String)
  Binary(Bytes)
} derive(Debug, Eq)

///|
pub struct DataChannelConfig {
  label : String
  protocol : String
  ordering : @sctp.Ordering
  reliability : @sctp.Reliability
  negotiated : Bool
  id : @sctp.StreamId?
  priority : UInt16
} derive(Debug, Eq)

///|
pub fn DataChannelConfig::new(
  label~ : String,
  protocol? : String = "",
  ordering? : @sctp.Ordering = Ordered,
  reliability? : @sctp.Reliability = Reliable,
  negotiated? : Bool = false,
  id? : @sctp.StreamId,
  priority? : UInt16 = 256,
) -> DataChannelConfig raise DataChannelError {
  let label_length = @utf8.encode(label).length()
  let protocol_length = @utf8.encode(protocol).length()
  if label_length > 65535 {
    raise InvalidConfiguration("data channel label exceeds 65535 UTF-8 bytes")
  }
  if protocol_length > 65535 {
    raise InvalidConfiguration(
      "data channel protocol exceeds 65535 UTF-8 bytes",
    )
  }
  if negotiated && id is None {
    raise InvalidConfiguration(
      "an out-of-band negotiated data channel requires a stream id",
    )
  }
  match id {
    Some(stream) if stream.value() == 0xffff =>
      raise InvalidConfiguration("SCTP stream id 65535 is not negotiable")
    _ => ()
  }
  { label, protocol, ordering, reliability, negotiated, id, priority, }
}

///|
pub fn DataChannelConfig::label(self : DataChannelConfig) -> String {
  self.label
}

///|
pub fn DataChannelConfig::protocol(self : DataChannelConfig) -> String {
  self.protocol
}

///|
pub fn DataChannelConfig::ordering(self : DataChannelConfig) -> @sctp.Ordering {
  self.ordering
}

///|
pub fn DataChannelConfig::reliability(
  self : DataChannelConfig,
) -> @sctp.Reliability {
  self.reliability
}

///|
pub fn DataChannelConfig::is_negotiated(self : DataChannelConfig) -> Bool {
  self.negotiated
}

///|
pub fn DataChannelConfig::id(self : DataChannelConfig) -> @sctp.StreamId? {
  self.id
}

///|
pub fn DataChannelConfig::priority(self : DataChannelConfig) -> UInt16 {
  self.priority
}

///|
pub struct DataChannel {
  mut id : @sctp.StreamId
  label : String
  protocol : String
  ordering : @sctp.Ordering
  reliability : @sctp.Reliability
  negotiated : Bool
  priority : UInt16
  mut state : DataChannelState
} derive(Debug, Eq)

///|
pub fn DataChannel::new(
  id~ : @sctp.StreamId,
  label~ : String,
  protocol? : String = "",
  ordering? : @sctp.Ordering = Ordered,
  reliability? : @sctp.Reliability = Reliable,
  negotiated? : Bool = false,
  priority? : UInt16 = 256,
) -> DataChannel {
  {
    id,
    label,
    protocol,
    ordering,
    reliability,
    negotiated,
    priority,
    state: Connecting,
  }
}

///|
pub fn DataChannel::id(self : DataChannel) -> @sctp.StreamId {
  self.id
}

///|
pub fn DataChannel::label(self : DataChannel) -> String {
  self.label
}

///|
pub fn DataChannel::protocol(self : DataChannel) -> String {
  self.protocol
}

///|
pub fn DataChannel::state(self : DataChannel) -> DataChannelState {
  self.state
}

///|
pub fn DataChannel::ordering(self : DataChannel) -> @sctp.Ordering {
  self.ordering
}

///|
pub fn DataChannel::reliability(self : DataChannel) -> @sctp.Reliability {
  self.reliability
}

///|
pub fn DataChannel::is_negotiated(self : DataChannel) -> Bool {
  self.negotiated
}

///|
pub fn DataChannel::priority(self : DataChannel) -> UInt16 {
  self.priority
}

///|
pub(all) enum StreamRole {
  DtlsClient
  DtlsServer
} derive(Debug, Eq)

///|
pub(all) enum ChannelType {
  ReliableChannel
  ReliableUnorderedChannel
  PartialReliableRetransmitChannel
  PartialReliableRetransmitUnorderedChannel
  PartialReliableTimedChannel
  PartialReliableTimedUnorderedChannel
} derive(Debug, Eq)

///|
pub struct DcepOpen {
  channel_type : ChannelType
  priority : UInt16
  reliability_parameter : UInt
  label : String
  protocol : String
} derive(Debug, Eq)

///|
pub fn DcepOpen::new(
  channel_type~ : ChannelType,
  priority? : UInt16 = 256,
  reliability_parameter? : UInt = 0U,
  label~ : String,
  protocol? : String = "",
) -> DcepOpen raise DataChannelError {
  let label_length = @utf8.encode(label).length()
  let protocol_length = @utf8.encode(protocol).length()
  if label_length > 65535 || protocol_length > 65535 {
    raise InvalidConfiguration(
      "DCEP label and protocol must each fit in 65535 UTF-8 bytes",
    )
  }
  { channel_type, priority, reliability_parameter, label, protocol, }
}

///|
pub fn DcepOpen::channel_type(self : DcepOpen) -> ChannelType {
  self.channel_type
}

///|
pub fn DcepOpen::priority(self : DcepOpen) -> UInt16 {
  self.priority
}

///|
pub fn DcepOpen::reliability_parameter(self : DcepOpen) -> UInt {
  self.reliability_parameter
}

///|
pub fn DcepOpen::label(self : DcepOpen) -> String {
  self.label
}

///|
pub fn DcepOpen::protocol(self : DcepOpen) -> String {
  self.protocol
}

///|
pub(all) enum DcepMessage {
  Open(DcepOpen)
  Acknowledgement
} derive(Debug, Eq)

///|
pub(all) enum PayloadProtocolIdentifier {
  Dcep
  StringPayload
  BinaryPayload
  StringEmptyPayload
  BinaryEmptyPayload
} derive(Debug, Eq)

///|
pub fn PayloadProtocolIdentifier::code(
  self : PayloadProtocolIdentifier,
) -> UInt {
  match self {
    Dcep => 50U
    StringPayload => 51U
    BinaryPayload => 53U
    StringEmptyPayload => 56U
    BinaryEmptyPayload => 57U
  }
}

///|
pub(all) enum DataChannelEvent {
  Opened(DataChannel)
  MessageReceived(@sctp.StreamId, DataChannelMessage)
  ClosedEvent(@sctp.StreamId)
  BufferedAmountLowEvent(@sctp.StreamId)
} derive(Debug, Eq)

///|
pub(all) enum DataChannelCommand {
  SendSctp(@sctp.Message, @sctp.Reliability)
  ResetSctpStream(@sctp.StreamId)
} derive(Debug, Eq)
