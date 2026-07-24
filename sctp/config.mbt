///|
pub struct AssociationConfig {
  role : AssociationRole
  local_port : UInt16
  remote_port : UInt16
  max_message_size : UInt64
  max_payload_size : Int
  send_buffer_size : UInt64
  receive_buffer_size : UInt
  initial_tag : UInt?
  initial_tsn : UInt?
  initial_rto : @transport.Duration
}

///|
pub fn AssociationConfig::new(
  role~ : AssociationRole,
  local_port? : UInt16 = 5000,
  remote_port? : UInt16 = 5000,
  max_message_size? : UInt64 = 262144UL,
  max_payload_size? : Int = 1100,
  send_buffer_size? : UInt64 = 1048576UL,
  receive_buffer_size? : UInt = 1048576U,
  initial_tag? : UInt,
  initial_tsn? : UInt,
  initial_rto? : @transport.Duration,
) -> AssociationConfig raise SctpError {
  if local_port == 0 || remote_port == 0 {
    raise InvalidPacket("SCTP ports must be nonzero")
  }
  if max_message_size == 0UL ||
    max_payload_size < 1 ||
    max_payload_size > 0xffef ||
    send_buffer_size == 0UL ||
    receive_buffer_size < 1500U {
    raise InvalidState("invalid SCTP size limit")
  }
  match initial_tag {
    Some(0) => raise InvalidState("SCTP initiate tag must be nonzero")
    _ => ()
  }
  let initial_rto = match initial_rto {
    Some(value) => value
    None =>
      @transport.Duration::milliseconds(1000) catch {
        error => raise Time(error)
      }
  }
  if initial_rto.as_milliseconds() == 0L {
    raise InvalidState("SCTP retransmission timeout must be positive")
  }
  {
    role,
    local_port,
    remote_port,
    max_message_size,
    max_payload_size,
    send_buffer_size,
    receive_buffer_size,
    initial_tag,
    initial_tsn,
    initial_rto,
  }
}

///|
pub fn AssociationConfig::role(self : AssociationConfig) -> AssociationRole {
  self.role
}
