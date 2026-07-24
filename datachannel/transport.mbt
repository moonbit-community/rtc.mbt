///|
fn[T] from_sctp(
  operation : () -> T raise @sctp.SctpError,
) -> T raise DataChannelError {
  operation() catch {
    error => raise Sctp(error)
  }
}

///|
pub struct Transport {
  association : @sctp.Association
  manager : Manager
}

///|
pub fn Transport::new(
  role~ : StreamRole,
  association_config~ : @sctp.AssociationConfig,
) -> Transport raise DataChannelError {
  Transport::with_manager(manager=Manager::new(role~), association_config~)
}

///|
pub fn Transport::with_manager(
  manager~ : Manager,
  association_config~ : @sctp.AssociationConfig,
) -> Transport raise DataChannelError {
  let role = manager.role()
  let expected_role : @sctp.AssociationRole = if role == DtlsClient {
    Active
  } else {
    Passive
  }
  if association_config.role() != expected_role {
    raise InvalidConfiguration(
      "SCTP association role does not match the DTLS stream-id role",
    )
  }
  {
    association: from_sctp(() => @sctp.Association::new(association_config)),
    manager,
  }
}

///|
fn Transport::pump(
  self : Transport,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  while self.association.poll_event() is Some(event) {
    self.manager.handle_sctp_event(event)
  }
  while self.manager.poll_command() is Some(command) {
    match command {
      SendSctp(message, reliability) =>
        from_sctp(() => self.association.send(message, reliability~, now~))
      ResetSctpStream(stream) =>
        from_sctp(() => self.association.reset_stream(stream, now))
    }
  }
}

///|
pub fn Transport::start(
  self : Transport,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  from_sctp(() => self.association.start(now))
  self.pump(now)
}

///|
pub fn Transport::handle_datagram(
  self : Transport,
  now : @transport.Instant,
  datagram : Bytes,
) -> Unit raise DataChannelError {
  from_sctp(() => self.association.handle_datagram(now, datagram))
  self.pump(now)
}

///|
pub fn Transport::poll_datagram(self : Transport) -> Bytes? {
  self.association.poll_datagram()
}

///|
pub fn Transport::create_channel(
  self : Transport,
  config : DataChannelConfig,
  now : @transport.Instant,
) -> DataChannel raise DataChannelError {
  let channel = self.manager.create_channel(config)
  self.pump(now)
  channel
}

///|
pub fn Transport::channel(
  self : Transport,
  stream : @sctp.StreamId,
) -> DataChannel? {
  self.manager.channel(stream)
}

///|
pub fn Transport::send(
  self : Transport,
  stream : @sctp.StreamId,
  message : DataChannelMessage,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  self.manager.send(stream, message)
  self.pump(now)
}

///|
pub fn Transport::close_channel(
  self : Transport,
  stream : @sctp.StreamId,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  self.manager.close_channel(stream)
  self.pump(now)
}

///|
pub fn Transport::buffered_amount(
  self : Transport,
  stream : @sctp.StreamId,
) -> UInt64 {
  self.association.buffered_amount(stream)
}

///|
pub fn Transport::set_buffered_amount_low_threshold(
  self : Transport,
  stream : @sctp.StreamId,
  threshold : UInt64,
) -> Unit {
  self.association.set_buffered_amount_low_threshold(stream, threshold)
}

///|
pub fn Transport::poll_event(self : Transport) -> DataChannelEvent? {
  self.manager.poll_event()
}

///|
pub fn Transport::poll_timeout(self : Transport) -> @transport.Instant? {
  self.association.poll_timeout()
}

///|
pub fn Transport::handle_timeout(
  self : Transport,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  from_sctp(() => self.association.handle_timeout(now))
  self.pump(now)
}

///|
pub fn Transport::close(
  self : Transport,
  now : @transport.Instant,
) -> Unit raise DataChannelError {
  from_sctp(() => self.association.close(now))
  self.pump(now)
}

///|
pub fn Transport::association_state(self : Transport) -> @sctp.AssociationState {
  self.association.state()
}
