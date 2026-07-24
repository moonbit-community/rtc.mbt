///|
fn command_message(command : DataChannelCommand) -> @sctp.Message {
  match command {
    SendSctp(message, _) => message
    ResetSctpStream(_) => abort("expected an SCTP send command")
  }
}

///|
fn expect_open_event(manager : Manager, stream : @sctp.StreamId) -> Bool {
  match manager.poll_event() {
    Some(Opened(channel)) => channel.id() == stream && channel.state() == Open
    _ => false
  }
}

///|
test "DCEP managers allocate parity, open, exchange text, and close both streams" {
  let client = Manager::new(role=DtlsClient)
  let server = Manager::new(role=DtlsServer)
  let created = client.create_channel(DataChannelConfig::new(label="chat"))
  assert_eq(created.id().value(), 0)
  assert_eq(created.state(), Connecting)
  client.handle_sctp_event(StateChanged(Established))
  server.handle_sctp_event(StateChanged(Established))
  guard client.poll_command() is Some(open_command) else {
    fail("client did not queue DCEP OPEN")
  }
  let open_message = command_message(open_command)
  assert_eq(open_message.stream().value(), 0)
  assert_eq(open_message.protocol_id(), 50U)
  server.handle_sctp_event(MessageReceived(open_message))
  assert_true(expect_open_event(server, StreamId(0)))
  guard server.poll_command() is Some(ack_command) else {
    fail("server did not queue DCEP ACK")
  }
  client.handle_sctp_event(MessageReceived(command_message(ack_command)))
  assert_true(expect_open_event(client, StreamId(0)))
  client.send(StreamId(0), Text("hello 🌙"))
  guard client.poll_command() is Some(text_command) else {
    fail("client did not queue data")
  }
  server.handle_sctp_event(MessageReceived(command_message(text_command)))
  assert_eq(
    server.poll_event(),
    Some(MessageReceived(StreamId(0), Text("hello 🌙"))),
  )

  client.close_channel(StreamId(0))
  assert_eq(client.channel(StreamId(0)).unwrap().state(), Closing)
  guard client.poll_command() is Some(ResetSctpStream(client_stream)) else {
    fail("client did not request outgoing stream reset")
  }
  server.handle_sctp_event(StreamReset(client_stream))
  guard server.poll_command() is Some(ResetSctpStream(server_stream)) else {
    fail("server did not reset its outgoing stream")
  }
  client.handle_sctp_event(StreamResetAcknowledged(client_stream))
  assert_eq(client.poll_event(), None)
  client.handle_sctp_event(StreamReset(server_stream))
  guard client.poll_event() is Some(ClosedEvent(closed_client)) else {
    fail("client did not close after both stream directions reset")
  }
  assert_eq(closed_client, StreamId(0))
  server.handle_sctp_event(StreamResetAcknowledged(server_stream))
  guard server.poll_event() is Some(ClosedEvent(closed_server)) else {
    fail("server did not close after both stream directions reset")
  }
  assert_eq(closed_server, StreamId(0))
}

///|
test "negotiated channels open without DCEP and may use either parity" {
  let manager = Manager::new(role=DtlsClient)
  let channel = manager.create_channel(
    DataChannelConfig::new(label="negotiated", negotiated=true, id=StreamId(7)),
  )
  assert_eq(channel.state(), Connecting)
  manager.handle_sctp_event(StateChanged(Established))
  assert_true(expect_open_event(manager, StreamId(7)))
  assert_eq(manager.poll_command(), None)
}

///|
test "pending in-band channels follow a late DTLS role decision" {
  let manager = Manager::new(role=DtlsServer)
  let automatic = manager.create_channel(
    DataChannelConfig::new(label="late-role"),
  )
  let negotiated = manager.create_channel(
    DataChannelConfig::new(label="fixed", negotiated=true, id=StreamId(7)),
  )
  assert_eq(automatic.id(), StreamId(1))
  assert_eq(manager.set_role(DtlsClient), [(StreamId(1), StreamId(0))])
  assert_eq(automatic.id(), StreamId(0))
  assert_eq(negotiated.id(), StreamId(7))
  manager.handle_sctp_event(StateChanged(Established))
  guard manager.poll_command() is Some(command) else {
    fail("remapped channel did not send DCEP OPEN")
  }
  assert_eq(command_message(command).stream(), StreamId(0))
}

///|
test "DCEP rejects peer parity collisions and data before open" {
  let manager = Manager::new(role=DtlsClient)
  manager.handle_sctp_event(StateChanged(Established))
  let invalid_open = @sctp.Message::new(
    stream=StreamId(2),
    protocol_id=50U,
    payload=DcepMessage::Open(
      DcepOpen::new(channel_type=ReliableChannel, label="wrong parity"),
    ).encode(),
  )
  try manager.handle_sctp_event(MessageReceived(invalid_open)) catch {
    ProtocolViolation(_) => ()
    _ => fail("unexpected parity error")
  } noraise {
    _ => fail("peer-parity violation was accepted")
  }
  let pending = manager.create_channel(DataChannelConfig::new(label="pending"))
  try
    manager.handle_sctp_event(
      MessageReceived(
        @sctp.Message::new(
          stream=pending.id(),
          protocol_id=51U,
          payload=b"too soon",
        ),
      ),
    )
  catch {
    ProtocolViolation(_) => ()
    _ => fail("unexpected premature-data error")
  } noraise {
    _ => fail("data before DCEP ACK was accepted")
  }
}
