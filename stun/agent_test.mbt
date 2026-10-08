///|
fn transaction_message(transaction_id : @stun.TransactionId) -> @stun.Message {
  @stun.Message::new(
    class=SuccessResponse,
    stun_method=Binding,
    transaction_id~,
  )
}

///|
test "transaction agent tracks exact deterministic deadlines" {
  let agent = @stun.TransactionAgent::new()
  let first = @stun.TransactionId::from_bytes(b"first-id-001")
  let second = @stun.TransactionId::from_bytes(b"second-id-02")
  let first_deadline = @transport.Instant::from_milliseconds(10)
  let second_deadline = @transport.Instant::from_milliseconds(20)
  agent.start(first, first_deadline)
  agent.start(second, second_deadline)
  assert_eq(agent.transaction_count(), 2)
  assert_eq(agent.poll_timeout(), Some(first_deadline))
  agent.collect(@transport.Instant::from_milliseconds(9))
  assert_eq(agent.poll_event(), None)
  agent.collect(first_deadline)
  guard agent.poll_event() is Some(event) else { fail("missing timeout event") }
  assert_eq(event.transaction_id(), first)
  assert_eq(event.event(), TimedOut)
  assert_eq(agent.poll_timeout(), Some(second_deadline))
}

///|
test "processing and stopping transactions produce one queued event" {
  let agent = @stun.TransactionAgent::new()
  let received_id = @stun.TransactionId::from_bytes(b"received-001")
  let stopped_id = @stun.TransactionId::from_bytes(b"stopped--001")
  let deadline = @transport.Instant::from_milliseconds(100)
  agent.start(received_id, deadline)
  agent.start(stopped_id, deadline)
  agent.process(transaction_message(received_id))
  agent.stop(stopped_id)
  guard agent.poll_event() is Some(received) else {
    fail("missing received event")
  }
  assert_eq(received.transaction_id(), received_id)
  assert_eq(received.event(), Received(transaction_message(received_id)))
  guard agent.poll_event() is Some(stopped) else {
    fail("missing stopped event")
  }
  assert_eq(stopped.transaction_id(), stopped_id)
  assert_eq(stopped.event(), Stopped)
  assert_eq(agent.poll_event(), None)
  assert_eq(agent.transaction_count(), 0)
}

///|
test "transaction agent rejects duplicates, missing stops, and use after close" {
  let agent = @stun.TransactionAgent::new()
  let transaction_id = @stun.TransactionId::from_bytes(b"close-id-001")
  let deadline = @transport.Instant::from_milliseconds(100)
  agent.start(transaction_id, deadline)
  try agent.start(transaction_id, deadline) catch {
    TransactionAlreadyExists => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("duplicate transaction was accepted")
  }
  let missing = @stun.TransactionId::from_bytes(b"missing-id01")
  try agent.stop(missing) catch {
    TransactionNotFound => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("missing transaction was stopped")
  }
  agent.close()
  assert_true(agent.is_closed())
  guard agent.poll_event() is Some(event) else {
    fail("close did not terminate the transaction")
  }
  assert_eq(event.transaction_id(), transaction_id)
  assert_eq(event.event(), Closed)
  try agent.process(transaction_message(transaction_id)) catch {
    AgentClosed => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("closed agent accepted a message")
  }
}
