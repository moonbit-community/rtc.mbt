///|
pub(all) enum TransactionEventKind {
  Received(Message)
  TimedOut
  Stopped
  Closed
} derive(Debug, Eq)

///|
pub struct TransactionEvent {
  transaction_id : TransactionId
  event : TransactionEventKind
} derive(Debug, Eq)

///|
pub fn TransactionEvent::transaction_id(
  self : TransactionEvent,
) -> TransactionId {
  self.transaction_id
}

///|
pub fn TransactionEvent::event(self : TransactionEvent) -> TransactionEventKind {
  self.event
}

///|
pub struct TransactionAgent {
  transactions : Map[TransactionId, @transport.Instant]
  events : @queue.Queue[TransactionEvent]
  mut closed : Bool
}

///|
pub fn TransactionAgent::new() -> TransactionAgent {
  { transactions: Map([]), events: Queue([]), closed: false }
}

///|
pub fn TransactionAgent::is_closed(self : TransactionAgent) -> Bool {
  self.closed
}

///|
pub fn TransactionAgent::transaction_count(self : TransactionAgent) -> Int {
  self.transactions.length()
}

///|
pub fn TransactionAgent::start(
  self : TransactionAgent,
  transaction_id : TransactionId,
  deadline : @transport.Instant,
) -> Unit raise StunError {
  if self.closed {
    raise AgentClosed
  }
  if self.transactions.contains(transaction_id) {
    raise TransactionAlreadyExists
  }
  self.transactions[transaction_id] = deadline
}

///|
pub fn TransactionAgent::process(
  self : TransactionAgent,
  message : Message,
) -> Unit raise StunError {
  if self.closed {
    raise AgentClosed
  }
  let transaction_id = message.transaction_id
  self.transactions.remove(transaction_id)
  self.events.push({ transaction_id, event: Received(message) })
}

///|
pub fn TransactionAgent::stop(
  self : TransactionAgent,
  transaction_id : TransactionId,
) -> Unit raise StunError {
  if self.closed {
    raise AgentClosed
  }
  if !self.transactions.contains(transaction_id) {
    raise TransactionNotFound
  }
  self.transactions.remove(transaction_id)
  self.events.push({ transaction_id, event: Stopped })
}

///|
pub fn TransactionAgent::collect(
  self : TransactionAgent,
  now : @transport.Instant,
) -> Unit raise StunError {
  if self.closed {
    raise AgentClosed
  }
  let expired : Array[TransactionId] = []
  self.transactions.each((transaction_id, deadline) => {
    if deadline <= now {
      expired.push(transaction_id)
    }
  })
  for transaction_id in expired {
    self.transactions.remove(transaction_id)
    self.events.push({ transaction_id, event: TimedOut })
  }
}

///|
pub fn TransactionAgent::poll_timeout(
  self : TransactionAgent,
) -> @transport.Instant? {
  let mut result : @transport.Instant? = None
  for deadline in self.transactions.values() {
    match result {
      None => result = Some(deadline)
      Some(current) => if deadline < current { result = Some(deadline) }
    }
  }
  result
}

///|
pub fn TransactionAgent::poll_event(
  self : TransactionAgent,
) -> TransactionEvent? {
  self.events.pop()
}

///|
pub fn TransactionAgent::close(self : TransactionAgent) -> Unit raise StunError {
  if self.closed {
    raise AgentClosed
  }
  for transaction_id in self.transactions.keys() {
    self.events.push({ transaction_id, event: Closed })
  }
  self.transactions.clear()
  self.closed = true
}
