///|
priv struct FragmentAssembly {
  handshake_type : HandshakeType
  total_length : Int
  message_sequence : UInt16
  bytes : Array[Byte]
  present : Array[Bool]
  mut present_count : Int
}

///|
fn FragmentAssembly::new(
  fragment : HandshakeFragment,
) -> FragmentAssembly raise DtlsError {
  let total_length = fragment.total_length.reinterpret_as_int()
  if total_length < 0 || total_length > 1048576 {
    raise InvalidHandshake(
      "DTLS handshake message exceeds the 1 MiB implementation limit",
    )
  }
  {
    handshake_type: fragment.handshake_type,
    total_length,
    message_sequence: fragment.message_sequence,
    bytes: Array::make(total_length, 0),
    present: Array::make(total_length, false),
    present_count: 0,
  }
}

///|
fn FragmentAssembly::insert(
  self : FragmentAssembly,
  fragment : HandshakeFragment,
) -> Unit raise DtlsError {
  if fragment.handshake_type != self.handshake_type ||
    fragment.total_length.reinterpret_as_int() != self.total_length ||
    fragment.message_sequence != self.message_sequence {
    raise InvalidHandshake("inconsistent DTLS handshake fragments")
  }
  let offset = fragment.fragment_offset.reinterpret_as_int()
  for index = 0; index < fragment.body.length(); index = index + 1 {
    let destination = offset + index
    if self.present[destination] {
      if self.bytes[destination] != fragment.body[index] {
        raise InvalidHandshake("overlapping DTLS fragments disagree")
      }
    } else {
      self.bytes[destination] = fragment.body[index]
      self.present[destination] = true
      self.present_count += 1
    }
  }
}

///|
fn FragmentAssembly::complete(self : FragmentAssembly) -> Bool {
  self.present_count == self.total_length
}

///|
fn FragmentAssembly::finish(
  self : FragmentAssembly,
) -> HandshakeFragment raise DtlsError {
  if !self.complete() {
    raise InvalidHandshake("DTLS handshake reassembly is incomplete")
  }
  HandshakeFragment::new(
    handshake_type=self.handshake_type,
    total_length=self.total_length.reinterpret_as_uint(),
    message_sequence=self.message_sequence,
    fragment_offset=0,
    body=Bytes::from_array(self.bytes),
  )
}

///|
struct FragmentBuffer {
  assemblies : Map[UInt16, FragmentAssembly]
  completed : Map[UInt16, HandshakeFragment]
  mut expected_sequence : UInt16
}

///|
fn FragmentBuffer::new(expected_sequence? : UInt16 = 0) -> FragmentBuffer {
  { assemblies: Map([]), completed: Map([]), expected_sequence }
}

///|
fn FragmentBuffer::insert(
  self : FragmentBuffer,
  fragment : HandshakeFragment,
) -> (Array[HandshakeFragment], Bool) raise DtlsError {
  if fragment.message_sequence < self.expected_sequence {
    return ([], true)
  }
  if !self.completed.contains(fragment.message_sequence) {
    if fragment.is_complete() {
      self.completed[fragment.message_sequence] = fragment
    } else {
      let assembly = match self.assemblies.get(fragment.message_sequence) {
        Some(assembly) => assembly
        None => {
          let assembly = FragmentAssembly::new(fragment)
          self.assemblies[fragment.message_sequence] = assembly
          assembly
        }
      }
      assembly.insert(fragment)
      if assembly.complete() {
        self.completed[fragment.message_sequence] = assembly.finish()
        self.assemblies.remove(fragment.message_sequence)
      }
    }
  }
  let ready : Array[HandshakeFragment] = []
  while self.completed.get(self.expected_sequence) is Some(fragment) {
    ready.push(fragment)
    self.completed.remove(self.expected_sequence)
    if self.expected_sequence == 0xffff {
      raise InvalidHandshake("DTLS handshake sequence number wrapped")
    }
    self.expected_sequence += 1
  }
  (ready, false)
}
