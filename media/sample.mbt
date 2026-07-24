///|
pub(all) struct Sample {
  data : Bytes
  timestamp : @transport.WallTime
  duration : @transport.Duration
  packet_timestamp : UInt
  prev_dropped_packets : UInt16
  prev_padding_packets : UInt16
} derive(Debug, Eq)

///|
pub fn Sample::data(self : Sample) -> Bytes {
  self.data
}

///|
pub fn Sample::timestamp(self : Sample) -> @transport.WallTime {
  self.timestamp
}

///|
pub fn Sample::duration(self : Sample) -> @transport.Duration {
  self.duration
}

///|
pub fn Sample::packet_timestamp(self : Sample) -> UInt {
  self.packet_timestamp
}

///|
pub fn Sample::prev_dropped_packets(self : Sample) -> UInt16 {
  self.prev_dropped_packets
}

///|
pub fn Sample::prev_padding_packets(self : Sample) -> UInt16 {
  self.prev_padding_packets
}

///|
fn sample_forward_distance(from : UInt16, to : UInt16) -> Int {
  (to - from).to_int()
}

///|
pub struct SampleBuilder {
  max_late : Int
  codec : @rtp.PayloadCodec
  sample_rate : UInt
  mut max_late_timestamp : UInt
  packets : Array[@rtp.Packet]
  ready : Array[Sample]
  mut next_sequence : UInt16?
  mut consumed_any : Bool
  mut last_sample_timestamp : UInt?
  mut dropped_packets : UInt16
  mut padding_packets : UInt16
  mut generated_at : @transport.WallTime
}

///|
pub fn SampleBuilder::new(
  max_late~ : UInt16,
  codec~ : @rtp.PayloadCodec,
  sample_rate~ : UInt,
  generated_at? : @transport.WallTime = @transport.WallTime::from_unix_nanoseconds(
    0L,
  ),
) -> SampleBuilder raise MediaError {
  if sample_rate == 0 {
    raise InvalidMedia("sample rate must be positive")
  }
  {
    max_late: max_late.to_int(),
    codec,
    sample_rate,
    max_late_timestamp: 0,
    packets: [],
    ready: [],
    next_sequence: None,
    consumed_any: false,
    last_sample_timestamp: None,
    dropped_packets: 0,
    padding_packets: 0,
    generated_at,
  }
}

///|
pub fn SampleBuilder::with_max_time_delay(
  self : SampleBuilder,
  duration : @transport.Duration,
) -> SampleBuilder {
  let milliseconds = duration.as_milliseconds()
  let ticks = self.sample_rate.to_int64() * milliseconds / 1000L
  self.max_late_timestamp = if ticks <= 0L {
    0
  } else {
    ticks.to_int().reinterpret_as_uint()
  }
  self
}

///|
pub fn SampleBuilder::set_generated_at(
  self : SampleBuilder,
  timestamp : @transport.WallTime,
) -> Unit {
  self.generated_at = timestamp
}

///|
fn SampleBuilder::packet_index(self : SampleBuilder, sequence : UInt16) -> Int? {
  for index = 0; index < self.packets.length(); index = index + 1 {
    if self.packets[index].sequence_number() == sequence {
      return Some(index)
    }
  }
  None
}

///|
fn SampleBuilder::packet(
  self : SampleBuilder,
  sequence : UInt16,
) -> @rtp.Packet? {
  match self.packet_index(sequence) {
    Some(index) => Some(self.packets[index])
    None => None
  }
}

///|
fn SampleBuilder::remove_packet(
  self : SampleBuilder,
  sequence : UInt16,
) -> Unit {
  match self.packet_index(sequence) {
    Some(index) => ignore(self.packets.remove(index))
    None => ()
  }
}

///|
fn SampleBuilder::buffer_span(self : SampleBuilder) -> Int {
  match self.next_sequence {
    None => 0
    Some(head) => {
      let mut distance = 0
      for packet in self.packets {
        let candidate = sample_forward_distance(head, packet.sequence_number())
        if candidate < 0x8000 && candidate > distance {
          distance = candidate
        }
      }
      distance
    }
  }
}

///|
fn SampleBuilder::timestamp_span(self : SampleBuilder) -> UInt {
  match self.next_sequence {
    None => 0
    Some(head) =>
      match self.packet(head) {
        None => 0
        Some(first) => {
          let mut distance = 0U
          for packet in self.packets {
            let candidate = packet.timestamp() - first.timestamp()
            if candidate < 0x80000000U && candidate > distance {
              distance = candidate
            }
          }
          distance
        }
      }
  }
}

///|
fn SampleBuilder::must_purge(self : SampleBuilder) -> Bool {
  self.buffer_span() > self.max_late ||
  (
    self.max_late_timestamp != 0 &&
    self.timestamp_span() > self.max_late_timestamp
  )
}

///|
fn SampleBuilder::increment_dropped(self : SampleBuilder) -> Unit {
  self.dropped_packets = self.dropped_packets + 1
}

///|
pub fn SampleBuilder::push(
  self : SampleBuilder,
  packet : @rtp.Packet,
) -> Unit raise MediaError {
  let sequence = packet.sequence_number()
  match self.next_sequence {
    Some(head) if self.consumed_any &&
      sample_forward_distance(head, sequence) >= 0x8000 => return
    _ => ()
  }
  match self.packet_index(sequence) {
    Some(_) => return
    None => ()
  }
  self.packets.push(packet)
  match self.next_sequence {
    None => self.next_sequence = Some(sequence)
    Some(head) =>
      if !self.consumed_any {
        let backwards = sample_forward_distance(sequence, head)
        let forwards = sample_forward_distance(head, sequence)
        if backwards <= self.max_late && forwards >= 0x8000 {
          self.next_sequence = Some(sequence)
        }
      }
  }
  self.prepare(false)
}

///|
pub fn SampleBuilder::push_at(
  self : SampleBuilder,
  packet : @rtp.Packet,
  generated_at : @transport.WallTime,
) -> Unit raise MediaError {
  self.generated_at = generated_at
  self.push(packet)
}

///|
fn SampleBuilder::duration_from_ticks(
  self : SampleBuilder,
  ticks : UInt,
) -> @transport.Duration raise MediaError {
  let milliseconds = ticks.to_int64() * 1000L / self.sample_rate.to_int64()
  @transport.Duration::milliseconds(milliseconds) catch {
    _ => raise InvalidMedia("sample duration is outside the supported range")
  }
}

///|
fn SampleBuilder::queue_sample(
  self : SampleBuilder,
  sequences : Array[UInt16],
  timestamp : UInt,
  next_timestamp : UInt?,
) -> Unit raise MediaError {
  let payloads : Array[Bytes] = []
  for sequence in sequences {
    match self.packet(sequence) {
      Some(packet) => payloads.push(packet.payload())
      None => raise InvalidMedia("sample contains an RTP sequence gap")
    }
  }
  let data = @rtp.depacketize_payload(self.codec, payloads) catch {
    _ => raise InvalidMedia("RTP codec depacketization failed")
  }
  let ticks = match next_timestamp {
    Some(value) => value - timestamp
    None => 0
  }
  let duration = self.duration_from_ticks(ticks)
  self.ready.push({
    data,
    timestamp: self.generated_at,
    duration,
    packet_timestamp: timestamp,
    prev_dropped_packets: self.dropped_packets,
    prev_padding_packets: self.padding_packets,
  })
  self.dropped_packets = 0
  self.padding_packets = 0
  self.last_sample_timestamp = Some(timestamp)
  for sequence in sequences {
    self.remove_packet(sequence)
  }
  self.next_sequence = Some(sequences[sequences.length() - 1] + 1)
  self.consumed_any = true
}

///|
fn SampleBuilder::drop_head(self : SampleBuilder) -> Unit {
  match self.next_sequence {
    None => ()
    Some(sequence) => {
      match self.packet(sequence) {
        Some(packet) => {
          if packet.payload().is_empty() &&
            self.last_sample_timestamp == Some(packet.timestamp()) {
            self.padding_packets = self.padding_packets + 1
          }
          self.remove_packet(sequence)
        }
        None => ()
      }
      self.increment_dropped()
      self.next_sequence = Some(sequence + 1)
      self.consumed_any = true
    }
  }
}

///|
fn SampleBuilder::prepare(
  self : SampleBuilder,
  force : Bool,
) -> Unit raise MediaError {
  while !self.packets.is_empty() {
    let head = match self.next_sequence {
      Some(value) => value
      None => return
    }
    let first = match self.packet(head) {
      Some(value) => value
      None =>
        if force || self.must_purge() {
          self.drop_head()
          continue
        } else {
          return
        }
    }
    if first.payload().is_empty() &&
      self.last_sample_timestamp == Some(first.timestamp()) {
      self.drop_head()
      continue
    }
    if !self.codec.is_partition_head(first.payload()) {
      if force || self.must_purge() {
        self.drop_head()
        continue
      }
      return
    }
    let timestamp = first.timestamp()
    let sequences : Array[UInt16] = []
    let mut sequence = head
    let mut complete = false
    let mut next_timestamp : UInt? = None
    while true {
      match self.packet(sequence) {
        None => break
        Some(packet) => {
          if packet.timestamp() != timestamp {
            next_timestamp = Some(packet.timestamp())
            complete = !sequences.is_empty()
            break
          }
          sequences.push(sequence)
          if self.codec.is_partition_tail(packet.marker(), packet.payload()) {
            complete = true
            let following = sequence + 1
            match self.packet(following) {
              Some(packet) if packet.timestamp() != timestamp =>
                next_timestamp = Some(packet.timestamp())
              _ => ()
            }
            break
          }
          sequence = sequence + 1
        }
      }
    }
    if complete && (next_timestamp is Some(_) || force) {
      self.queue_sample(sequences, timestamp, next_timestamp)
      continue
    }
    if force || self.must_purge() {
      for consumed_sequence in sequences {
        self.remove_packet(consumed_sequence)
        self.increment_dropped()
      }
      self.next_sequence = Some(sequence)
      if sequences.is_empty() {
        self.drop_head()
      }
      continue
    }
    return
  }
}

///|
pub fn SampleBuilder::pop(self : SampleBuilder) -> Sample? raise MediaError {
  self.prepare(false)
  if self.ready.is_empty() {
    None
  } else {
    Some(self.ready.remove(0))
  }
}

///|
pub fn SampleBuilder::pop_with_timestamp(
  self : SampleBuilder,
) -> (Sample, UInt)? raise MediaError {
  match self.pop() {
    Some(sample) => Some((sample, sample.packet_timestamp))
    None => None
  }
}

///|
pub fn SampleBuilder::flush(self : SampleBuilder) -> Unit raise MediaError {
  self.prepare(true)
}
