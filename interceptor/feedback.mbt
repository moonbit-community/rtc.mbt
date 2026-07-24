///|
fn[T] interceptor_rtp(
  operation : () -> T raise @rtp.RtpError,
) -> T raise InterceptorError {
  operation() catch {
    _ => raise PipelineFailed("RTP processing failed")
  }
}

///|
fn[T] interceptor_rtcp(
  operation : () -> T raise @rtcp.RtcpError,
) -> T raise InterceptorError {
  operation() catch {
    _ => raise PipelineFailed("RTCP processing failed")
  }
}

///|
fn interceptor_seq_distance(from : UInt16, to : UInt16) -> Int {
  (to - from).to_int()
}

///|
struct MissingPacket {
  sequence : UInt16
  mut attempts : Int
}

///|
pub struct NackGenerator {
  sender_ssrc : UInt
  media_ssrc : UInt
  max_tracked : Int
  max_retries : Int
  missing : Array[MissingPacket]
  mut last_sequence : UInt16?
}

///|
pub fn NackGenerator::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
  max_tracked? : Int = 1024,
  max_retries? : Int = 5,
) -> NackGenerator raise InterceptorError {
  if max_tracked <= 0 || max_tracked > 0x7fff {
    raise InvalidConfiguration("NACK tracking window is invalid")
  }
  if max_retries <= 0 {
    raise InvalidConfiguration("NACK retry count must be positive")
  }
  {
    sender_ssrc,
    media_ssrc,
    max_tracked,
    max_retries,
    missing: [],
    last_sequence: None,
  }
}

///|
fn NackGenerator::missing_index(
  self : NackGenerator,
  sequence : UInt16,
) -> Int? {
  for index = 0; index < self.missing.length(); index = index + 1 {
    if self.missing[index].sequence == sequence {
      return Some(index)
    }
  }
  None
}

///|
pub fn NackGenerator::observe(
  self : NackGenerator,
  packet : @rtp.Packet,
) -> Unit {
  if packet.ssrc() != self.media_ssrc {
    return
  }
  let sequence = packet.sequence_number()
  match self.last_sequence {
    None => self.last_sequence = Some(sequence)
    Some(previous) => {
      let forward = interceptor_seq_distance(previous, sequence)
      if forward == 0 {
        return
      }
      if forward < 0x8000 {
        if forward > 1 {
          let missing_count = Int::min(forward - 1, self.max_tracked)
          let first = sequence - missing_count.to_uint16()
          for offset = 0; offset < missing_count; offset = offset + 1 {
            let candidate = first + offset.to_uint16()
            if self.missing_index(candidate) is None {
              self.missing.push({ sequence: candidate, attempts: 0 })
            }
          }
          while self.missing.length() > self.max_tracked {
            ignore(self.missing.remove(0))
          }
        }
        self.last_sequence = Some(sequence)
      } else {
        match self.missing_index(sequence) {
          Some(index) => ignore(self.missing.remove(index))
          None => ()
        }
      }
    }
  }
}

///|
pub fn NackGenerator::missing_sequences(self : NackGenerator) -> Array[UInt16] {
  self.missing.map(entry => entry.sequence)
}

///|
pub fn NackGenerator::poll_feedback(
  self : NackGenerator,
) -> @rtcp.TransportLayerNackPacket? {
  if self.missing.is_empty() {
    return None
  }
  let pairs : Array[@rtcp.NackPair] = []
  let mut index = 0
  while index < self.missing.length() {
    let first = self.missing[index].sequence
    let mut mask : UInt16 = 0
    let mut next = index + 1
    while next < self.missing.length() {
      let distance = interceptor_seq_distance(
        first,
        self.missing[next].sequence,
      )
      if distance <= 0 || distance > 16 {
        break
      }
      mask = mask | (1U << (distance - 1)).to_uint16()
      next += 1
    }
    pairs.push(@rtcp.NackPair::new(packet_id=first, lost_packets=mask))
    index = next
  }
  for entry in self.missing {
    entry.attempts += 1
  }
  let mut remove_index = self.missing.length() - 1
  while remove_index >= 0 {
    if self.missing[remove_index].attempts >= self.max_retries {
      ignore(self.missing.remove(remove_index))
    }
    remove_index -= 1
  }
  Some(
    @rtcp.TransportLayerNackPacket::new(
      sender_ssrc=self.sender_ssrc,
      media_ssrc=self.media_ssrc,
      nacks=pairs,
    ),
  )
}

///|
pub struct SenderReportGenerator {
  sender_ssrc : UInt
  mut packet_count : UInt
  mut octet_count : UInt
  mut last_rtp_timestamp : UInt
}

///|
pub fn SenderReportGenerator::new(sender_ssrc : UInt) -> SenderReportGenerator {
  { sender_ssrc, packet_count: 0, octet_count: 0, last_rtp_timestamp: 0 }
}

///|
pub fn SenderReportGenerator::observe(
  self : SenderReportGenerator,
  packet : @rtp.Packet,
) -> Unit {
  if packet.ssrc() != self.sender_ssrc {
    return
  }
  self.packet_count += 1
  self.octet_count += packet.payload().length().reinterpret_as_uint()
  self.last_rtp_timestamp = packet.timestamp()
}

///|
pub fn SenderReportGenerator::report(
  self : SenderReportGenerator,
  ntp_timestamp : UInt64,
  reports? : Array[@rtcp.ReceptionReport] = [],
) -> @rtcp.SenderReportPacket raise InterceptorError {
  interceptor_rtcp(() => {
    @rtcp.SenderReportPacket::new(
      sender_ssrc=self.sender_ssrc,
      ntp_timestamp~,
      rtp_timestamp=self.last_rtp_timestamp,
      packet_count=self.packet_count,
      octet_count=self.octet_count,
      reports~,
    )
  })
}

///|
pub fn SenderReportGenerator::packet_count(
  self : SenderReportGenerator,
) -> UInt {
  self.packet_count
}

///|
pub fn SenderReportGenerator::octet_count(self : SenderReportGenerator) -> UInt {
  self.octet_count
}

///|
pub struct ReceiverReportGenerator {
  sender_ssrc : UInt
  media_ssrc : UInt
  clock_rate : UInt
  mut initialized : Bool
  mut base_sequence : UInt16
  mut max_sequence : UInt16
  mut cycles : UInt
  mut received : UInt
  mut octet_count : UInt64
  mut expected_prior : UInt
  mut received_prior : UInt
  mut transit : Int64?
  mut jitter : Int64
  seen : Array[UInt]
  mut last_sender_report : UInt
  mut last_sender_report_arrival_ms : Int64?
}

///|
pub fn ReceiverReportGenerator::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
  clock_rate~ : UInt,
) -> ReceiverReportGenerator raise InterceptorError {
  if clock_rate == 0 {
    raise InvalidConfiguration("receiver-report clock rate must be positive")
  }
  {
    sender_ssrc,
    media_ssrc,
    clock_rate,
    initialized: false,
    base_sequence: 0,
    max_sequence: 0,
    cycles: 0,
    received: 0,
    octet_count: 0UL,
    expected_prior: 0,
    received_prior: 0,
    transit: None,
    jitter: 0L,
    seen: [],
    last_sender_report: 0,
    last_sender_report_arrival_ms: None,
  }
}

///|
fn ReceiverReportGenerator::extended_sequence(
  self : ReceiverReportGenerator,
  sequence : UInt16,
) -> UInt {
  if sequence > self.max_sequence &&
    (sequence - self.max_sequence).to_int() >= 0x8000 &&
    self.cycles >= 0x10000U {
    self.cycles - 0x10000U + sequence.to_uint()
  } else {
    self.cycles + sequence.to_uint()
  }
}

///|
pub fn ReceiverReportGenerator::observe(
  self : ReceiverReportGenerator,
  packet : @rtp.Packet,
  arrival_ticks : UInt,
) -> Unit {
  if packet.ssrc() != self.media_ssrc {
    return
  }
  let sequence = packet.sequence_number()
  if !self.initialized {
    self.initialized = true
    self.base_sequence = sequence
    self.max_sequence = sequence
  } else if sequence < self.max_sequence &&
    (self.max_sequence - sequence).to_int() > 0x8000 {
    self.cycles += 0x10000U
    self.max_sequence = sequence
  } else if sequence > self.max_sequence &&
    (sequence - self.max_sequence).to_int() < 0x8000 {
    self.max_sequence = sequence
  }
  let extended = self.extended_sequence(sequence)
  if self.seen.contains(extended) {
    return
  }
  self.seen.push(extended)
  if self.seen.length() > 4096 {
    ignore(self.seen.remove(0))
  }
  self.received += 1
  self.octet_count += packet.payload().length().to_uint64()
  let transit = arrival_ticks.to_int64() - packet.timestamp().to_int64()
  match self.transit {
    Some(previous) => {
      let difference = Int64::abs(transit - previous)
      self.jitter += (difference - self.jitter) / 16L
    }
    None => ()
  }
  self.transit = Some(transit)
}

///|
pub fn ReceiverReportGenerator::observe_sender_report(
  self : ReceiverReportGenerator,
  report : @rtcp.SenderReportPacket,
  arrival_ms : Int64,
) -> Unit {
  self.last_sender_report = ((report.ntp_timestamp >> 16) & 0xffffffffUL).to_uint()
  self.last_sender_report_arrival_ms = Some(arrival_ms)
}

///|
pub fn ReceiverReportGenerator::report(
  self : ReceiverReportGenerator,
  now_ms : Int64,
) -> @rtcp.ReceiverReportPacket raise InterceptorError {
  if !self.initialized {
    return interceptor_rtcp(() => {
      @rtcp.ReceiverReportPacket::new(sender_ssrc=self.sender_ssrc)
    })
  }
  let extended_max = self.cycles + self.max_sequence.to_uint()
  let expected = extended_max - self.base_sequence.to_uint() + 1U
  let lost_signed = expected.to_int64() - self.received.to_int64()
  let cumulative_lost = if lost_signed < -8388608L {
    -8388608
  } else if lost_signed > 8388607L {
    8388607
  } else {
    lost_signed.to_int()
  }
  let expected_interval = expected - self.expected_prior
  let received_interval = self.received - self.received_prior
  let lost_interval = expected_interval.to_int64() -
    received_interval.to_int64()
  let fraction_lost : Byte = if expected_interval == 0 || lost_interval <= 0L {
    0
  } else {
    (lost_interval * 256L / expected_interval.to_int64()).to_byte()
  }
  self.expected_prior = expected
  self.received_prior = self.received
  let delay = match self.last_sender_report_arrival_ms {
    Some(arrival) if now_ms > arrival =>
      ((now_ms - arrival) * 65536L / 1000L).to_int().reinterpret_as_uint()
    _ => 0U
  }
  let reception = interceptor_rtcp(() => {
    @rtcp.ReceptionReport::new(
      ssrc=self.media_ssrc,
      fraction_lost~,
      cumulative_lost~,
      extended_sequence_number=extended_max,
      jitter=self.jitter.to_int().reinterpret_as_uint(),
      last_sender_report=self.last_sender_report,
      delay_since_last_sender_report=delay,
    )
  })
  interceptor_rtcp(() => {
    @rtcp.ReceiverReportPacket::new(sender_ssrc=self.sender_ssrc, reports=[
      reception,
    ])
  })
}

///|
pub fn ReceiverReportGenerator::packets_lost(
  self : ReceiverReportGenerator,
) -> UInt64 {
  if !self.initialized {
    return 0UL
  }
  let expected = self.cycles +
    self.max_sequence.to_uint() -
    self.base_sequence.to_uint() +
    1U
  if expected > self.received {
    (expected - self.received).to_uint64()
  } else {
    0UL
  }
}

///|
pub fn ReceiverReportGenerator::packet_count(
  self : ReceiverReportGenerator,
) -> UInt {
  self.received
}

///|
pub fn ReceiverReportGenerator::octet_count(
  self : ReceiverReportGenerator,
) -> UInt64 {
  self.octet_count
}

///|
pub fn ReceiverReportGenerator::jitter(
  self : ReceiverReportGenerator,
) -> UInt64 {
  if self.jitter <= 0L {
    0UL
  } else {
    self.jitter.reinterpret_as_uint64()
  }
}

///|
struct TwccObservation {
  sequence : UInt16
  arrival_us : Int64
}

///|
pub struct TwccRecorder {
  sender_ssrc : UInt
  media_ssrc : UInt
  extension_id : Byte
  max_packets : Int
  observations : Array[TwccObservation]
  mut base_sequence : UInt16?
  mut feedback_packet_count : Byte
}

///|
pub fn TwccRecorder::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
  extension_id~ : Byte,
  max_packets? : Int = 4096,
) -> TwccRecorder raise InterceptorError {
  if extension_id == 0 {
    raise InvalidConfiguration("transport-cc extension id is zero")
  }
  if max_packets <= 0 || max_packets > 0xffff {
    raise InvalidConfiguration("transport-cc packet window is invalid")
  }
  {
    sender_ssrc,
    media_ssrc,
    extension_id,
    max_packets,
    observations: [],
    base_sequence: None,
    feedback_packet_count: 0,
  }
}

///|
fn TwccRecorder::observation(
  self : TwccRecorder,
  sequence : UInt16,
) -> TwccObservation? {
  for observation in self.observations {
    if observation.sequence == sequence {
      return Some(observation)
    }
  }
  None
}

///|
pub fn TwccRecorder::observe(
  self : TwccRecorder,
  packet : @rtp.Packet,
  arrival_us : Int64,
) -> Unit raise InterceptorError {
  self.observe_with_extension_id(packet, arrival_us, self.extension_id)
}

///|
pub fn TwccRecorder::observe_with_extension_id(
  self : TwccRecorder,
  packet : @rtp.Packet,
  arrival_us : Int64,
  extension_id : Byte,
) -> Unit raise InterceptorError {
  if extension_id == 0 {
    raise InvalidConfiguration("transport-cc extension id is zero")
  }
  let mut transport_sequence : UInt16? = None
  for extension in packet.extensions() {
    if extension.id() == extension_id {
      let decoded = interceptor_rtp(() => {
        @rtp.TransportCcExtension::unmarshal(extension.payload())
      })
      transport_sequence = Some(decoded.transport_sequence())
      break
    }
  }
  guard transport_sequence is Some(sequence) else { return }
  if self.observation(sequence) is Some(_) {
    return
  }
  match self.base_sequence {
    None => self.base_sequence = Some(sequence)
    Some(base) => {
      let backwards = interceptor_seq_distance(sequence, base)
      let forwards = interceptor_seq_distance(base, sequence)
      if backwards < self.max_packets && forwards >= 0x8000 {
        self.base_sequence = Some(sequence)
      }
    }
  }
  self.observations.push({ sequence, arrival_us })
  if self.observations.length() > self.max_packets {
    ignore(self.observations.remove(0))
    self.base_sequence = if self.observations.is_empty() {
      None
    } else {
      Some(self.observations[0].sequence)
    }
  }
}

///|
pub fn TwccRecorder::poll_feedback(
  self : TwccRecorder,
) -> @rtcp.TransportWideCcPacket? raise InterceptorError {
  guard self.base_sequence is Some(base) else { return None }
  if self.observations.is_empty() {
    self.base_sequence = None
    return None
  }
  let mut last_distance = 0
  for observation in self.observations {
    let distance = interceptor_seq_distance(base, observation.sequence)
    if distance < 0x8000 && distance > last_distance {
      last_distance = distance
    }
  }
  if last_distance + 1 > self.max_packets {
    raise PipelineFailed("transport-cc sequence range exceeds its window")
  }
  guard self.observation(base) is Some(first) else {
    raise PipelineFailed("transport-cc base packet is missing")
  }
  let reference_units = first.arrival_us / 64000L
  let reference_time = reference_units.to_int().reinterpret_as_uint() &
    0xffffffU
  let mut previous_arrival = reference_units * 64000L
  let statuses : Array[@rtcp.TransportWideStatus] = []
  for distance = 0; distance <= last_distance; distance = distance + 1 {
    let sequence = base + distance.to_uint16()
    match self.observation(sequence) {
      None => statuses.push(PacketNotReceived)
      Some(observation) => {
        let delta = observation.arrival_us - previous_arrival
        let encoded = delta / 250L * 250L
        if encoded >= 0L && encoded <= 63750L {
          statuses.push(PacketReceivedSmallDelta(encoded.to_int()))
        } else if encoded >= -8192000L && encoded <= 8191750L {
          statuses.push(PacketReceivedLargeDelta(encoded.to_int()))
        } else {
          raise PipelineFailed("transport-cc receive delta is out of range")
        }
        previous_arrival = observation.arrival_us
      }
    }
  }
  let feedback_count = self.feedback_packet_count
  self.feedback_packet_count += 1
  self.observations.clear()
  self.base_sequence = None
  Some(
    interceptor_rtcp(() => {
      @rtcp.TransportWideCcPacket::new(
        sender_ssrc=self.sender_ssrc,
        media_ssrc=self.media_ssrc,
        base_sequence_number=base,
        reference_time~,
        feedback_packet_count=feedback_count,
        statuses~,
      )
    }),
  )
}

///|
pub struct RtxSender {
  media_ssrc : UInt
  rtx_ssrc : UInt
  rtx_payload_type : Byte
  capacity : Int
  history : Array[@rtp.Packet]
  mut sequence_number : UInt16
  mut retransmitted_packets : UInt64
  mut retransmitted_bytes : UInt64
}

///|
pub fn RtxSender::new(
  media_ssrc~ : UInt,
  rtx_ssrc~ : UInt,
  rtx_payload_type~ : Byte,
  sequence_number? : UInt16 = 0,
  capacity? : Int = 1024,
) -> RtxSender raise InterceptorError {
  if rtx_payload_type > 127 {
    raise InvalidConfiguration("RTX payload type exceeds seven bits")
  }
  if capacity <= 0 || capacity > 0x7fff {
    raise InvalidConfiguration("RTX history capacity is invalid")
  }
  {
    media_ssrc,
    rtx_ssrc,
    rtx_payload_type,
    capacity,
    history: [],
    sequence_number,
    retransmitted_packets: 0UL,
    retransmitted_bytes: 0UL,
  }
}

///|
pub fn RtxSender::remember(self : RtxSender, packet : @rtp.Packet) -> Unit {
  if packet.ssrc() != self.media_ssrc {
    return
  }
  for index = 0; index < self.history.length(); index = index + 1 {
    if self.history[index].sequence_number() == packet.sequence_number() {
      self.history[index] = packet
      return
    }
  }
  self.history.push(packet)
  while self.history.length() > self.capacity {
    ignore(self.history.remove(0))
  }
}

///|
pub fn RtxSender::retransmit(
  self : RtxSender,
  nack : @rtcp.TransportLayerNackPacket,
) -> Array[@rtp.Packet] raise InterceptorError {
  if nack.media_ssrc != self.media_ssrc {
    return []
  }
  let output : Array[@rtp.Packet] = []
  for pair in nack.nacks {
    for lost in pair.lost_sequence_numbers() {
      let mut original : @rtp.Packet? = None
      for packet in self.history {
        if packet.sequence_number() == lost {
          original = Some(packet)
          break
        }
      }
      match original {
        None => ()
        Some(packet) => {
          let payload : Array[Byte] = [(lost >> 8).to_byte(), lost.to_byte()]
          for byte in packet.payload() {
            payload.push(byte)
          }
          output.push(
            interceptor_rtp(() => {
              @rtp.Packet::new(
                marker=packet.marker(),
                payload_type=self.rtx_payload_type,
                sequence_number=self.sequence_number,
                timestamp=packet.timestamp(),
                ssrc=self.rtx_ssrc,
                csrc=packet.csrc(),
                extensions=packet.extensions(),
                payload=Bytes::from_array(payload),
              )
            }),
          )
          self.retransmitted_packets += 1UL
          self.retransmitted_bytes += payload.length().to_uint64()
          self.sequence_number += 1
        }
      }
    }
  }
  output
}

///|
pub fn RtxSender::retransmitted_packets(self : RtxSender) -> UInt64 {
  self.retransmitted_packets
}

///|
pub fn RtxSender::retransmitted_bytes(self : RtxSender) -> UInt64 {
  self.retransmitted_bytes
}

///|
pub struct RtxReceiver {
  media_ssrc : UInt
  media_payload_type : Byte
  rtx_ssrc : UInt
  rtx_payload_type : Byte
  recent : Array[UInt16]
  capacity : Int
}

///|
pub fn RtxReceiver::new(
  media_ssrc~ : UInt,
  media_payload_type~ : Byte,
  rtx_ssrc~ : UInt,
  rtx_payload_type~ : Byte,
  capacity? : Int = 1024,
) -> RtxReceiver raise InterceptorError {
  if media_payload_type > 127 || rtx_payload_type > 127 {
    raise InvalidConfiguration("RTP payload type exceeds seven bits")
  }
  if capacity <= 0 {
    raise InvalidConfiguration("RTX replay window is empty")
  }
  {
    media_ssrc,
    media_payload_type,
    rtx_ssrc,
    rtx_payload_type,
    recent: [],
    capacity,
  }
}

///|
pub fn RtxReceiver::recover(
  self : RtxReceiver,
  packet : @rtp.Packet,
) -> @rtp.Packet? raise InterceptorError {
  if packet.ssrc() != self.rtx_ssrc ||
    packet.payload_type() != self.rtx_payload_type {
    return Some(packet)
  }
  if packet.payload().length() < 2 {
    raise PipelineFailed("RTX packet is shorter than its original sequence")
  }
  let original_sequence = ((packet.payload()[0].to_uint() << 8) |
  packet.payload()[1].to_uint()).to_uint16()
  if self.recent.contains(original_sequence) {
    return None
  }
  self.recent.push(original_sequence)
  while self.recent.length() > self.capacity {
    ignore(self.recent.remove(0))
  }
  Some(
    interceptor_rtp(() => {
      @rtp.Packet::new(
        marker=packet.marker(),
        payload_type=self.media_payload_type,
        sequence_number=original_sequence,
        timestamp=packet.timestamp(),
        ssrc=self.media_ssrc,
        csrc=packet.csrc(),
        extensions=packet.extensions(),
        payload=packet.payload()[2:].to_owned(),
      )
    }),
  )
}

///|
pub fn RtxReceiver::observe_primary(
  self : RtxReceiver,
  packet : @rtp.Packet,
) -> Unit {
  if packet.ssrc() != self.media_ssrc ||
    packet.payload_type() != self.media_payload_type {
    return
  }
  let sequence = packet.sequence_number()
  if !self.recent.contains(sequence) {
    self.recent.push(sequence)
  }
  while self.recent.length() > self.capacity {
    ignore(self.recent.remove(0))
  }
}
