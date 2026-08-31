///|
pub(all) struct Header {
  padding : Bool
  count : Byte
  packet_type : Byte
  length_words_minus_one : UInt16
} derive(Debug, Eq)

///|
pub fn Header::padding(self : Header) -> Bool {
  self.padding
}

///|
pub fn Header::count(self : Header) -> Byte {
  self.count
}

///|
pub fn Header::packet_type(self : Header) -> Byte {
  self.packet_type
}

///|
pub fn Header::length_words_minus_one(self : Header) -> UInt16 {
  self.length_words_minus_one
}

///|
fn rtcp_read_u16(data : Bytes, offset : Int) -> UInt16 raise RtcpError {
  if offset < 0 || offset + 2 > data.length() {
    raise InvalidPacket("truncated RTCP 16-bit field")
  }
  ((data[offset].to_uint() << 8) | data[offset + 1].to_uint()).to_uint16()
}

///|
fn rtcp_read_u24(data : Bytes, offset : Int) -> UInt raise RtcpError {
  if offset < 0 || offset + 3 > data.length() {
    raise InvalidPacket("truncated RTCP 24-bit field")
  }
  (data[offset].to_uint() << 16) |
  (data[offset + 1].to_uint() << 8) |
  data[offset + 2].to_uint()
}

///|
fn rtcp_read_u32(data : Bytes, offset : Int) -> UInt raise RtcpError {
  if offset < 0 || offset + 4 > data.length() {
    raise InvalidPacket("truncated RTCP 32-bit field")
  }
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn rtcp_read_u64(data : Bytes, offset : Int) -> UInt64 raise RtcpError {
  if offset < 0 || offset + 8 > data.length() {
    raise InvalidPacket("truncated RTCP 64-bit field")
  }
  (data[offset].to_uint64() << 56) |
  (data[offset + 1].to_uint64() << 48) |
  (data[offset + 2].to_uint64() << 40) |
  (data[offset + 3].to_uint64() << 32) |
  (data[offset + 4].to_uint64() << 24) |
  (data[offset + 5].to_uint64() << 16) |
  (data[offset + 6].to_uint64() << 8) |
  data[offset + 7].to_uint64()
}

///|
fn rtcp_write_u16(output : Array[Byte], value : UInt16) -> Unit {
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn rtcp_write_u24(output : Array[Byte], value : UInt) -> Unit {
  output.push((value >> 16).to_byte())
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn rtcp_write_u32(output : Array[Byte], value : UInt) -> Unit {
  output.push((value >> 24).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn rtcp_write_u64(output : Array[Byte], value : UInt64) -> Unit {
  output.push((value >> 56).to_byte())
  output.push((value >> 48).to_byte())
  output.push((value >> 40).to_byte())
  output.push((value >> 32).to_byte())
  output.push((value >> 24).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 8).to_byte())
  output.push(value.to_byte())
}

///|
fn decode_header(data : Bytes) -> Header raise RtcpError {
  if data.length() < 4 {
    raise InvalidPacket("RTCP packet is shorter than its header")
  }
  if data[0] >> 6 != 2 {
    raise InvalidPacket("unsupported RTCP version")
  }
  {
    padding: (data[0] & 0x20) != 0,
    count: data[0] & 0x1f,
    packet_type: data[1],
    length_words_minus_one: rtcp_read_u16(data, 2),
  }
}

///|
pub fn Packet::header(self : Packet) -> Header raise RtcpError {
  decode_header(self.marshal())
}

///|
fn packet_wire_bytes(packet : Packet) -> Bytes {
  match packet {
    SenderReport(data)
    | ReceiverReport(data)
    | SourceDescription(data)
    | Goodbye(data)
    | ApplicationDefined(data)
    | TransportFeedback(data)
    | PayloadFeedback(data)
    | ExtendedReport(data)
    | Unknown(data) => data
  }
}

///|
fn classify_packet(data : Bytes, packet_type : Byte) -> Packet {
  match packet_type {
    200 => SenderReport(data)
    201 => ReceiverReport(data)
    202 => SourceDescription(data)
    203 => Goodbye(data)
    204 => ApplicationDefined(data)
    205 => TransportFeedback(data)
    206 => PayloadFeedback(data)
    207 => ExtendedReport(data)
    _ => Unknown(data)
  }
}

///|
fn validate_single_packet(data : Bytes) -> Header raise RtcpError {
  let header = decode_header(data)
  let expected = (header.length_words_minus_one.to_int() + 1) * 4
  if expected != data.length() {
    raise InvalidPacket("RTCP length field does not match packet length")
  }
  if header.padding {
    let padding_length = data[data.length() - 1].to_int()
    if padding_length == 0 || padding_length > data.length() - 4 {
      raise InvalidPacket("invalid RTCP padding length")
    }
  }
  header
}

///|
pub fn Packet::marshal(self : Packet) -> Bytes raise RtcpError {
  let data = packet_wire_bytes(self)
  let header = validate_single_packet(data)
  match self {
    SenderReport(_) if header.packet_type != 200 =>
      raise InvalidPacket(
        "RTCP sender-report variant has the wrong packet type",
      )
    ReceiverReport(_) if header.packet_type != 201 =>
      raise InvalidPacket(
        "RTCP receiver-report variant has the wrong packet type",
      )
    SourceDescription(_) if header.packet_type != 202 =>
      raise InvalidPacket("RTCP SDES variant has the wrong packet type")
    Goodbye(_) if header.packet_type != 203 =>
      raise InvalidPacket("RTCP BYE variant has the wrong packet type")
    ApplicationDefined(_) if header.packet_type != 204 =>
      raise InvalidPacket("RTCP APP variant has the wrong packet type")
    TransportFeedback(_) if header.packet_type != 205 =>
      raise InvalidPacket("RTCP RTPFB variant has the wrong packet type")
    PayloadFeedback(_) if header.packet_type != 206 =>
      raise InvalidPacket("RTCP PSFB variant has the wrong packet type")
    ExtendedReport(_) if header.packet_type != 207 =>
      raise InvalidPacket("RTCP XR variant has the wrong packet type")
    _ => ()
  }
  data
}

///|
pub fn Packet::unmarshal(data : Bytes) -> Packet raise RtcpError {
  let packets = decode_compound(data)
  guard packets is [packet] else {
    raise InvalidPacket("expected exactly one RTCP packet")
  }
  packet
}

///|
pub fn Packet::decode(data : Bytes) -> Packet raise RtcpError {
  Packet::unmarshal(data)
}

///|
pub fn decode_compound(data : Bytes) -> Array[Packet] raise RtcpError {
  if data.is_empty() {
    raise InvalidCompoundPacket("RTCP compound packet is empty")
  }
  let packets : Array[Packet] = []
  let mut offset = 0
  while offset < data.length() {
    if data.length() - offset < 4 {
      raise InvalidCompoundPacket("truncated RTCP compound packet")
    }
    let view = data[offset:].to_owned()
    let header = decode_header(view)
    let packet_length = (header.length_words_minus_one.to_int() + 1) * 4
    if packet_length < 4 || offset + packet_length > data.length() {
      raise InvalidCompoundPacket("RTCP packet length exceeds compound packet")
    }
    if header.padding && offset + packet_length != data.length() {
      raise InvalidCompoundPacket(
        "only the last RTCP packet may contain padding",
      )
    }
    let packet_data = data[offset:offset + packet_length].to_owned()
    ignore(validate_single_packet(packet_data))
    packets.push(classify_packet(packet_data, header.packet_type))
    offset += packet_length
  }
  packets
}

///|
pub fn encode_compound(packets : Array[Packet]) -> Bytes raise RtcpError {
  if packets.is_empty() {
    raise InvalidCompoundPacket("RTCP compound packet is empty")
  }
  let output : Array[Byte] = []
  for index = 0; index < packets.length(); index = index + 1 {
    let wire = packets[index].marshal()
    let header = decode_header(wire)
    if header.padding && index != packets.length() - 1 {
      raise InvalidCompoundPacket(
        "only the last RTCP packet may contain padding",
      )
    }
    for byte in wire {
      output.push(byte)
    }
  }
  Bytes::from_array(output)
}

///|
fn build_packet(
  count : Byte,
  packet_type : Byte,
  body : Bytes,
) -> Bytes raise RtcpError {
  if count > 31 {
    raise InvalidPacket("RTCP count/format exceeds five bits")
  }
  let total_length = 4 + body.length()
  if total_length % 4 != 0 {
    raise InvalidPacket("RTCP packet body must be 32-bit aligned")
  }
  if total_length > 262144 {
    raise PacketTooLarge(total_length)
  }
  let word_length = total_length / 4 - 1
  if word_length > 0xffff {
    raise PacketTooLarge(total_length)
  }
  let output : Array[Byte] = Array::new(capacity=total_length)
  output.push(0x80 | count)
  output.push(packet_type)
  rtcp_write_u16(output, word_length.to_uint16())
  for byte in body {
    output.push(byte)
  }
  Bytes::from_array(output)
}

///|
fn encode_reception_report(
  output : Array[Byte],
  report : ReceptionReport,
) -> Unit raise RtcpError {
  if report.cumulative_lost < -8388608 || report.cumulative_lost > 8388607 {
    raise InvalidPacket("RTCP cumulative loss does not fit in signed 24 bits")
  }
  rtcp_write_u32(output, report.ssrc)
  output.push(report.fraction_lost)
  rtcp_write_u24(
    output,
    report.cumulative_lost.reinterpret_as_uint() & 0xffffffU,
  )
  rtcp_write_u32(output, report.extended_sequence_number)
  rtcp_write_u32(output, report.jitter)
  rtcp_write_u32(output, report.last_sender_report)
  rtcp_write_u32(output, report.delay_since_last_sender_report)
}

///|
fn decode_reception_report(
  data : Bytes,
  offset : Int,
) -> ReceptionReport raise RtcpError {
  if offset + 24 > data.length() {
    raise InvalidPacket("truncated RTCP reception report")
  }
  let lost_raw = rtcp_read_u24(data, offset + 5)
  let cumulative_lost = if (lost_raw & 0x800000U) != 0U {
    lost_raw.reinterpret_as_int() - 0x1000000
  } else {
    lost_raw.reinterpret_as_int()
  }
  ReceptionReport::new(
    ssrc=rtcp_read_u32(data, offset),
    fraction_lost=data[offset + 4],
    cumulative_lost~,
    extended_sequence_number=rtcp_read_u32(data, offset + 8),
    jitter=rtcp_read_u32(data, offset + 12),
    last_sender_report=rtcp_read_u32(data, offset + 16),
    delay_since_last_sender_report=rtcp_read_u32(data, offset + 20),
  )
}

///|
pub fn SenderReportPacket::to_packet(
  self : SenderReportPacket,
) -> Packet raise RtcpError {
  if self.reports.length() > 31 {
    raise InvalidPacket("RTCP sender report contains more than 31 reports")
  }
  if self.profile_extensions.length() % 4 != 0 {
    raise InvalidPacket("RTCP profile extension must be 32-bit aligned")
  }
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u64(body, self.ntp_timestamp)
  rtcp_write_u32(body, self.rtp_timestamp)
  rtcp_write_u32(body, self.packet_count)
  rtcp_write_u32(body, self.octet_count)
  for report in self.reports {
    encode_reception_report(body, report)
  }
  for byte in self.profile_extensions {
    body.push(byte)
  }
  SenderReport(
    build_packet(self.reports.length().to_byte(), 200, Bytes::from_array(body)),
  )
}

///|
pub fn SenderReportPacket::marshal(
  self : SenderReportPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_sender_report(
  self : Packet,
) -> SenderReportPacket raise RtcpError {
  guard self is SenderReport(data) else {
    raise InvalidPacket("RTCP packet is not a sender report")
  }
  let header = validate_single_packet(data)
  let body_end = unpadded_end(data, header)
  let report_count = header.count.to_int()
  let required = 28 + report_count * 24
  if body_end < required {
    raise InvalidPacket("truncated RTCP sender report")
  }
  let reports : Array[ReceptionReport] = []
  for index = 0; index < report_count; index = index + 1 {
    reports.push(decode_reception_report(data, 28 + index * 24))
  }
  SenderReportPacket::new(
    sender_ssrc=rtcp_read_u32(data, 4),
    ntp_timestamp=rtcp_read_u64(data, 8),
    rtp_timestamp=rtcp_read_u32(data, 16),
    packet_count=rtcp_read_u32(data, 20),
    octet_count=rtcp_read_u32(data, 24),
    reports~,
    profile_extensions=data[required:body_end].to_owned(),
  )
}

///|
pub fn ReceiverReportPacket::to_packet(
  self : ReceiverReportPacket,
) -> Packet raise RtcpError {
  if self.reports.length() > 31 || self.profile_extensions.length() % 4 != 0 {
    raise InvalidPacket("invalid RTCP receiver report")
  }
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  for report in self.reports {
    encode_reception_report(body, report)
  }
  for byte in self.profile_extensions {
    body.push(byte)
  }
  ReceiverReport(
    build_packet(self.reports.length().to_byte(), 201, Bytes::from_array(body)),
  )
}

///|
pub fn ReceiverReportPacket::marshal(
  self : ReceiverReportPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_receiver_report(
  self : Packet,
) -> ReceiverReportPacket raise RtcpError {
  guard self is ReceiverReport(data) else {
    raise InvalidPacket("RTCP packet is not a receiver report")
  }
  let header = validate_single_packet(data)
  let body_end = unpadded_end(data, header)
  let report_count = header.count.to_int()
  let required = 8 + report_count * 24
  if body_end < required {
    raise InvalidPacket("truncated RTCP receiver report")
  }
  let reports : Array[ReceptionReport] = []
  for index = 0; index < report_count; index = index + 1 {
    reports.push(decode_reception_report(data, 8 + index * 24))
  }
  ReceiverReportPacket::new(
    sender_ssrc=rtcp_read_u32(data, 4),
    reports~,
    profile_extensions=data[required:body_end].to_owned(),
  )
}

///|
fn unpadded_end(data : Bytes, header : Header) -> Int {
  if header.padding {
    data.length() - data[data.length() - 1].to_int()
  } else {
    data.length()
  }
}

///|
fn sdes_type_code(item_type : SourceDescriptionType) -> Byte {
  match item_type {
    Cname => 1
    Name => 2
    Email => 3
    Phone => 4
    Location => 5
    Tool => 6
    Note => 7
    Private => 8
    Unknown(code) => code
  }
}

///|
fn sdes_type_from_code(code : Byte) -> SourceDescriptionType {
  match code {
    1 => Cname
    2 => Name
    3 => Email
    4 => Phone
    5 => Location
    6 => Tool
    7 => Note
    8 => Private
    _ => Unknown(code)
  }
}

///|
pub fn SourceDescriptionPacket::to_packet(
  self : SourceDescriptionPacket,
) -> Packet raise RtcpError {
  if self.chunks.length() > 31 {
    raise InvalidPacket("RTCP SDES packet contains more than 31 chunks")
  }
  let body : Array[Byte] = []
  for chunk in self.chunks {
    rtcp_write_u32(body, chunk.source)
    for item in chunk.items {
      let code = sdes_type_code(item.item_type)
      if code == 0 || item.value.length() > 255 {
        raise InvalidPacket("invalid RTCP SDES item")
      }
      body.push(code)
      body.push(item.value.length().to_byte())
      for byte in item.value {
        body.push(byte)
      }
    }
    body.push(0)
    while body.length() % 4 != 0 {
      body.push(0)
    }
  }
  SourceDescription(
    build_packet(self.chunks.length().to_byte(), 202, Bytes::from_array(body)),
  )
}

///|
pub fn SourceDescriptionPacket::marshal(
  self : SourceDescriptionPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_source_description(
  self : Packet,
) -> SourceDescriptionPacket raise RtcpError {
  guard self is SourceDescription(data) else {
    raise InvalidPacket("RTCP packet is not SDES")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  let chunks : Array[SourceDescriptionChunk] = []
  let mut offset = 4
  for chunk_index = 0
      chunk_index < header.count.to_int()
      chunk_index = chunk_index + 1 {
    if offset + 4 > end {
      raise InvalidPacket("truncated RTCP SDES chunk")
    }
    let source = rtcp_read_u32(data, offset)
    offset += 4
    let items : Array[SourceDescriptionItem] = []
    let mut terminated = false
    while offset < end {
      let code = data[offset]
      offset += 1
      if code == 0 {
        terminated = true
        break
      }
      if offset >= end {
        raise InvalidPacket("truncated RTCP SDES item length")
      }
      let length = data[offset].to_int()
      offset += 1
      if offset + length > end {
        raise InvalidPacket("truncated RTCP SDES item value")
      }
      items.push(
        SourceDescriptionItem::new(
          item_type=sdes_type_from_code(code),
          value=data[offset:offset + length].to_owned(),
        ),
      )
      offset += length
    }
    if !terminated {
      raise InvalidPacket("RTCP SDES chunk has no terminator")
    }
    while offset % 4 != 0 && offset < end {
      if data[offset] != 0 {
        raise InvalidPacket("RTCP SDES padding must be zero")
      }
      offset += 1
    }
    chunks.push(SourceDescriptionChunk::new(source~, items~))
  }
  if offset != end {
    raise InvalidPacket("RTCP SDES contains trailing data")
  }
  SourceDescriptionPacket::new(chunks~)
}

///|
pub fn GoodbyePacket::to_packet(self : GoodbyePacket) -> Packet raise RtcpError {
  if self.sources.is_empty() || self.sources.length() > 31 {
    raise InvalidPacket("RTCP BYE requires between one and 31 sources")
  }
  let body : Array[Byte] = []
  for source in self.sources {
    rtcp_write_u32(body, source)
  }
  match self.reason {
    Some(reason) => {
      if reason.length() > 255 {
        raise InvalidPacket("RTCP BYE reason exceeds 255 bytes")
      }
      body.push(reason.length().to_byte())
      for byte in reason {
        body.push(byte)
      }
      while body.length() % 4 != 0 {
        body.push(0)
      }
    }
    None => ()
  }
  Goodbye(
    build_packet(self.sources.length().to_byte(), 203, Bytes::from_array(body)),
  )
}

///|
pub fn GoodbyePacket::marshal(self : GoodbyePacket) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_goodbye(self : Packet) -> GoodbyePacket raise RtcpError {
  guard self is Goodbye(data) else {
    raise InvalidPacket("RTCP packet is not BYE")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  let source_count = header.count.to_int()
  let required = 4 + source_count * 4
  if source_count == 0 || required > end {
    raise InvalidPacket("truncated RTCP BYE")
  }
  let sources : Array[UInt] = []
  for index = 0; index < source_count; index = index + 1 {
    sources.push(rtcp_read_u32(data, 4 + index * 4))
  }
  let reason : Bytes? = if required == end {
    None
  } else {
    let reason_length = data[required].to_int()
    if required + 1 + reason_length > end {
      raise InvalidPacket("truncated RTCP BYE reason")
    }
    for byte in data[required + 1 + reason_length:end] {
      if byte != 0 {
        raise InvalidPacket("RTCP BYE padding must be zero")
      }
    }
    Some(data[required + 1:required + 1 + reason_length].to_owned())
  }
  GoodbyePacket::new(sources~, reason?)
}

///|
pub fn ApplicationDefinedPacket::to_packet(
  self : ApplicationDefinedPacket,
) -> Packet raise RtcpError {
  if self.subtype > 31 || self.name.length() != 4 || self.data.length() % 4 != 0 {
    raise InvalidPacket("invalid RTCP APP packet")
  }
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.ssrc)
  for byte in self.name {
    body.push(byte)
  }
  for byte in self.data {
    body.push(byte)
  }
  ApplicationDefined(build_packet(self.subtype, 204, Bytes::from_array(body)))
}

///|
pub fn ApplicationDefinedPacket::marshal(
  self : ApplicationDefinedPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_application_defined(
  self : Packet,
) -> ApplicationDefinedPacket raise RtcpError {
  guard self is ApplicationDefined(data) else {
    raise InvalidPacket("RTCP packet is not APP")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if end < 12 {
    raise InvalidPacket("truncated RTCP APP packet")
  }
  ApplicationDefinedPacket::new(
    subtype=header.count,
    ssrc=rtcp_read_u32(data, 4),
    name=data[8:12].to_owned(),
    data=data[12:end].to_owned(),
  )
}

///|
pub fn TransportLayerNackPacket::to_packet(
  self : TransportLayerNackPacket,
) -> Packet raise RtcpError {
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u32(body, self.media_ssrc)
  for nack in self.nacks {
    rtcp_write_u16(body, nack.packet_id)
    rtcp_write_u16(body, nack.lost_packets)
  }
  TransportFeedback(build_packet(1, 205, Bytes::from_array(body)))
}

///|
pub fn TransportLayerNackPacket::marshal(
  self : TransportLayerNackPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_transport_layer_nack(
  self : Packet,
) -> TransportLayerNackPacket raise RtcpError {
  guard self is TransportFeedback(data) else {
    raise InvalidPacket("RTCP packet is not transport feedback")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 1 || end < 12 || (end - 12) % 4 != 0 {
    raise InvalidPacket("RTCP feedback packet is not a valid NACK")
  }
  let nacks : Array[NackPair] = []
  for offset = 12; offset < end; offset = offset + 4 {
    nacks.push({
      packet_id: rtcp_read_u16(data, offset),
      lost_packets: rtcp_read_u16(data, offset + 2),
    })
  }
  {
    sender_ssrc: rtcp_read_u32(data, 4),
    media_ssrc: rtcp_read_u32(data, 8),
    nacks,
  }
}

///|
fn transport_wide_symbol(status : TransportWideStatus) -> UInt16 {
  match status {
    PacketNotReceived => 0
    PacketReceivedSmallDelta(_) => 1
    PacketReceivedLargeDelta(_) => 2
    PacketReceivedWithoutDelta => 3
  }
}

///|
fn validate_transport_wide_status(
  status : TransportWideStatus,
) -> Unit raise RtcpError {
  match status {
    PacketReceivedSmallDelta(delta) if delta < 0 ||
      delta > 63750 ||
      delta % 250 != 0 =>
      raise InvalidPacket("invalid transport-cc small receive delta")
    PacketReceivedLargeDelta(delta) if delta < -8192000 ||
      delta > 8191750 ||
      delta % 250 != 0 =>
      raise InvalidPacket("invalid transport-cc large receive delta")
    _ => ()
  }
}

///|
pub fn TransportWideCcPacket::to_packet(
  self : TransportWideCcPacket,
) -> Packet raise RtcpError {
  if self.reference_time > 0xffffffU || self.statuses.length() > 0xffff {
    raise InvalidPacket("invalid RTCP transport-cc header")
  }
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u32(body, self.media_ssrc)
  rtcp_write_u16(body, self.base_sequence_number)
  rtcp_write_u16(body, self.statuses.length().to_uint16())
  rtcp_write_u24(body, self.reference_time)
  body.push(self.feedback_packet_count)
  let mut offset = 0
  while offset < self.statuses.length() {
    let symbol = transport_wide_symbol(self.statuses[offset])
    let mut run_length = 1
    while offset + run_length < self.statuses.length() &&
          run_length < 0x1fff &&
          transport_wide_symbol(self.statuses[offset + run_length]) == symbol {
      run_length += 1
    }
    rtcp_write_u16(body, (symbol << 13) | run_length.to_uint16())
    offset += run_length
  }
  for status in self.statuses {
    validate_transport_wide_status(status)
    match status {
      PacketReceivedSmallDelta(delta) => body.push((delta / 250).to_byte())
      PacketReceivedLargeDelta(delta) =>
        rtcp_write_u16(body, (delta / 250).reinterpret_as_uint().to_uint16())
      PacketNotReceived | PacketReceivedWithoutDelta => ()
    }
  }
  while body.length() % 4 != 0 {
    body.push(0)
  }
  TransportFeedback(build_packet(15, 205, Bytes::from_array(body)))
}

///|
pub fn TransportWideCcPacket::marshal(
  self : TransportWideCcPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_transport_wide_cc(
  self : Packet,
) -> TransportWideCcPacket raise RtcpError {
  guard self is TransportFeedback(data) else {
    raise InvalidPacket("RTCP packet is not transport feedback")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 15 || end < 20 {
    raise InvalidPacket("RTCP feedback packet is not transport-cc")
  }
  let status_count = rtcp_read_u16(data, 14).to_int()
  let symbols : Array[UInt16] = []
  let mut offset = 20
  while symbols.length() < status_count {
    if offset + 2 > end {
      raise InvalidPacket("truncated transport-cc status chunks")
    }
    let chunk = rtcp_read_u16(data, offset)
    offset += 2
    if (chunk & 0x8000) == 0 {
      let symbol = (chunk >> 13) & 0x0003
      let run_length = (chunk & 0x1fff).to_int()
      if run_length == 0 || symbols.length() + run_length > status_count {
        raise InvalidPacket("invalid transport-cc run-length chunk")
      }
      for run_index = 0; run_index < run_length; run_index = run_index + 1 {
        symbols.push(symbol)
      }
    } else if (chunk & 0x4000) == 0 {
      for bit = 13; bit >= 0 && symbols.length() < status_count; bit = bit - 1 {
        symbols.push((chunk >> bit) & 0x0001)
      }
    } else {
      for pair = 0; pair < 7 && symbols.length() < status_count; pair = pair + 1 {
        let shift = 12 - pair * 2
        symbols.push((chunk >> shift) & 0x0003)
      }
    }
  }
  let statuses : Array[TransportWideStatus] = []
  for symbol in symbols {
    match symbol {
      0 => statuses.push(PacketNotReceived)
      1 => {
        if offset >= end {
          raise InvalidPacket("truncated transport-cc small delta")
        }
        statuses.push(PacketReceivedSmallDelta(data[offset].to_int() * 250))
        offset += 1
      }
      2 => {
        if offset + 2 > end {
          raise InvalidPacket("truncated transport-cc large delta")
        }
        let encoded = rtcp_read_u16(data, offset).to_uint()
        let units = if (encoded & 0x8000U) != 0U {
          encoded.reinterpret_as_int() - 0x10000
        } else {
          encoded.reinterpret_as_int()
        }
        statuses.push(PacketReceivedLargeDelta(units * 250))
        offset += 2
      }
      _ => statuses.push(PacketReceivedWithoutDelta)
    }
  }
  if end - offset > 3 {
    raise InvalidPacket("transport-cc packet contains trailing data")
  }
  for byte in data[offset:end] {
    if byte != 0 {
      raise InvalidPacket("transport-cc alignment padding must be zero")
    }
  }
  TransportWideCcPacket::new(
    sender_ssrc=rtcp_read_u32(data, 4),
    media_ssrc=rtcp_read_u32(data, 8),
    base_sequence_number=rtcp_read_u16(data, 12),
    reference_time=rtcp_read_u24(data, 16),
    feedback_packet_count=data[19],
    statuses~,
  )
}

///|
pub fn PictureLossIndicationPacket::to_packet(
  self : PictureLossIndicationPacket,
) -> Packet raise RtcpError {
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u32(body, self.media_ssrc)
  PayloadFeedback(build_packet(1, 206, Bytes::from_array(body)))
}

///|
pub fn PictureLossIndicationPacket::marshal(
  self : PictureLossIndicationPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_picture_loss_indication(
  self : Packet,
) -> PictureLossIndicationPacket raise RtcpError {
  guard self is PayloadFeedback(data) else {
    raise InvalidPacket("RTCP packet is not payload feedback")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 1 || end != 12 {
    raise InvalidPacket("RTCP feedback packet is not a valid PLI")
  }
  { sender_ssrc: rtcp_read_u32(data, 4), media_ssrc: rtcp_read_u32(data, 8), }
}

///|
pub fn FullIntraRequestPacket::to_packet(
  self : FullIntraRequestPacket,
) -> Packet raise RtcpError {
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u32(body, self.media_ssrc)
  for entry in self.entries {
    rtcp_write_u32(body, entry.ssrc)
    body.push(entry.sequence_number)
    body.push(0)
    body.push(0)
    body.push(0)
  }
  PayloadFeedback(build_packet(4, 206, Bytes::from_array(body)))
}

///|
pub fn FullIntraRequestPacket::marshal(
  self : FullIntraRequestPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_full_intra_request(
  self : Packet,
) -> FullIntraRequestPacket raise RtcpError {
  guard self is PayloadFeedback(data) else {
    raise InvalidPacket("RTCP packet is not payload feedback")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 4 || end < 12 || (end - 12) % 8 != 0 {
    raise InvalidPacket("RTCP feedback packet is not a valid FIR")
  }
  let entries : Array[FullIntraRequestEntry] = []
  for offset = 12; offset < end; offset = offset + 8 {
    if data[offset + 5] != 0 || data[offset + 6] != 0 || data[offset + 7] != 0 {
      raise InvalidPacket("RTCP FIR reserved bytes are nonzero")
    }
    entries.push({
      ssrc: rtcp_read_u32(data, offset),
      sequence_number: data[offset + 4],
    })
  }
  {
    sender_ssrc: rtcp_read_u32(data, 4),
    media_ssrc: rtcp_read_u32(data, 8),
    entries,
  }
}

///|
fn encode_remb_bitrate(bitrate : UInt64) -> (Byte, UInt) raise RtcpError {
  let mut exponent : Byte = 0
  let mut mantissa = bitrate
  while mantissa > 0x3ffffUL && exponent < 63 {
    mantissa = mantissa >> 1
    exponent += 1
  }
  if mantissa > 0x3ffffUL {
    raise PacketTooLarge(0)
  }
  (exponent, mantissa.to_uint())
}

///|
pub fn ReceiverEstimatedMaximumBitratePacket::to_packet(
  self : ReceiverEstimatedMaximumBitratePacket,
) -> Packet raise RtcpError {
  if self.ssrcs.length() > 255 {
    raise InvalidPacket("RTCP REMB contains more than 255 SSRC values")
  }
  let (exponent, mantissa) = encode_remb_bitrate(self.bitrate)
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  rtcp_write_u32(body, 0U)
  body.push(0x52)
  body.push(0x45)
  body.push(0x4d)
  body.push(0x42)
  body.push(self.ssrcs.length().to_byte())
  body.push(((exponent.to_uint() << 2) | (mantissa >> 16)).to_byte())
  body.push((mantissa >> 8).to_byte())
  body.push(mantissa.to_byte())
  for ssrc in self.ssrcs {
    rtcp_write_u32(body, ssrc)
  }
  PayloadFeedback(build_packet(15, 206, Bytes::from_array(body)))
}

///|
pub fn ReceiverEstimatedMaximumBitratePacket::marshal(
  self : ReceiverEstimatedMaximumBitratePacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_receiver_estimated_maximum_bitrate(
  self : Packet,
) -> ReceiverEstimatedMaximumBitratePacket raise RtcpError {
  guard self is PayloadFeedback(data) else {
    raise InvalidPacket("RTCP packet is not payload feedback")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 15 || end < 20 || data[12:16] != b"REMB" {
    raise InvalidPacket("RTCP feedback packet is not REMB")
  }
  let count = data[16].to_int()
  if end != 20 + count * 4 {
    raise InvalidPacket("RTCP REMB SSRC count does not match its length")
  }
  let exponent = data[17].to_uint() >> 2
  let mantissa = ((data[17].to_uint() & 0x03) << 16) |
    (data[18].to_uint() << 8) |
    data[19].to_uint()
  let ssrcs : Array[UInt] = []
  for index = 0; index < count; index = index + 1 {
    ssrcs.push(rtcp_read_u32(data, 20 + index * 4))
  }
  ReceiverEstimatedMaximumBitratePacket::new(
    sender_ssrc=rtcp_read_u32(data, 4),
    bitrate=mantissa.to_uint64() << exponent.reinterpret_as_int(),
    ssrcs~,
  )
}

///|
pub fn ExtendedReportPacket::to_packet(
  self : ExtendedReportPacket,
) -> Packet raise RtcpError {
  let body : Array[Byte] = []
  rtcp_write_u32(body, self.sender_ssrc)
  for block in self.blocks {
    if block.payload.length() % 4 != 0 || block.payload.length() / 4 > 0xffff {
      raise InvalidPacket("invalid RTCP XR block length")
    }
    body.push(block.block_type)
    body.push(block.type_specific)
    rtcp_write_u16(body, (block.payload.length() / 4).to_uint16())
    for byte in block.payload {
      body.push(byte)
    }
  }
  ExtendedReport(build_packet(0, 207, Bytes::from_array(body)))
}

///|
pub fn ExtendedReportPacket::marshal(
  self : ExtendedReportPacket,
) -> Bytes raise RtcpError {
  self.to_packet().marshal()
}

///|
pub fn Packet::as_extended_report(
  self : Packet,
) -> ExtendedReportPacket raise RtcpError {
  guard self is ExtendedReport(data) else {
    raise InvalidPacket("RTCP packet is not an extended report")
  }
  let header = validate_single_packet(data)
  let end = unpadded_end(data, header)
  if header.count != 0 || end < 8 {
    raise InvalidPacket("invalid RTCP extended report header")
  }
  let blocks : Array[ExtendedReportBlock] = []
  let mut offset = 8
  while offset < end {
    if offset + 4 > end {
      raise InvalidPacket("truncated RTCP XR block header")
    }
    let payload_length = rtcp_read_u16(data, offset + 2).to_int() * 4
    if offset + 4 + payload_length > end {
      raise InvalidPacket("truncated RTCP XR block")
    }
    blocks.push(
      ExtendedReportBlock::new(
        block_type=data[offset],
        type_specific=data[offset + 1],
        payload=data[offset + 4:offset + 4 + payload_length].to_owned(),
      ),
    )
    offset += 4 + payload_length
  }
  { sender_ssrc: rtcp_read_u32(data, 4), blocks, }
}
