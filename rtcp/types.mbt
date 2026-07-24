///|
pub(all) suberror RtcpError {
  InvalidPacket(String)
  InvalidCompoundPacket(String)
  PacketTooLarge(Int)
} derive(Debug, Eq)

///|
pub(all) enum Packet {
  SenderReport(Bytes)
  ReceiverReport(Bytes)
  SourceDescription(Bytes)
  Goodbye(Bytes)
  ApplicationDefined(Bytes)
  TransportFeedback(Bytes)
  PayloadFeedback(Bytes)
  ExtendedReport(Bytes)
  Unknown(Bytes)
} derive(Debug, Eq)

///|
pub(all) struct ReceptionReport {
  ssrc : UInt
  fraction_lost : Byte
  cumulative_lost : Int
  extended_sequence_number : UInt
  jitter : UInt
  last_sender_report : UInt
  delay_since_last_sender_report : UInt
} derive(Debug, Eq)

///|
pub fn ReceptionReport::new(
  ssrc~ : UInt,
  fraction_lost? : Byte = 0,
  cumulative_lost? : Int = 0,
  extended_sequence_number? : UInt = 0U,
  jitter? : UInt = 0U,
  last_sender_report? : UInt = 0U,
  delay_since_last_sender_report? : UInt = 0U,
) -> ReceptionReport raise RtcpError {
  if cumulative_lost < -8388608 || cumulative_lost > 8388607 {
    raise InvalidPacket("RTCP cumulative loss does not fit in signed 24 bits")
  }
  {
    ssrc,
    fraction_lost,
    cumulative_lost,
    extended_sequence_number,
    jitter,
    last_sender_report,
    delay_since_last_sender_report,
  }
}

///|
pub fn ReceptionReport::ssrc(self : ReceptionReport) -> UInt {
  self.ssrc
}

///|
pub fn ReceptionReport::fraction_lost(self : ReceptionReport) -> Byte {
  self.fraction_lost
}

///|
pub fn ReceptionReport::cumulative_lost(self : ReceptionReport) -> Int {
  self.cumulative_lost
}

///|
pub fn ReceptionReport::extended_sequence_number(
  self : ReceptionReport,
) -> UInt {
  self.extended_sequence_number
}

///|
pub fn ReceptionReport::jitter(self : ReceptionReport) -> UInt {
  self.jitter
}

///|
pub fn ReceptionReport::last_sender_report(self : ReceptionReport) -> UInt {
  self.last_sender_report
}

///|
pub fn ReceptionReport::delay_since_last_sender_report(
  self : ReceptionReport,
) -> UInt {
  self.delay_since_last_sender_report
}

///|
pub(all) struct SenderReportPacket {
  sender_ssrc : UInt
  ntp_timestamp : UInt64
  rtp_timestamp : UInt
  packet_count : UInt
  octet_count : UInt
  reports : Array[ReceptionReport]
  profile_extensions : Bytes
} derive(Debug, Eq)

///|
pub fn SenderReportPacket::new(
  sender_ssrc~ : UInt,
  ntp_timestamp~ : UInt64,
  rtp_timestamp~ : UInt,
  packet_count~ : UInt,
  octet_count~ : UInt,
  reports? : Array[ReceptionReport] = [],
  profile_extensions? : Bytes = b"",
) -> SenderReportPacket raise RtcpError {
  if reports.length() > 31 {
    raise InvalidPacket("RTCP sender report contains more than 31 reports")
  }
  if profile_extensions.length() % 4 != 0 {
    raise InvalidPacket("RTCP profile extension must be 32-bit aligned")
  }
  {
    sender_ssrc,
    ntp_timestamp,
    rtp_timestamp,
    packet_count,
    octet_count,
    reports: reports.copy(),
    profile_extensions,
  }
}

///|
pub(all) struct ReceiverReportPacket {
  sender_ssrc : UInt
  reports : Array[ReceptionReport]
  profile_extensions : Bytes
} derive(Debug, Eq)

///|
pub fn ReceiverReportPacket::new(
  sender_ssrc~ : UInt,
  reports? : Array[ReceptionReport] = [],
  profile_extensions? : Bytes = b"",
) -> ReceiverReportPacket raise RtcpError {
  if reports.length() > 31 {
    raise InvalidPacket("RTCP receiver report contains more than 31 reports")
  }
  if profile_extensions.length() % 4 != 0 {
    raise InvalidPacket("RTCP profile extension must be 32-bit aligned")
  }
  { sender_ssrc, reports: reports.copy(), profile_extensions }
}

///|
pub(all) enum SourceDescriptionType {
  Cname
  Name
  Email
  Phone
  Location
  Tool
  Note
  Private
  Unknown(Byte)
} derive(Debug, Eq)

///|
pub(all) struct SourceDescriptionItem {
  item_type : SourceDescriptionType
  value : Bytes
} derive(Debug, Eq)

///|
pub fn SourceDescriptionItem::new(
  item_type~ : SourceDescriptionType,
  value~ : Bytes,
) -> SourceDescriptionItem raise RtcpError {
  if value.length() > 255 {
    raise InvalidPacket("RTCP SDES item exceeds 255 bytes")
  }
  { item_type, value }
}

///|
pub(all) struct SourceDescriptionChunk {
  source : UInt
  items : Array[SourceDescriptionItem]
} derive(Debug, Eq)

///|
pub fn SourceDescriptionChunk::new(
  source~ : UInt,
  items? : Array[SourceDescriptionItem] = [],
) -> SourceDescriptionChunk {
  { source, items: items.copy() }
}

///|
pub(all) struct SourceDescriptionPacket {
  chunks : Array[SourceDescriptionChunk]
} derive(Debug, Eq)

///|
pub fn SourceDescriptionPacket::new(
  chunks~ : Array[SourceDescriptionChunk],
) -> SourceDescriptionPacket raise RtcpError {
  if chunks.length() > 31 {
    raise InvalidPacket("RTCP SDES packet contains more than 31 chunks")
  }
  { chunks: chunks.copy() }
}

///|
pub(all) struct GoodbyePacket {
  sources : Array[UInt]
  reason : Bytes?
} derive(Debug, Eq)

///|
pub fn GoodbyePacket::new(
  sources~ : Array[UInt],
  reason? : Bytes,
) -> GoodbyePacket raise RtcpError {
  if sources.is_empty() || sources.length() > 31 {
    raise InvalidPacket("RTCP BYE requires between one and 31 sources")
  }
  match reason {
    Some(value) if value.length() > 255 =>
      raise InvalidPacket("RTCP BYE reason exceeds 255 bytes")
    _ => ()
  }
  { sources: sources.copy(), reason }
}

///|
pub(all) struct ApplicationDefinedPacket {
  subtype : Byte
  ssrc : UInt
  name : Bytes
  data : Bytes
} derive(Debug, Eq)

///|
pub fn ApplicationDefinedPacket::new(
  subtype? : Byte = 0,
  ssrc~ : UInt,
  name~ : Bytes,
  data? : Bytes = b"",
) -> ApplicationDefinedPacket raise RtcpError {
  if subtype > 31 {
    raise InvalidPacket("RTCP APP subtype exceeds five bits")
  }
  if name.length() != 4 {
    raise InvalidPacket("RTCP APP name must contain exactly four bytes")
  }
  if data.length() % 4 != 0 {
    raise InvalidPacket("RTCP APP data must be 32-bit aligned")
  }
  { subtype, ssrc, name, data }
}

///|
pub(all) struct NackPair {
  packet_id : UInt16
  lost_packets : UInt16
} derive(Debug, Eq)

///|
pub fn NackPair::new(
  packet_id~ : UInt16,
  lost_packets? : UInt16 = 0,
) -> NackPair {
  { packet_id, lost_packets }
}

///|
pub fn NackPair::lost_sequence_numbers(self : NackPair) -> Array[UInt16] {
  let result : Array[UInt16] = [self.packet_id]
  for bit = 0; bit < 16; bit = bit + 1 {
    if (self.lost_packets & (1U << bit).to_uint16()) != 0 {
      result.push(self.packet_id + (bit + 1).to_uint16())
    }
  }
  result
}

///|
pub(all) struct TransportLayerNackPacket {
  sender_ssrc : UInt
  media_ssrc : UInt
  nacks : Array[NackPair]
} derive(Debug, Eq)

///|
pub fn TransportLayerNackPacket::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
  nacks~ : Array[NackPair],
) -> TransportLayerNackPacket {
  { sender_ssrc, media_ssrc, nacks: nacks.copy() }
}

///|
pub(all) enum TransportWideStatus {
  PacketNotReceived
  PacketReceivedSmallDelta(Int)
  PacketReceivedLargeDelta(Int)
  PacketReceivedWithoutDelta
} derive(Debug, Eq)

///|
pub(all) struct TransportWideCcPacket {
  sender_ssrc : UInt
  media_ssrc : UInt
  base_sequence_number : UInt16
  reference_time : UInt
  feedback_packet_count : Byte
  statuses : Array[TransportWideStatus]
} derive(Debug, Eq)

///|
pub fn TransportWideCcPacket::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
  base_sequence_number~ : UInt16,
  reference_time~ : UInt,
  feedback_packet_count? : Byte = 0,
  statuses~ : Array[TransportWideStatus],
) -> TransportWideCcPacket raise RtcpError {
  if reference_time > 0xffffffU {
    raise InvalidPacket("RTCP transport-cc reference time exceeds 24 bits")
  }
  if statuses.length() > 0xffff {
    raise InvalidPacket("RTCP transport-cc status count exceeds 65535")
  }
  for status in statuses {
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
  {
    sender_ssrc,
    media_ssrc,
    base_sequence_number,
    reference_time,
    feedback_packet_count,
    statuses: statuses.copy(),
  }
}

///|
pub(all) struct PictureLossIndicationPacket {
  sender_ssrc : UInt
  media_ssrc : UInt
} derive(Debug, Eq)

///|
pub fn PictureLossIndicationPacket::new(
  sender_ssrc~ : UInt,
  media_ssrc~ : UInt,
) -> PictureLossIndicationPacket {
  { sender_ssrc, media_ssrc }
}

///|
pub(all) struct FullIntraRequestEntry {
  ssrc : UInt
  sequence_number : Byte
} derive(Debug, Eq)

///|
pub(all) struct FullIntraRequestPacket {
  sender_ssrc : UInt
  media_ssrc : UInt
  entries : Array[FullIntraRequestEntry]
} derive(Debug, Eq)

///|
pub fn FullIntraRequestPacket::new(
  sender_ssrc~ : UInt,
  media_ssrc? : UInt = 0U,
  entries~ : Array[FullIntraRequestEntry],
) -> FullIntraRequestPacket {
  { sender_ssrc, media_ssrc, entries: entries.copy() }
}

///|
pub(all) struct ReceiverEstimatedMaximumBitratePacket {
  sender_ssrc : UInt
  bitrate : UInt64
  ssrcs : Array[UInt]
} derive(Debug, Eq)

///|
pub fn ReceiverEstimatedMaximumBitratePacket::new(
  sender_ssrc~ : UInt,
  bitrate~ : UInt64,
  ssrcs~ : Array[UInt],
) -> ReceiverEstimatedMaximumBitratePacket raise RtcpError {
  if ssrcs.length() > 255 {
    raise InvalidPacket("RTCP REMB contains more than 255 SSRC values")
  }
  { sender_ssrc, bitrate, ssrcs: ssrcs.copy() }
}

///|
pub(all) struct ExtendedReportBlock {
  block_type : Byte
  type_specific : Byte
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn ExtendedReportBlock::new(
  block_type~ : Byte,
  type_specific? : Byte = 0,
  payload~ : Bytes,
) -> ExtendedReportBlock raise RtcpError {
  if payload.length() % 4 != 0 {
    raise InvalidPacket("RTCP XR block payload must be 32-bit aligned")
  }
  { block_type, type_specific, payload }
}

///|
pub(all) struct ExtendedReportPacket {
  sender_ssrc : UInt
  blocks : Array[ExtendedReportBlock]
} derive(Debug, Eq)

///|
pub fn ExtendedReportPacket::new(
  sender_ssrc~ : UInt,
  blocks? : Array[ExtendedReportBlock] = [],
) -> ExtendedReportPacket {
  { sender_ssrc, blocks: blocks.copy() }
}
