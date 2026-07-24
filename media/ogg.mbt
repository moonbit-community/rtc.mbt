///|
const OGG_PAGE_HEADER_SIZE : Int = 27

///|
const OGG_DEFAULT_PRE_SKIP : UInt16 = 3840

///|
const OGG_BOS : Byte = 0x02

///|
const OGG_EOS : Byte = 0x04

///|
const OGG_CONTINUED : Byte = 0x01

///|
fn ogg_crc_page(page : Array[Byte]) -> UInt {
  let mut crc = 0U
  for index = 0; index < page.length(); index = index + 1 {
    let byte : Byte = if index >= 22 && index < 26 { 0 } else { page[index] }
    crc = crc ^ (byte.to_uint() << 24)
    for bit = 0; bit < 8; bit = bit + 1 {
      crc = if (crc & 0x80000000U) != 0 {
        (crc << 1) ^ 0x04c11db7U
      } else {
        crc << 1
      }
    }
  }
  crc
}

///|
pub(all) struct UserComment {
  key : String
  value : String
} derive(Debug, Eq)

///|
pub fn UserComment::new(key~ : String, value~ : String) -> UserComment {
  { key, value }
}

///|
pub fn UserComment::key(self : UserComment) -> String {
  self.key
}

///|
pub fn UserComment::value(self : UserComment) -> String {
  self.value
}

///|
pub(all) struct OpusTags {
  vendor : String
  comments : Array[UserComment]
} derive(Debug, Eq)

///|
pub fn OpusTags::new(
  vendor~ : String,
  comments? : Array[UserComment] = [],
) -> OpusTags {
  { vendor, comments: comments.copy() }
}

///|
pub fn OpusTags::vendor(self : OpusTags) -> String {
  self.vendor
}

///|
pub fn OpusTags::comments(self : OpusTags) -> Array[UserComment] {
  self.comments.copy()
}

///|
pub(all) struct OggHeader {
  version : Byte
  channels : Byte
  pre_skip : UInt16
  sample_rate : UInt
  output_gain : UInt16
  channel_mapping_family : Byte
  stream_count : Byte
  coupled_count : Byte
  channel_mapping : Bytes
} derive(Debug, Eq)

///|
pub fn OggHeader::version(self : OggHeader) -> Byte {
  self.version
}

///|
pub fn OggHeader::channels(self : OggHeader) -> Byte {
  self.channels
}

///|
pub fn OggHeader::pre_skip(self : OggHeader) -> UInt16 {
  self.pre_skip
}

///|
pub fn OggHeader::sample_rate(self : OggHeader) -> UInt {
  self.sample_rate
}

///|
pub fn OggHeader::output_gain(self : OggHeader) -> UInt16 {
  self.output_gain
}

///|
pub fn OggHeader::channel_mapping_family(self : OggHeader) -> Byte {
  self.channel_mapping_family
}

///|
pub fn OggHeader::stream_count(self : OggHeader) -> Byte {
  self.stream_count
}

///|
pub fn OggHeader::coupled_count(self : OggHeader) -> Byte {
  self.coupled_count
}

///|
pub fn OggHeader::channel_mapping(self : OggHeader) -> Bytes {
  self.channel_mapping
}

///|
pub(all) struct OggPageHeader {
  header_type : Byte
  granule_position : UInt64
  serial : UInt
  sequence : UInt
  checksum : UInt
  segments : Bytes
} derive(Debug, Eq)

///|
pub fn OggPageHeader::header_type(self : OggPageHeader) -> Byte {
  self.header_type
}

///|
pub fn OggPageHeader::granule_position(self : OggPageHeader) -> UInt64 {
  self.granule_position
}

///|
pub fn OggPageHeader::serial(self : OggPageHeader) -> UInt {
  self.serial
}

///|
pub fn OggPageHeader::sequence(self : OggPageHeader) -> UInt {
  self.sequence
}

///|
pub fn OggPageHeader::checksum(self : OggPageHeader) -> UInt {
  self.checksum
}

///|
pub fn OggPageHeader::segments(self : OggPageHeader) -> Bytes {
  self.segments
}

///|
pub fn OggPageHeader::is_beginning_of_stream(self : OggPageHeader) -> Bool {
  (self.header_type & OGG_BOS) != 0
}

///|
pub fn OggPageHeader::is_end_of_stream(self : OggPageHeader) -> Bool {
  (self.header_type & OGG_EOS) != 0
}

///|
pub(all) struct OggPage {
  header : OggPageHeader
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn OggPage::header(self : OggPage) -> OggPageHeader {
  self.header
}

///|
pub fn OggPage::payload(self : OggPage) -> Bytes {
  self.payload
}

///|
pub(all) struct OggPacket {
  data : Bytes
  granule_position : UInt64
  end_of_stream : Bool
} derive(Debug, Eq)

///|
pub fn OggPacket::data(self : OggPacket) -> Bytes {
  self.data
}

///|
pub fn OggPacket::granule_position(self : OggPacket) -> UInt64 {
  self.granule_position
}

///|
pub fn OggPacket::is_end_of_stream(self : OggPacket) -> Bool {
  self.end_of_stream
}

///|
fn ogg_encode_page(
  payload : Bytes,
  header_type : Byte,
  granule_position : UInt64,
  serial : UInt,
  sequence : UInt,
) -> Bytes raise MediaError {
  let segment_count = payload.length() / 255 + 1
  if segment_count > 255 {
    raise InvalidMedia("Ogg packet needs more than 255 lacing values")
  }
  let page : Array[Byte] = []
  for byte in b"OggS" {
    page.push(byte)
  }
  page.push(0)
  page.push(header_type)
  media_write_u64_le(page, granule_position)
  media_write_u32_le(page, serial)
  media_write_u32_le(page, sequence)
  media_write_u32_le(page, 0)
  page.push(segment_count.to_byte())
  let full_segments = payload.length() / 255
  for index = 0; index < full_segments; index = index + 1 {
    page.push(255)
  }
  page.push((payload.length() % 255).to_byte())
  for byte in payload {
    page.push(byte)
  }
  let checksum = ogg_crc_page(page)
  page[22] = checksum.to_byte()
  page[23] = (checksum >> 8).to_byte()
  page[24] = (checksum >> 16).to_byte()
  page[25] = (checksum >> 24).to_byte()
  Bytes::from_array(page)
}

///|
fn ogg_parse_page_at(
  data : Bytes,
  offset : Int,
  verify_checksum : Bool,
) -> (OggPage, Int) raise MediaError {
  if offset < 0 || offset + OGG_PAGE_HEADER_SIZE > data.length() {
    raise InvalidMedia("truncated Ogg page header")
  }
  if data[offset:offset + 4] != b"OggS" {
    raise InvalidMedia("invalid Ogg capture pattern")
  }
  if data[offset + 4] != 0 {
    raise InvalidMedia("unsupported Ogg bitstream version")
  }
  let segment_count = data[offset + 26].to_int()
  let table_start = offset + OGG_PAGE_HEADER_SIZE
  let body_start = table_start + segment_count
  if body_start > data.length() {
    raise InvalidMedia("truncated Ogg segment table")
  }
  let mut body_length = 0
  for lace in data[table_start:body_start] {
    body_length += lace.to_int()
  }
  let page_end = body_start + body_length
  if page_end > data.length() {
    raise InvalidMedia("Ogg lacing values exceed page data")
  }
  let checksum = media_read_u32_le(data, offset + 22)
  if verify_checksum {
    let page = data[offset:page_end].to_array()
    if ogg_crc_page(page) != checksum {
      raise InvalidMedia("Ogg page checksum mismatch")
    }
  }
  let header : OggPageHeader = {
    header_type: data[offset + 5],
    granule_position: media_read_u64_le(data, offset + 6),
    serial: media_read_u32_le(data, offset + 14),
    sequence: media_read_u32_le(data, offset + 18),
    checksum,
    segments: data[table_start:body_start].to_owned(),
  }
  ({ header, payload: data[body_start:page_end].to_owned() }, page_end)
}

///|
fn ogg_opus_head(
  sample_rate : UInt,
  channels : Byte,
  pre_skip : UInt16,
) -> Bytes {
  let output : Array[Byte] = []
  for byte in b"OpusHead" {
    output.push(byte)
  }
  output.push(1)
  output.push(channels)
  media_write_u16_le(output, pre_skip)
  media_write_u32_le(output, sample_rate)
  media_write_u16_le(output, 0)
  output.push(0)
  Bytes::from_array(output)
}

///|
fn ogg_opus_tags(tags : OpusTags) -> Bytes {
  let output : Array[Byte] = []
  for byte in b"OpusTags" {
    output.push(byte)
  }
  let vendor = @utf8.encode(tags.vendor)
  media_write_u32_le(output, vendor.length().reinterpret_as_uint())
  for byte in vendor {
    output.push(byte)
  }
  media_write_u32_le(output, tags.comments.length().reinterpret_as_uint())
  for comment in tags.comments {
    let encoded = @utf8.encode(comment.key + "=" + comment.value)
    media_write_u32_le(output, encoded.length().reinterpret_as_uint())
    for byte in encoded {
      output.push(byte)
    }
  }
  Bytes::from_array(output)
}

///|
pub struct OggWriter {
  sample_rate : UInt
  channels : Byte
  pre_skip : UInt16
  serial : UInt
  output : Array[Byte]
  mut sequence : UInt
  mut last_granule_position : UInt64
  mut last_rtp_timestamp : UInt?
  mut closed : Bool
}

///|
pub fn OggWriter::new(
  sample_rate~ : UInt,
  channels~ : Byte,
  pre_skip? : UInt16 = OGG_DEFAULT_PRE_SKIP,
  serial? : UInt = 0x72746301U,
  tags? : OpusTags = { vendor: "rtc.mbt", comments: [] },
) -> OggWriter raise MediaError {
  if sample_rate == 0 || channels == 0 || channels > 2 {
    raise InvalidMedia("Ogg Opus mapping family zero supports mono or stereo")
  }
  let output : Array[Byte] = []
  let id_page = ogg_encode_page(
    ogg_opus_head(sample_rate, channels, pre_skip),
    OGG_BOS,
    0UL,
    serial,
    0U,
  )
  let tags_page = ogg_encode_page(ogg_opus_tags(tags), 0, 0UL, serial, 1U)
  for byte in id_page {
    output.push(byte)
  }
  for byte in tags_page {
    output.push(byte)
  }
  {
    sample_rate,
    channels,
    pre_skip,
    serial,
    output,
    sequence: 2U,
    last_granule_position: 0UL,
    last_rtp_timestamp: None,
    closed: false,
  }
}

///|
fn OggWriter::append_page(
  self : OggWriter,
  payload : Bytes,
  flags : Byte,
  granule_position : UInt64,
) -> Unit raise MediaError {
  let page = ogg_encode_page(
    payload,
    flags,
    granule_position,
    self.serial,
    self.sequence,
  )
  for byte in page {
    self.output.push(byte)
  }
  self.sequence += 1
}

///|
pub fn OggWriter::write_opus_packet(
  self : OggWriter,
  payload : Bytes,
  granule_position : UInt64,
) -> Unit raise MediaError {
  if self.closed {
    raise InvalidMedia("cannot write an Ogg packet after close")
  }
  if payload.is_empty() {
    raise InvalidMedia("cannot write an empty Opus packet")
  }
  if granule_position < self.last_granule_position {
    raise InvalidMedia("Ogg granule position moved backwards")
  }
  self.append_page(payload, 0, granule_position)
  self.last_granule_position = granule_position
}

///|
pub fn OggWriter::write_rtp(
  self : OggWriter,
  packet : @rtp.Packet,
) -> Unit raise MediaError {
  if packet.payload().is_empty() {
    return
  }
  let granule = match self.last_rtp_timestamp {
    None => self.pre_skip.to_uint64()
    Some(previous) =>
      self.last_granule_position + (packet.timestamp() - previous).to_uint64()
  }
  self.write_opus_packet(packet.payload(), granule)
  self.last_rtp_timestamp = Some(packet.timestamp())
}

///|
pub fn OggWriter::close(self : OggWriter) -> Unit raise MediaError {
  if self.closed {
    return
  }
  self.append_page(b"", OGG_EOS, self.last_granule_position)
  self.closed = true
}

///|
pub fn OggWriter::bytes(self : OggWriter) -> Bytes {
  Bytes::from_array(self.output)
}

///|
fn parse_opus_head(payload : Bytes) -> OggHeader raise MediaError {
  if payload.length() < 19 || payload[0:8] != b"OpusHead" {
    raise InvalidMedia("invalid OpusHead packet")
  }
  let version = payload[8]
  let channels = payload[9]
  let pre_skip = media_read_u16_le(payload, 10)
  let sample_rate = media_read_u32_le(payload, 12)
  let output_gain = media_read_u16_le(payload, 16)
  let family = payload[18]
  if version > 15 || channels == 0 || sample_rate == 0 {
    raise InvalidMedia("unsupported OpusHead parameters")
  }
  if family == 0 {
    if channels > 2 || payload.length() != 19 {
      raise InvalidMedia("invalid Opus mapping family zero header")
    }
    return {
      version,
      channels,
      pre_skip,
      sample_rate,
      output_gain,
      channel_mapping_family: family,
      stream_count: 0,
      coupled_count: 0,
      channel_mapping: b"",
    }
  }
  let expected = 21 + channels.to_int()
  if payload.length() < expected {
    raise InvalidMedia("truncated Opus channel mapping")
  }
  {
    version,
    channels,
    pre_skip,
    sample_rate,
    output_gain,
    channel_mapping_family: family,
    stream_count: payload[19],
    coupled_count: payload[20],
    channel_mapping: payload[21:expected].to_owned(),
  }
}

///|
fn parse_opus_tags(payload : Bytes) -> OpusTags raise MediaError {
  if payload.length() < 16 || payload[0:8] != b"OpusTags" {
    raise InvalidMedia("invalid OpusTags packet")
  }
  let vendor_length = media_read_u32_le(payload, 8).reinterpret_as_int()
  let vendor_start = 12
  let vendor_end = vendor_start + vendor_length
  if vendor_length < 0 || vendor_end + 4 > payload.length() {
    raise InvalidMedia("truncated OpusTags vendor")
  }
  let vendor = @utf8.decode(payload[vendor_start:vendor_end]) catch {
    _ => raise InvalidMedia("OpusTags vendor is not valid UTF-8")
  }
  let comment_count = media_read_u32_le(payload, vendor_end).reinterpret_as_int()
  let comments : Array[UserComment] = []
  let mut offset = vendor_end + 4
  for comment_index = 0
      comment_index < comment_count
      comment_index = comment_index + 1 {
    if offset + 4 > payload.length() {
      raise InvalidMedia("truncated OpusTags comment length")
    }
    let length = media_read_u32_le(payload, offset).reinterpret_as_int()
    offset += 4
    if length < 0 || offset + length > payload.length() {
      raise InvalidMedia("truncated OpusTags comment")
    }
    let value = @utf8.decode(payload[offset:offset + length]) catch {
      _ => raise InvalidMedia("OpusTags comment is not valid UTF-8")
    }
    match value.split_once("=") {
      Some((key, comment_value)) =>
        comments.push(
          UserComment::new(key=key.to_owned(), value=comment_value.to_owned()),
        )
      None => ()
    }
    offset += length
  }
  { vendor, comments }
}

///|
fn ogg_single_packet(page : OggPage) -> Bytes raise MediaError {
  let segments = page.header.segments
  if segments.is_empty() || segments[segments.length() - 1] == 255 {
    raise InvalidMedia("Ogg header packet spans multiple pages")
  }
  let mut terminators = 0
  for value in segments {
    if value < 255 {
      terminators += 1
    }
  }
  if terminators != 1 {
    raise InvalidMedia("Ogg header page contains multiple packets")
  }
  page.payload
}

///|
pub struct OggReader {
  data : Bytes
  header : OggHeader
  tags : OpusTags
  verify_checksum : Bool
  mut offset : Int
  pending : Array[Byte]
  queued : Array[OggPacket]
  serial : UInt
  mut expected_sequence : UInt
  mut reached_eos : Bool
}

///|
pub fn OggReader::new(
  data : Bytes,
  verify_checksum? : Bool = true,
) -> OggReader raise MediaError {
  let (id_page, after_id) = ogg_parse_page_at(data, 0, verify_checksum)
  if !id_page.header.is_beginning_of_stream() {
    raise InvalidMedia("OpusHead page is not beginning-of-stream")
  }
  let serial = id_page.header.serial
  let header = parse_opus_head(ogg_single_packet(id_page))
  let (tags_page, after_tags) = ogg_parse_page_at(
    data, after_id, verify_checksum,
  )
  if tags_page.header.serial != serial || tags_page.header.sequence != 1U {
    raise InvalidMedia("Ogg Opus header page sequence is invalid")
  }
  let tags = parse_opus_tags(ogg_single_packet(tags_page))
  {
    data,
    header,
    tags,
    verify_checksum,
    offset: after_tags,
    pending: [],
    queued: [],
    serial,
    expected_sequence: 2U,
    reached_eos: false,
  }
}

///|
pub fn OggReader::header(self : OggReader) -> OggHeader {
  self.header
}

///|
pub fn OggReader::tags(self : OggReader) -> OpusTags {
  self.tags
}

///|
fn OggReader::read_page(self : OggReader) -> OggPage? raise MediaError {
  if self.offset == self.data.length() {
    return None
  }
  let (page, next) = ogg_parse_page_at(
    self.data,
    self.offset,
    self.verify_checksum,
  )
  if page.header.serial != self.serial {
    raise InvalidMedia("unexpected logical stream in Ogg Opus data")
  }
  if page.header.sequence != self.expected_sequence {
    raise InvalidMedia("Ogg page sequence number gap")
  }
  self.offset = next
  self.expected_sequence += 1
  Some(page)
}

///|
fn OggReader::queue_page_packets(
  self : OggReader,
  page : OggPage,
) -> Unit raise MediaError {
  let continued = (page.header.header_type & OGG_CONTINUED) != 0
  if continued != !self.pending.is_empty() {
    raise InvalidMedia("Ogg continued-packet flag does not match lacing state")
  }
  let mut body_offset = 0
  for lace in page.header.segments {
    let length = lace.to_int()
    if body_offset + length > page.payload.length() {
      raise InvalidMedia("Ogg segment exceeds page body")
    }
    for byte in page.payload[body_offset:body_offset + length] {
      self.pending.push(byte)
    }
    body_offset += length
    if lace < 255 {
      if !self.pending.is_empty() {
        self.queued.push({
          data: Bytes::from_array(self.pending),
          granule_position: page.header.granule_position,
          end_of_stream: page.header.is_end_of_stream(),
        })
      }
      self.pending.clear()
    }
  }
  if body_offset != page.payload.length() {
    raise InvalidMedia("Ogg page has unreferenced body bytes")
  }
  if page.header.is_end_of_stream() {
    self.reached_eos = true
    if !self.pending.is_empty() {
      raise InvalidMedia("Ogg stream ends with an incomplete packet")
    }
  }
}

///|
pub fn OggReader::next_packet(self : OggReader) -> OggPacket? raise MediaError {
  while self.queued.is_empty() {
    if self.reached_eos {
      return None
    }
    match self.read_page() {
      None => {
        if !self.pending.is_empty() {
          raise InvalidMedia("Ogg stream ends with an incomplete packet")
        }
        return None
      }
      Some(page) => self.queue_page_packets(page)
    }
  }
  Some(self.queued.remove(0))
}

///|
pub fn OggReader::bytes_read(self : OggReader) -> Int {
  self.offset
}
