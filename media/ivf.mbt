///|
const IVF_HEADER_SIZE : Int = 32

///|
const IVF_FRAME_HEADER_SIZE : Int = 12

///|
fn media_read_u16_le(data : Bytes, offset : Int) -> UInt16 raise MediaError {
  if offset < 0 || offset + 2 > data.length() {
    raise InvalidMedia("truncated little-endian 16-bit field")
  }
  (data[offset].to_uint() | (data[offset + 1].to_uint() << 8)).to_uint16()
}

///|
fn media_read_u32_le(data : Bytes, offset : Int) -> UInt raise MediaError {
  if offset < 0 || offset + 4 > data.length() {
    raise InvalidMedia("truncated little-endian 32-bit field")
  }
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn media_read_u64_le(data : Bytes, offset : Int) -> UInt64 raise MediaError {
  if offset < 0 || offset + 8 > data.length() {
    raise InvalidMedia("truncated little-endian 64-bit field")
  }
  let mut value = 0UL
  for index = 0; index < 8; index = index + 1 {
    value = value | (data[offset + index].to_uint64() << (index * 8))
  }
  value
}

///|
fn media_write_u16_le(output : Array[Byte], value : UInt16) -> Unit {
  output.push(value.to_byte())
  output.push((value >> 8).to_byte())
}

///|
fn media_write_u32_le(output : Array[Byte], value : UInt) -> Unit {
  output.push(value.to_byte())
  output.push((value >> 8).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 24).to_byte())
}

///|
fn media_write_u64_le(output : Array[Byte], value : UInt64) -> Unit {
  for index = 0; index < 8; index = index + 1 {
    output.push((value >> (index * 8)).to_byte())
  }
}

///|
pub(all) enum IvfCodec {
  Vp8
  Vp9
  Av1
} derive(Debug, Eq)

///|
pub fn IvfCodec::fourcc(self : IvfCodec) -> Bytes {
  match self {
    Vp8 => b"VP80"
    Vp9 => b"VP90"
    Av1 => b"AV01"
  }
}

///|
pub fn IvfCodec::from_fourcc(value : Bytes) -> IvfCodec raise MediaError {
  match value {
    b"VP80" => Vp8
    b"VP90" => Vp9
    b"AV01" => Av1
    _ => raise InvalidMedia("unsupported IVF FOURCC")
  }
}

///|
pub(all) struct IvfHeader {
  codec : IvfCodec
  width : UInt16
  height : UInt16
  timebase_denominator : UInt
  timebase_numerator : UInt
  num_frames : UInt
} derive(Debug, Eq)

///|
pub fn IvfHeader::new(
  codec~ : IvfCodec,
  width~ : UInt16,
  height~ : UInt16,
  timebase_denominator~ : UInt,
  timebase_numerator~ : UInt,
  num_frames? : UInt = 0,
) -> IvfHeader raise MediaError {
  if width == 0 ||
    height == 0 ||
    timebase_denominator == 0 ||
    timebase_numerator == 0 {
    raise InvalidMedia("invalid IVF dimensions or timebase")
  }
  { codec, width, height, timebase_denominator, timebase_numerator, num_frames }
}

///|
pub fn IvfHeader::codec(self : IvfHeader) -> IvfCodec {
  self.codec
}

///|
pub fn IvfHeader::width(self : IvfHeader) -> UInt16 {
  self.width
}

///|
pub fn IvfHeader::height(self : IvfHeader) -> UInt16 {
  self.height
}

///|
pub fn IvfHeader::timebase_denominator(self : IvfHeader) -> UInt {
  self.timebase_denominator
}

///|
pub fn IvfHeader::timebase_numerator(self : IvfHeader) -> UInt {
  self.timebase_numerator
}

///|
pub fn IvfHeader::num_frames(self : IvfHeader) -> UInt {
  self.num_frames
}

///|
pub(all) struct IvfFrame {
  data : Bytes
  timestamp : UInt64
} derive(Debug, Eq)

///|
pub fn IvfFrame::new(data~ : Bytes, timestamp~ : UInt64) -> IvfFrame {
  { data, timestamp }
}

///|
pub fn IvfFrame::data(self : IvfFrame) -> Bytes {
  self.data
}

///|
pub fn IvfFrame::timestamp(self : IvfFrame) -> UInt64 {
  self.timestamp
}

///|
fn ivf_encode_header(header : IvfHeader, num_frames : UInt) -> Array[Byte] {
  let output : Array[Byte] = []
  for byte in b"DKIF" {
    output.push(byte)
  }
  media_write_u16_le(output, 0)
  media_write_u16_le(output, IVF_HEADER_SIZE.to_uint16())
  for byte in header.codec.fourcc() {
    output.push(byte)
  }
  media_write_u16_le(output, header.width)
  media_write_u16_le(output, header.height)
  media_write_u32_le(output, header.timebase_denominator)
  media_write_u32_le(output, header.timebase_numerator)
  media_write_u32_le(output, num_frames)
  media_write_u32_le(output, 0)
  output
}

///|
pub struct IvfWriter {
  header : IvfHeader
  output : Array[Byte]
  mut frame_count : UInt
  mut closed : Bool
}

///|
pub fn IvfWriter::new(header : IvfHeader) -> IvfWriter {
  {
    header,
    output: ivf_encode_header(header, 0),
    frame_count: 0,
    closed: false,
  }
}

///|
pub fn IvfWriter::write_frame(
  self : IvfWriter,
  frame : Bytes,
  timestamp : UInt64,
) -> Unit raise MediaError {
  if self.closed {
    raise InvalidMedia("cannot write an IVF frame after close")
  }
  if frame.is_empty() {
    raise InvalidMedia("cannot write an empty IVF frame")
  }
  media_write_u32_le(self.output, frame.length().reinterpret_as_uint())
  media_write_u64_le(self.output, timestamp)
  for byte in frame {
    self.output.push(byte)
  }
  self.frame_count += 1
}

///|
pub fn IvfWriter::frame_count(self : IvfWriter) -> UInt {
  self.frame_count
}

///|
pub fn IvfWriter::close(self : IvfWriter) -> Unit {
  self.closed = true
}

///|
pub fn IvfWriter::bytes(self : IvfWriter) -> Bytes {
  let output = self.output.copy()
  let count = self.frame_count
  output[24] = count.to_byte()
  output[25] = (count >> 8).to_byte()
  output[26] = (count >> 16).to_byte()
  output[27] = (count >> 24).to_byte()
  Bytes::from_array(output)
}

///|
pub struct IvfReader {
  data : Bytes
  header : IvfHeader
  mut offset : Int
  mut frame_index : UInt
}

///|
pub fn IvfReader::new(data : Bytes) -> IvfReader raise MediaError {
  if data.length() < IVF_HEADER_SIZE {
    raise InvalidMedia("IVF file is shorter than its header")
  }
  if data[0:4] != b"DKIF" {
    raise InvalidMedia("invalid IVF signature")
  }
  let version = media_read_u16_le(data, 4)
  let header_size = media_read_u16_le(data, 6)
  if version != 0 {
    raise InvalidMedia("unsupported IVF version")
  }
  if header_size < IVF_HEADER_SIZE.to_uint16() ||
    header_size.to_int() > data.length() {
    raise InvalidMedia("invalid IVF header size")
  }
  let codec = IvfCodec::from_fourcc(data[8:12].to_owned())
  let header = IvfHeader::new(
    codec~,
    width=media_read_u16_le(data, 12),
    height=media_read_u16_le(data, 14),
    timebase_denominator=media_read_u32_le(data, 16),
    timebase_numerator=media_read_u32_le(data, 20),
    num_frames=media_read_u32_le(data, 24),
  )
  { data, header, offset: header_size.to_int(), frame_index: 0 }
}

///|
pub fn IvfReader::header(self : IvfReader) -> IvfHeader {
  self.header
}

///|
pub fn IvfReader::next_frame(self : IvfReader) -> IvfFrame? raise MediaError {
  if self.offset == self.data.length() {
    return None
  }
  if self.offset + IVF_FRAME_HEADER_SIZE > self.data.length() {
    raise InvalidMedia("truncated IVF frame header")
  }
  let frame_size = media_read_u32_le(self.data, self.offset).reinterpret_as_int()
  let timestamp = media_read_u64_le(self.data, self.offset + 4)
  self.offset += IVF_FRAME_HEADER_SIZE
  if frame_size < 0 || self.offset + frame_size > self.data.length() {
    raise InvalidMedia("IVF frame size exceeds file")
  }
  let frame = self.data[self.offset:self.offset + frame_size].to_owned()
  self.offset += frame_size
  self.frame_index += 1
  Some(IvfFrame::new(data=frame, timestamp~))
}

///|
pub fn IvfReader::bytes_read(self : IvfReader) -> Int {
  self.offset
}
