///|
pub(all) suberror CodecError {
  InvalidLength(Int)
  Truncated(needed~ : Int, remaining~ : Int)
} derive(Debug, Eq)

///|
pub struct Reader {
  data : Bytes
  mut offset : Int
}

///|
pub fn Reader::new(data : Bytes) -> Reader {
  { data, offset: 0, }
}

///|
pub fn Reader::position(self : Reader) -> Int {
  self.offset
}

///|
pub fn Reader::remaining(self : Reader) -> Int {
  self.data.length() - self.offset
}

///|
fn Reader::require(self : Reader, length : Int) -> Unit raise CodecError {
  if length < 0 {
    raise InvalidLength(length)
  }
  let remaining = self.remaining()
  if remaining < length {
    raise Truncated(needed=length, remaining~)
  }
}

///|
pub fn Reader::read_u8(self : Reader) -> Byte raise CodecError {
  self.require(1)
  let result = self.data[self.offset]
  self.offset += 1
  result
}

///|
pub fn Reader::read_u16_be(self : Reader) -> UInt16 raise CodecError {
  self.require(2)
  let value = (self.data[self.offset].to_uint() << 8) |
    self.data[self.offset + 1].to_uint()
  self.offset += 2
  value.to_uint16()
}

///|
pub fn Reader::read_u24_be(self : Reader) -> UInt raise CodecError {
  self.require(3)
  let value = (self.data[self.offset].to_uint() << 16) |
    (self.data[self.offset + 1].to_uint() << 8) |
    self.data[self.offset + 2].to_uint()
  self.offset += 3
  value
}

///|
pub fn Reader::read_u32_be(self : Reader) -> UInt raise CodecError {
  self.require(4)
  let value = (self.data[self.offset].to_uint() << 24) |
    (self.data[self.offset + 1].to_uint() << 16) |
    (self.data[self.offset + 2].to_uint() << 8) |
    self.data[self.offset + 3].to_uint()
  self.offset += 4
  value
}

///|
pub fn Reader::read_u64_be(self : Reader) -> UInt64 raise CodecError {
  self.require(8)
  let value = (self.data[self.offset].to_uint64() << 56) |
    (self.data[self.offset + 1].to_uint64() << 48) |
    (self.data[self.offset + 2].to_uint64() << 40) |
    (self.data[self.offset + 3].to_uint64() << 32) |
    (self.data[self.offset + 4].to_uint64() << 24) |
    (self.data[self.offset + 5].to_uint64() << 16) |
    (self.data[self.offset + 6].to_uint64() << 8) |
    self.data[self.offset + 7].to_uint64()
  self.offset += 8
  value
}

///|
pub fn Reader::read_bytes(
  self : Reader,
  length : Int,
) -> Bytes raise CodecError {
  self.require(length)
  let end = self.offset + length
  let result = self.data[self.offset:end].to_owned()
  self.offset = end
  result
}

///|
pub fn Reader::skip(self : Reader, length : Int) -> Unit raise CodecError {
  self.require(length)
  self.offset += length
}

///|
pub struct Writer {
  bytes : Array[Byte]
}

///|
pub fn Writer::new(capacity? : Int = 0) -> Writer raise CodecError {
  if capacity < 0 {
    raise InvalidLength(capacity)
  }
  { bytes: Array(capacity~), }
}

///|
pub fn Writer::length(self : Writer) -> Int {
  self.bytes.length()
}

///|
pub fn Writer::write_u8(self : Writer, value : Byte) -> Unit {
  self.bytes.push(value)
}

///|
pub fn Writer::write_u16_be(self : Writer, value : UInt16) -> Unit {
  self.bytes.push((value >> 8).to_byte())
  self.bytes.push(value.to_byte())
}

///|
pub fn Writer::write_u24_be(self : Writer, value : UInt) -> Unit {
  self.bytes.push((value >> 16).to_byte())
  self.bytes.push((value >> 8).to_byte())
  self.bytes.push(value.to_byte())
}

///|
pub fn Writer::write_u32_be(self : Writer, value : UInt) -> Unit {
  self.bytes.push((value >> 24).to_byte())
  self.bytes.push((value >> 16).to_byte())
  self.bytes.push((value >> 8).to_byte())
  self.bytes.push(value.to_byte())
}

///|
pub fn Writer::write_u64_be(self : Writer, value : UInt64) -> Unit {
  self.bytes.push((value >> 56).to_byte())
  self.bytes.push((value >> 48).to_byte())
  self.bytes.push((value >> 40).to_byte())
  self.bytes.push((value >> 32).to_byte())
  self.bytes.push((value >> 24).to_byte())
  self.bytes.push((value >> 16).to_byte())
  self.bytes.push((value >> 8).to_byte())
  self.bytes.push(value.to_byte())
}

///|
pub fn Writer::write_bytes(self : Writer, value : Bytes) -> Unit {
  for byte in value {
    self.bytes.push(byte)
  }
}

///|
pub fn Writer::finish(self : Writer) -> Bytes {
  Bytes::from_array(self.bytes)
}
