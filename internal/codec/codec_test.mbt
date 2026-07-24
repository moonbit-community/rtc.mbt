///|
test "network byte order values round-trip" {
  let writer = @codec.Writer::new()
  writer.write_u8(0x12)
  writer.write_u16_be(0x3456)
  writer.write_u24_be(0x789abc)
  writer.write_u32_be(0xdef01234)
  writer.write_u64_be(0x56789abcdef01234UL)
  writer.write_bytes(b"rtc")
  let reader = @codec.Reader::new(writer.finish())
  inspect(reader.read_u8(), content="b'\\x12'")
  inspect(reader.read_u16_be(), content="13398")
  inspect(reader.read_u24_be(), content="7903932")
  inspect(reader.read_u32_be(), content="3740275252")
  inspect(reader.read_u64_be(), content="6230900220451885620")
  inspect(reader.read_bytes(3), content="b\"rtc\"")
  inspect(reader.remaining(), content="0")
}

///|
test "truncation is reported without advancing the reader" {
  let reader = @codec.Reader::new(b"\x01")
  try reader.read_u16_be() catch {
    Truncated(needed~, remaining~) => {
      inspect(needed, content="2")
      inspect(remaining, content="1")
    }
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected truncation")
  }
  inspect(reader.position(), content="0")
}

///|
test "negative lengths are rejected" {
  let reader = @codec.Reader::new(b"")
  try reader.read_bytes(-1) catch {
    InvalidLength(length) => inspect(length, content="-1")
    _ => fail("unexpected error")
  } noraise {
    _ => fail("expected invalid length")
  }
}
