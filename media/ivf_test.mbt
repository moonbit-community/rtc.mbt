///|
test "IVF writer and reader round-trip VP9 frames" {
  let header = IvfHeader::new(
    codec=Vp9,
    width=640,
    height=360,
    timebase_denominator=30U,
    timebase_numerator=1U,
  )
  let writer = IvfWriter::new(header)
  writer.write_frame(b"keyframe", 7UL)
  writer.write_frame(b"delta", 8UL)
  writer.close()
  writer.close()
  let wire = writer.bytes()
  assert_eq(wire[0:4], b"DKIF")
  assert_eq(wire[8:12], b"VP90")
  assert_eq(wire[24:28], b"\x02\x00\x00\x00")

  let reader = IvfReader::new(wire)
  assert_eq(reader.header().codec(), Vp9)
  assert_eq(reader.header().width(), 640)
  assert_eq(reader.header().height(), 360)
  assert_eq(reader.header().num_frames(), 2U)
  let first = reader.next_frame().unwrap()
  assert_eq(first.data(), b"keyframe")
  assert_eq(first.timestamp(), 7UL)
  let second = reader.next_frame().unwrap()
  assert_eq(second.data(), b"delta")
  assert_eq(second.timestamp(), 8UL)
  assert_eq(reader.next_frame(), None)
  assert_eq(reader.bytes_read(), wire.length())
}

///|
test "IVF reader rejects bad signatures and truncated frames" {
  let malformed = [
    b"",
    b"NOPE\x00\x00\x20\x00VP80\x01\x00\x01\x00\x01\x00\x00\x00" +
    b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
  ]
  for wire in malformed {
    ignore(IvfReader::new(wire)) catch {
      InvalidMedia(_) => continue
      _ => fail("unexpected IVF error")
    }
    fail("malformed IVF header was accepted")
  }

  let writer = IvfWriter::new(
    IvfHeader::new(
      codec=Vp8,
      width=1,
      height=1,
      timebase_denominator=1U,
      timebase_numerator=1U,
    ),
  )
  writer.write_frame(b"abc", 0UL)
  let truncated = writer.bytes()[0:writer.bytes().length() - 1].to_owned()
  let reader = IvfReader::new(truncated)
  ignore(reader.next_frame()) catch {
    InvalidMedia(_) => return
    _ => fail("unexpected IVF frame error")
  }
  fail("truncated IVF frame was accepted")
}
