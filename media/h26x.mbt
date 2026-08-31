///|
pub(all) enum H26xCodec {
  Avc
  Hevc
} derive(Debug, Eq)

///|
fn h26x_payload_codec(codec : H26xCodec) -> @rtp.PayloadCodec {
  match codec {
    Avc => H264
    Hevc => H265
  }
}

///|
fn h26x_annexb_ranges(data : Bytes) -> Array[(Int, Int)] {
  let starts : Array[(Int, Int)] = []
  let mut offset = 0
  while offset + 2 < data.length() {
    if offset + 3 < data.length() &&
      data[offset] == 0 &&
      data[offset + 1] == 0 &&
      data[offset + 2] == 0 &&
      data[offset + 3] == 1 {
      starts.push((offset, 4))
      offset += 4
    } else if data[offset] == 0 &&
      data[offset + 1] == 0 &&
      data[offset + 2] == 1 {
      starts.push((offset, 3))
      offset += 3
    } else {
      offset += 1
    }
  }
  let ranges : Array[(Int, Int)] = []
  if starts.is_empty() {
    if !data.is_empty() {
      ranges.push((0, data.length()))
    }
    return ranges
  }
  for index = 0; index < starts.length(); index = index + 1 {
    let (start, prefix) = starts[index]
    let payload_start = start + prefix
    let end = if index + 1 < starts.length() {
      starts[index + 1].0
    } else {
      data.length()
    }
    if payload_start < end {
      ranges.push((payload_start, end))
    }
  }
  ranges
}

///|
pub(all) struct H26xNal {
  codec : H26xCodec
  unit_type : Byte
  forbidden_zero_bit : Bool
  layer_id : Byte
  temporal_id_plus_one : Byte
  data : Bytes
} derive(Debug, Eq)

///|
fn h26x_nal(codec : H26xCodec, data : Bytes) -> H26xNal raise MediaError {
  match codec {
    Avc => {
      if data.is_empty() {
        raise InvalidMedia("empty H264 NAL unit")
      }
      {
        codec,
        unit_type: data[0] & 0x1f,
        forbidden_zero_bit: (data[0] & 0x80) != 0,
        layer_id: 0,
        temporal_id_plus_one: 0,
        data,
      }
    }
    Hevc => {
      if data.length() < 2 {
        raise InvalidMedia("H265 NAL unit is shorter than its header")
      }
      {
        codec,
        unit_type: (data[0] >> 1) & 0x3f,
        forbidden_zero_bit: (data[0] & 0x80) != 0,
        layer_id: ((data[0] & 1) << 5) | (data[1] >> 3),
        temporal_id_plus_one: data[1] & 0x07,
        data,
      }
    }
  }
}

///|
pub fn H26xNal::codec(self : H26xNal) -> H26xCodec {
  self.codec
}

///|
pub fn H26xNal::unit_type(self : H26xNal) -> Byte {
  self.unit_type
}

///|
pub fn H26xNal::forbidden_zero_bit(self : H26xNal) -> Bool {
  self.forbidden_zero_bit
}

///|
pub fn H26xNal::layer_id(self : H26xNal) -> Byte {
  self.layer_id
}

///|
pub fn H26xNal::temporal_id_plus_one(self : H26xNal) -> Byte {
  self.temporal_id_plus_one
}

///|
pub fn H26xNal::data(self : H26xNal) -> Bytes {
  self.data
}

///|
pub struct H26xReader {
  codec : H26xCodec
  data : Bytes
  ranges : Array[(Int, Int)]
  mut index : Int
}

///|
pub fn H26xReader::new(
  codec~ : H26xCodec,
  data~ : Bytes,
) -> H26xReader raise MediaError {
  if data.is_empty() {
    raise InvalidMedia("H26x stream is empty")
  }
  let ranges = h26x_annexb_ranges(data)
  if ranges.is_empty() {
    raise InvalidMedia("H26x stream contains no NAL units")
  }
  { codec, data, ranges, index: 0, }
}

///|
pub fn H26xReader::next_nal(self : H26xReader) -> H26xNal? raise MediaError {
  if self.index >= self.ranges.length() {
    return None
  }
  let (start, end) = self.ranges[self.index]
  self.index += 1
  Some(h26x_nal(self.codec, self.data[start:end].to_owned()))
}

///|
pub fn H26xReader::reset(self : H26xReader) -> Unit {
  self.index = 0
}

///|
pub struct H26xWriter {
  codec : H26xCodec
  output : Array[Byte]
  pending_payloads : Array[Bytes]
  mut pending_timestamp : UInt?
  mut closed : Bool
  mut dropped_incomplete_samples : UInt
}

///|
pub fn H26xWriter::new(codec : H26xCodec) -> H26xWriter {
  {
    codec,
    output: [],
    pending_payloads: [],
    pending_timestamp: None,
    closed: false,
    dropped_incomplete_samples: 0,
  }
}

///|
fn H26xWriter::append_access_unit(
  self : H26xWriter,
  payloads : Array[Bytes],
) -> Unit raise MediaError {
  let data = @rtp.depacketize_payload(h26x_payload_codec(self.codec), payloads) catch {
    _ => raise InvalidMedia("invalid H26x RTP access unit")
  }
  for byte in data {
    self.output.push(byte)
  }
}

///|
pub fn H26xWriter::write_payloads(
  self : H26xWriter,
  payloads : Array[Bytes],
) -> Unit raise MediaError {
  if self.closed {
    raise InvalidMedia("cannot write H26x data after close")
  }
  if payloads.is_empty() {
    raise InvalidMedia("H26x access unit has no RTP payloads")
  }
  self.append_access_unit(payloads)
}

///|
pub fn H26xWriter::write_rtp(
  self : H26xWriter,
  packet : @rtp.Packet,
) -> Unit raise MediaError {
  if self.closed {
    raise InvalidMedia("cannot write H26x data after close")
  }
  if packet.payload().is_empty() {
    return
  }
  match self.pending_timestamp {
    Some(timestamp) if timestamp != packet.timestamp() => {
      if !self.pending_payloads.is_empty() {
        self.pending_payloads.clear()
        self.dropped_incomplete_samples += 1
      }
      self.pending_timestamp = Some(packet.timestamp())
    }
    None => self.pending_timestamp = Some(packet.timestamp())
    _ => ()
  }
  self.pending_payloads.push(packet.payload())
  if packet.marker() {
    self.append_access_unit(self.pending_payloads.copy())
    self.pending_payloads.clear()
    self.pending_timestamp = None
  }
}

///|
pub fn H26xWriter::write_sample(
  self : H26xWriter,
  sample : Sample,
) -> Unit raise MediaError {
  if self.closed {
    raise InvalidMedia("cannot write H26x data after close")
  }
  let reader = H26xReader::new(codec=self.codec, data=sample.data())
  let mut count = 0
  while true {
    match reader.next_nal() {
      None => break
      Some(nalu) => {
        for byte in b"\x00\x00\x00\x01" {
          self.output.push(byte)
        }
        for byte in nalu.data() {
          self.output.push(byte)
        }
        count += 1
      }
    }
  }
  if count == 0 {
    raise InvalidMedia("H26x sample contains no NAL units")
  }
}

///|
pub fn H26xWriter::dropped_incomplete_samples(self : H26xWriter) -> UInt {
  self.dropped_incomplete_samples
}

///|
pub fn H26xWriter::bytes(self : H26xWriter) -> Bytes {
  Bytes::from_array(self.output)
}

///|
pub fn H26xWriter::close(self : H26xWriter) -> Unit {
  if self.closed {
    return
  }
  if !self.pending_payloads.is_empty() {
    self.pending_payloads.clear()
    self.dropped_incomplete_samples += 1
  }
  self.pending_timestamp = None
  self.closed = true
}
