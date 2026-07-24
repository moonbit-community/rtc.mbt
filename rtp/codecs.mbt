///|
pub(all) enum PayloadCodec {
  Opus
  G711
  G722
  Vp8
  Vp9
  H264
  H265
  Av1
} derive(Debug, Eq)

///|
fn codec_bytes(parts : Array[Bytes]) -> Bytes {
  let output : Array[Byte] = []
  for part in parts {
    for byte in part {
      output.push(byte)
    }
  }
  Bytes::from_array(output)
}

///|
fn codec_chunk(payload : Bytes, size : Int) -> Array[Bytes] {
  let chunks : Array[Bytes] = []
  if size <= 0 {
    return chunks
  }
  let mut offset = 0
  while offset < payload.length() {
    let length = Int::min(size, payload.length() - offset)
    chunks.push(payload[offset:offset + length].to_owned())
    offset += length
  }
  chunks
}

///|
fn annexb_units(payload : Bytes) -> Array[Bytes] {
  let starts : Array[(Int, Int)] = []
  let mut offset = 0
  while offset + 2 < payload.length() {
    if offset + 3 < payload.length() &&
      payload[offset] == 0 &&
      payload[offset + 1] == 0 &&
      payload[offset + 2] == 0 &&
      payload[offset + 3] == 1 {
      starts.push((offset, 4))
      offset += 4
    } else if payload[offset] == 0 &&
      payload[offset + 1] == 0 &&
      payload[offset + 2] == 1 {
      starts.push((offset, 3))
      offset += 3
    } else {
      offset += 1
    }
  }
  if starts.is_empty() {
    return if payload.is_empty() { [] } else { [payload] }
  }
  let units : Array[Bytes] = []
  for index = 0; index < starts.length(); index = index + 1 {
    let (start, prefix_length) = starts[index]
    let end = if index + 1 < starts.length() {
      starts[index + 1].0
    } else {
      payload.length()
    }
    let data_start = start + prefix_length
    if data_start < end {
      units.push(payload[data_start:end].to_owned())
    }
  }
  units
}

///|
fn h264_emit(
  nalu : Bytes,
  mtu : Int,
  output : Array[Bytes],
) -> Unit raise RtpError {
  if nalu.is_empty() {
    return
  }
  let nalu_type = nalu[0] & 0x1f
  if nalu_type == 9 || nalu_type == 12 {
    return
  }
  if nalu.length() <= mtu {
    output.push(nalu)
    return
  }
  if mtu <= 2 || nalu.length() <= 1 {
    raise PayloadTooLarge(nalu.length())
  }
  let fragment_size = mtu - 2
  let indicator = (nalu[0] & 0xe0) | 28
  let mut offset = 1
  while offset < nalu.length() {
    let length = Int::min(fragment_size, nalu.length() - offset)
    let bytes : Array[Byte] = [indicator]
    let mut header = nalu_type
    if offset == 1 {
      header = header | 0x80
    }
    if offset + length == nalu.length() {
      header = header | 0x40
    }
    bytes.push(header)
    for byte in nalu[offset:offset + length] {
      bytes.push(byte)
    }
    output.push(Bytes::from_array(bytes))
    offset += length
  }
}

///|
fn h264_packetize(
  payload : Bytes,
  mtu : Int,
  previous_sps : Bytes?,
  previous_pps : Bytes?,
) -> (Array[Bytes], Bytes?, Bytes?) raise RtpError {
  let output : Array[Bytes] = []
  let mut sps = previous_sps
  let mut pps = previous_pps
  for nalu in annexb_units(payload) {
    if nalu.is_empty() {
      continue
    }
    let nalu_type = nalu[0] & 0x1f
    if nalu_type == 7 {
      sps = Some(nalu)
      continue
    }
    if nalu_type == 8 {
      pps = Some(nalu)
      continue
    }
    match (sps, pps) {
      (Some(saved_sps), Some(saved_pps)) => {
        let stap : Array[Byte] = [0x78]
        stap.push((saved_sps.length() >> 8).to_byte())
        stap.push(saved_sps.length().to_byte())
        for byte in saved_sps {
          stap.push(byte)
        }
        stap.push((saved_pps.length() >> 8).to_byte())
        stap.push(saved_pps.length().to_byte())
        for byte in saved_pps {
          stap.push(byte)
        }
        if stap.length() <= mtu {
          output.push(Bytes::from_array(stap))
        }
        sps = None
        pps = None
      }
      _ => ()
    }
    h264_emit(nalu, mtu, output)
  }
  (output, sps, pps)
}

///|
fn vp8_packetize(
  payload : Bytes,
  mtu : Int,
  picture_id : UInt16,
  include_picture_id : Bool,
) -> Array[Bytes] raise RtpError {
  if payload.is_empty() {
    return []
  }
  let header_size = if !include_picture_id {
    1
  } else if picture_id < 128 {
    3
  } else {
    4
  }
  if mtu <= header_size {
    raise PayloadTooLarge(payload.length())
  }
  let output : Array[Bytes] = []
  let mut offset = 0
  while offset < payload.length() {
    let length = Int::min(mtu - header_size, payload.length() - offset)
    let bytes : Array[Byte] = []
    let mut descriptor : Byte = if offset == 0 { 0x10 } else { 0 }
    if include_picture_id {
      descriptor = descriptor | 0x80
    }
    bytes.push(descriptor)
    if include_picture_id {
      bytes.push(0x80)
      if picture_id < 128 {
        bytes.push(picture_id.to_byte())
      } else {
        bytes.push(0x80 | ((picture_id >> 8).to_byte() & 0x7f))
        bytes.push(picture_id.to_byte())
      }
    }
    for byte in payload[offset:offset + length] {
      bytes.push(byte)
    }
    output.push(Bytes::from_array(bytes))
    offset += length
  }
  output
}

///|
fn vp8_payload_offset(payload : Bytes) -> Int raise RtpError {
  if payload.length() < 2 {
    raise InvalidPacket("truncated VP8 payload descriptor")
  }
  let descriptor = payload[0]
  let mut offset = 1
  if (descriptor & 0x80) != 0 {
    if offset >= payload.length() {
      raise InvalidPacket("truncated VP8 extension descriptor")
    }
    let extensions = payload[offset]
    offset += 1
    if (extensions & 0x80) != 0 {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP8 picture id")
      }
      let picture_id = payload[offset]
      offset += 1
      if (picture_id & 0x80) != 0 {
        if offset >= payload.length() {
          raise InvalidPacket("truncated extended VP8 picture id")
        }
        offset += 1
      }
    }
    if (extensions & 0x40) != 0 {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP8 TL0PICIDX")
      }
      offset += 1
    }
    if (extensions & 0x30) != 0 {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP8 temporal or key index")
      }
      offset += 1
    }
  }
  if offset >= payload.length() {
    raise InvalidPacket("VP8 payload descriptor has no media payload")
  }
  offset
}

///|
fn vp9_packetize(
  payload : Bytes,
  mtu : Int,
  picture_id : UInt16,
) -> Array[Bytes] raise RtpError {
  if payload.is_empty() {
    return []
  }
  if mtu <= 3 {
    raise PayloadTooLarge(payload.length())
  }
  let output : Array[Bytes] = []
  let mut offset = 0
  while offset < payload.length() {
    let length = Int::min(mtu - 3, payload.length() - offset)
    let mut descriptor : Byte = 0x90
    if offset == 0 {
      descriptor = descriptor | 0x08
    }
    if offset + length == payload.length() {
      descriptor = descriptor | 0x04
    }
    let bytes : Array[Byte] = [
      descriptor,
      0x80 | ((picture_id >> 8).to_byte() & 0x7f),
      picture_id.to_byte(),
    ]
    for byte in payload[offset:offset + length] {
      bytes.push(byte)
    }
    output.push(Bytes::from_array(bytes))
    offset += length
  }
  output
}

///|
fn vp9_payload_offset(payload : Bytes) -> Int raise RtpError {
  if payload.length() < 2 {
    raise InvalidPacket("truncated VP9 payload descriptor")
  }
  let descriptor = payload[0]
  let has_picture_id = (descriptor & 0x80) != 0
  let predicted = (descriptor & 0x40) != 0
  let has_layer = (descriptor & 0x20) != 0
  let flexible = (descriptor & 0x10) != 0
  let has_scalability = (descriptor & 0x02) != 0
  let mut offset = 1
  if has_picture_id {
    if offset >= payload.length() {
      raise InvalidPacket("truncated VP9 picture id")
    }
    let first = payload[offset]
    offset += 1
    if (first & 0x80) != 0 {
      if offset >= payload.length() {
        raise InvalidPacket("truncated extended VP9 picture id")
      }
      offset += 1
    }
  }
  if has_layer {
    if offset >= payload.length() {
      raise InvalidPacket("truncated VP9 layer indices")
    }
    let layer = payload[offset]
    if ((layer >> 1) & 0x07) >= 5 {
      raise InvalidPacket("VP9 payload has too many spatial layers")
    }
    offset += 1
    if !flexible {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP9 TL0PICIDX")
      }
      offset += 1
    }
  }
  if flexible && predicted {
    let mut references = 0
    let mut more = true
    while more {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP9 reference indices")
      }
      more = (payload[offset] & 1) != 0
      offset += 1
      references += 1
      if references > 3 {
        raise InvalidPacket("VP9 payload has too many reference indices")
      }
    }
  }
  if has_scalability {
    if offset >= payload.length() {
      raise InvalidPacket("truncated VP9 scalability structure")
    }
    let scalability = payload[offset]
    offset += 1
    let layers = ((scalability >> 5) & 0x07).to_int() + 1
    if layers > 5 {
      raise InvalidPacket("VP9 payload has too many spatial layers")
    }
    if (scalability & 0x10) != 0 {
      let dimensions = layers * 4
      if offset + dimensions > payload.length() {
        raise InvalidPacket("truncated VP9 spatial dimensions")
      }
      offset += dimensions
    }
    if (scalability & 0x08) != 0 {
      if offset >= payload.length() {
        raise InvalidPacket("truncated VP9 picture group")
      }
      let groups = payload[offset].to_int()
      offset += 1
      for group_index = 0; group_index < groups; group_index = group_index + 1 {
        if offset >= payload.length() {
          raise InvalidPacket("truncated VP9 picture group descriptor")
        }
        let references = (payload[offset] & 0x03).to_int()
        offset += 1
        if offset + references > payload.length() {
          raise InvalidPacket("truncated VP9 picture group references")
        }
        offset += references
      }
    }
  }
  if offset >= payload.length() {
    raise InvalidPacket("VP9 payload descriptor has no media payload")
  }
  offset
}

///|
fn h265_emit(
  nalu : Bytes,
  mtu : Int,
  output : Array[Bytes],
) -> Unit raise RtpError {
  if nalu.length() < 2 {
    raise InvalidPacket("H265 NAL unit is shorter than its header")
  }
  let nalu_type = (nalu[0] >> 1) & 0x3f
  if nalu_type >= 48 {
    raise InvalidPacket("H265 input contains a packetization NAL unit")
  }
  if nalu.length() <= mtu {
    output.push(nalu)
    return
  }
  if mtu <= 3 {
    raise PayloadTooLarge(nalu.length())
  }
  let fragment_size = mtu - 3
  let indicator0 = (nalu[0] & 0x81) | 0x62
  let indicator1 = nalu[1]
  let mut offset = 2
  while offset < nalu.length() {
    let length = Int::min(fragment_size, nalu.length() - offset)
    let mut fu_header = nalu_type
    if offset == 2 {
      fu_header = fu_header | 0x80
    }
    if offset + length == nalu.length() {
      fu_header = fu_header | 0x40
    }
    let bytes : Array[Byte] = [indicator0, indicator1, fu_header]
    for byte in nalu[offset:offset + length] {
      bytes.push(byte)
    }
    output.push(Bytes::from_array(bytes))
    offset += length
  }
}

///|
fn h265_packetize(payload : Bytes, mtu : Int) -> Array[Bytes] raise RtpError {
  let units = annexb_units(payload)
  let output : Array[Bytes] = []
  let aggregation : Array[Bytes] = []
  let mut aggregation_size = 2
  fn flush(aggregation : Array[Bytes], output : Array[Bytes]) -> Int {
    if aggregation.length() == 1 {
      output.push(aggregation[0])
    } else if aggregation.length() > 1 {
      let first = aggregation[0]
      let bytes : Array[Byte] = [(first[0] & 0x81) | 0x60, first[1]]
      for nalu in aggregation {
        bytes.push((nalu.length() >> 8).to_byte())
        bytes.push(nalu.length().to_byte())
        for byte in nalu {
          bytes.push(byte)
        }
      }
      output.push(Bytes::from_array(bytes))
    }
    aggregation.clear()
    2
  }
  for nalu in units {
    if nalu.length() < 2 {
      continue
    }
    if nalu.length() > mtu {
      aggregation_size = flush(aggregation, output)
      h265_emit(nalu, mtu, output)
    } else {
      let projected = aggregation_size + 2 + nalu.length()
      if !aggregation.is_empty() && projected > mtu {
        aggregation_size = flush(aggregation, output)
      }
      aggregation.push(nalu)
      aggregation_size += 2 + nalu.length()
    }
  }
  ignore(flush(aggregation, output))
  output
}

///|
fn leb128_write(output : Array[Byte], value : Int) -> Unit {
  let mut remaining = value
  while true {
    let mut byte = (remaining & 0x7f).to_byte()
    remaining = remaining >> 7
    if remaining != 0 {
      byte = byte | 0x80
    }
    output.push(byte)
    if remaining == 0 {
      break
    }
  }
}

///|
fn leb128_read(data : Bytes, start : Int) -> (Int, Int) raise RtpError {
  let mut value = 0
  let mut shift = 0
  let mut offset = start
  while offset < data.length() && shift <= 28 {
    let byte = data[offset]
    value = value | ((byte & 0x7f).to_int() << shift)
    offset += 1
    if (byte & 0x80) == 0 {
      return (value, offset - start)
    }
    shift += 7
  }
  raise InvalidPacket("invalid or truncated LEB128 value")
}

///|
fn av1_obus(payload : Bytes) -> Array[Bytes] raise RtpError {
  let output : Array[Bytes] = []
  let mut offset = 0
  while offset < payload.length() {
    let header = payload[offset]
    if (header & 0x80) != 0 {
      raise InvalidPacket("AV1 OBU forbidden bit is set")
    }
    let extension = (header & 0x04) != 0
    let has_size = (header & 0x02) != 0
    let header_size = if extension { 2 } else { 1 }
    if offset + header_size > payload.length() {
      raise InvalidPacket("truncated AV1 OBU header")
    }
    if !has_size {
      output.push(payload[offset:].to_owned())
      break
    }
    let (size, size_length) = leb128_read(payload, offset + header_size)
    let body_start = offset + header_size + size_length
    if body_start + size > payload.length() {
      raise InvalidPacket("AV1 OBU size exceeds payload")
    }
    let bytes : Array[Byte] = [header & 0xfd]
    if extension {
      bytes.push(payload[offset + 1])
    }
    for byte in payload[body_start:body_start + size] {
      bytes.push(byte)
    }
    output.push(Bytes::from_array(bytes))
    offset = body_start + size
  }
  output
}

///|
fn av1_packetize(payload : Bytes, mtu : Int) -> Array[Bytes] raise RtpError {
  if mtu <= 1 {
    raise PayloadTooLarge(payload.length())
  }
  let output : Array[Bytes] = []
  for obu in av1_obus(payload) {
    if obu.is_empty() {
      continue
    }
    let chunks = codec_chunk(obu, mtu - 1)
    for index = 0; index < chunks.length(); index = index + 1 {
      let first = index == 0
      let last = index + 1 == chunks.length()
      let mut aggregation_header : Byte = 0x10
      if !first {
        aggregation_header = aggregation_header | 0x80
      }
      if !last {
        aggregation_header = aggregation_header | 0x40
      }
      if first && ((obu[0] >> 3) & 0x0f) == 1 {
        aggregation_header = aggregation_header | 0x08
      }
      let bytes : Array[Byte] = [aggregation_header]
      for byte in chunks[index] {
        bytes.push(byte)
      }
      output.push(Bytes::from_array(bytes))
    }
  }
  output
}

///|
fn av1_finalize_obu(obu : Bytes, output : Array[Byte]) -> Unit raise RtpError {
  if obu.is_empty() {
    return
  }
  let header = obu[0]
  let obu_type = (header >> 3) & 0x0f
  if obu_type == 2 || obu_type == 8 {
    return
  }
  let extension = (header & 0x04) != 0
  let header_size = if extension { 2 } else { 1 }
  if obu.length() < header_size {
    raise InvalidPacket("truncated AV1 OBU extension")
  }
  if (header & 0x02) != 0 {
    for byte in obu {
      output.push(byte)
    }
    return
  }
  output.push(header | 0x02)
  if extension {
    output.push(obu[1])
  }
  leb128_write(output, obu.length() - header_size)
  for byte in obu[header_size:] {
    output.push(byte)
  }
}

///|
fn av1_depacketize(payloads : Array[Bytes]) -> Bytes raise RtpError {
  let output : Array[Byte] = []
  let continuation : Array[Byte] = []
  for payload in payloads {
    if payload.length() <= 1 {
      raise InvalidPacket("truncated AV1 RTP payload")
    }
    let header = payload[0]
    let z = (header & 0x80) != 0
    let y = (header & 0x40) != 0
    let count = ((header >> 4) & 0x03).to_int()
    if (header & 0x07) != 0 {
      raise InvalidPacket("AV1 aggregation header reserved bits are set")
    }
    if !z && !continuation.is_empty() {
      continuation.clear()
    }
    let elements : Array[Bytes] = []
    let mut offset = 1
    let mut element_index = 0
    while offset < payload.length() {
      let is_last_declared = count != 0 && element_index + 1 == count
      let length = if is_last_declared {
        payload.length() - offset
      } else {
        let (value, encoded) = leb128_read(payload, offset)
        offset += encoded
        value
      }
      if length < 0 || offset + length > payload.length() {
        raise InvalidPacket("AV1 OBU element exceeds RTP payload")
      }
      elements.push(payload[offset:offset + length].to_owned())
      offset += length
      element_index += 1
      if is_last_declared {
        break
      }
    }
    if count != 0 && elements.length() != count {
      raise InvalidPacket("AV1 aggregation OBU count does not match payload")
    }
    for index = 0; index < elements.length(); index = index + 1 {
      let first = index == 0
      let last = index + 1 == elements.length()
      let element = elements[index]
      if first && z {
        if continuation.is_empty() {
          continue
        }
        for byte in element {
          continuation.push(byte)
        }
        if last && y {
          continue
        }
        av1_finalize_obu(Bytes::from_array(continuation), output)
        continuation.clear()
      } else if last && y {
        continuation.clear()
        for byte in element {
          continuation.push(byte)
        }
      } else {
        av1_finalize_obu(element, output)
      }
    }
  }
  Bytes::from_array(output)
}

///|
pub fn packetize_payload(
  codec : PayloadCodec,
  payload : Bytes,
  mtu : Int,
) -> Array[Bytes] raise RtpError {
  if mtu <= 0 {
    raise InvalidPacket("RTP payload MTU must be positive")
  }
  if payload.is_empty() {
    return []
  }
  match codec {
    Opus => [payload]
    G711 | G722 => codec_chunk(payload, mtu)
    Vp8 => vp8_packetize(payload, mtu, 0, false)
    Vp9 => vp9_packetize(payload, mtu, 0)
    H264 => {
      let (output, _, _) = h264_packetize(payload, mtu, None, None)
      output
    }
    H265 => h265_packetize(payload, mtu)
    Av1 => av1_packetize(payload, mtu)
  }
}

///|
pub fn PayloadCodec::is_partition_head(
  self : PayloadCodec,
  payload : Bytes,
) -> Bool {
  if payload.is_empty() {
    return false
  }
  match self {
    Opus | G711 | G722 => true
    Vp8 => (payload[0] & 0x10) != 0
    Vp9 => (payload[0] & 0x08) != 0
    H264 =>
      if (payload[0] & 0x1f) == 28 && payload.length() >= 2 {
        (payload[1] & 0x80) != 0
      } else {
        true
      }
    H265 =>
      if ((payload[0] >> 1) & 0x3f) == 49 && payload.length() >= 3 {
        (payload[2] & 0x80) != 0
      } else {
        true
      }
    Av1 => (payload[0] & 0x80) == 0
  }
}

///|
pub fn PayloadCodec::is_partition_tail(
  self : PayloadCodec,
  marker : Bool,
  payload : Bytes,
) -> Bool {
  match self {
    Opus | G711 | G722 => true
    H264 =>
      if payload.length() >= 2 && (payload[0] & 0x1f) == 28 {
        (payload[1] & 0x40) != 0
      } else {
        marker
      }
    H265 =>
      if payload.length() >= 3 && ((payload[0] >> 1) & 0x3f) == 49 {
        (payload[2] & 0x40) != 0
      } else {
        marker
      }
    Vp8 | Vp9 | Av1 => marker
  }
}

///|
pub fn depacketize_payload(
  codec : PayloadCodec,
  payloads : Array[Bytes],
) -> Bytes raise RtpError {
  if payloads.is_empty() {
    raise InvalidPacket("cannot depacketize an empty payload list")
  }
  match codec {
    Opus => {
      if payloads.length() != 1 || payloads[0].is_empty() {
        raise InvalidPacket(
          "an Opus sample must contain exactly one RTP payload",
        )
      }
      payloads[0]
    }
    G711 | G722 => codec_bytes(payloads)
    Vp8 => {
      let output : Array[Byte] = []
      for payload in payloads {
        let offset = vp8_payload_offset(payload)
        for byte in payload[offset:] {
          output.push(byte)
        }
      }
      Bytes::from_array(output)
    }
    Vp9 => {
      let output : Array[Byte] = []
      for payload in payloads {
        let offset = vp9_payload_offset(payload)
        for byte in payload[offset:] {
          output.push(byte)
        }
      }
      Bytes::from_array(output)
    }
    H264 => {
      let output : Array[Byte] = []
      let fragmented : Array[Byte] = []
      let mut fragment_active = false
      for payload in payloads {
        if payload.length() <= 1 {
          raise InvalidPacket("truncated H264 RTP payload")
        }
        let nalu_type = payload[0] & 0x1f
        if nalu_type >= 1 && nalu_type <= 23 {
          if fragment_active {
            raise InvalidPacket("H264 FU-A sequence is interrupted")
          }
          for byte in b"\x00\x00\x00\x01" {
            output.push(byte)
          }
          for byte in payload {
            output.push(byte)
          }
        } else if nalu_type == 24 {
          if fragment_active {
            raise InvalidPacket("H264 FU-A sequence is interrupted")
          }
          let mut offset = 1
          while offset < payload.length() {
            if offset + 2 > payload.length() {
              raise InvalidPacket("truncated H264 STAP-A length")
            }
            let length = (payload[offset].to_int() << 8) |
              payload[offset + 1].to_int()
            offset += 2
            if length == 0 || offset + length > payload.length() {
              raise InvalidPacket("invalid H264 STAP-A NAL length")
            }
            for byte in b"\x00\x00\x00\x01" {
              output.push(byte)
            }
            for byte in payload[offset:offset + length] {
              output.push(byte)
            }
            offset += length
          }
        } else if nalu_type == 28 {
          let fu_header = payload[1]
          let start = (fu_header & 0x80) != 0
          let end = (fu_header & 0x40) != 0
          if start {
            if fragment_active {
              raise InvalidPacket("overlapping H264 FU-A sequences")
            }
            fragment_active = true
            fragmented.clear()
            fragmented.push((payload[0] & 0xe0) | (fu_header & 0x1f))
          } else if !fragment_active {
            raise InvalidPacket("H264 FU-A continuation has no start")
          }
          for byte in payload[2:] {
            fragmented.push(byte)
          }
          if end {
            if !fragment_active {
              raise InvalidPacket("H264 FU-A end has no start")
            }
            for byte in b"\x00\x00\x00\x01" {
              output.push(byte)
            }
            for byte in fragmented {
              output.push(byte)
            }
            fragmented.clear()
            fragment_active = false
          }
        } else {
          raise InvalidPacket("unsupported H264 packetization mode")
        }
      }
      if fragment_active {
        raise InvalidPacket("incomplete H264 FU-A sequence")
      }
      Bytes::from_array(output)
    }
    H265 => {
      let output : Array[Byte] = []
      let fragmented : Array[Byte] = []
      let mut fragment_active = false
      for payload in payloads {
        if payload.length() < 2 {
          raise InvalidPacket("truncated H265 RTP payload")
        }
        if (payload[0] & 0x80) != 0 {
          raise InvalidPacket("H265 forbidden bit is set")
        }
        let nalu_type = (payload[0] >> 1) & 0x3f
        if nalu_type < 48 {
          if fragment_active {
            raise InvalidPacket("H265 FU sequence is interrupted")
          }
          for byte in b"\x00\x00\x00\x01" {
            output.push(byte)
          }
          for byte in payload {
            output.push(byte)
          }
        } else if nalu_type == 48 {
          if fragment_active {
            raise InvalidPacket("H265 FU sequence is interrupted")
          }
          let mut offset = 2
          while offset < payload.length() {
            if offset + 2 > payload.length() {
              raise InvalidPacket("truncated H265 aggregation length")
            }
            let length = (payload[offset].to_int() << 8) |
              payload[offset + 1].to_int()
            offset += 2
            if length < 2 || offset + length > payload.length() {
              raise InvalidPacket("invalid H265 aggregation NAL length")
            }
            for byte in b"\x00\x00\x00\x01" {
              output.push(byte)
            }
            for byte in payload[offset:offset + length] {
              output.push(byte)
            }
            offset += length
          }
        } else if nalu_type == 49 {
          if payload.length() < 4 {
            raise InvalidPacket("truncated H265 fragmentation unit")
          }
          let fu_header = payload[2]
          let start = (fu_header & 0x80) != 0
          let end = (fu_header & 0x40) != 0
          if start {
            if fragment_active {
              raise InvalidPacket("overlapping H265 FU sequences")
            }
            fragment_active = true
            fragmented.clear()
            fragmented.push((payload[0] & 0x81) | ((fu_header & 0x3f) << 1))
            fragmented.push(payload[1])
          } else if !fragment_active {
            raise InvalidPacket("H265 FU continuation has no start")
          }
          for byte in payload[3:] {
            fragmented.push(byte)
          }
          if end {
            for byte in b"\x00\x00\x00\x01" {
              output.push(byte)
            }
            for byte in fragmented {
              output.push(byte)
            }
            fragmented.clear()
            fragment_active = false
          }
        } else {
          raise InvalidPacket("unsupported H265 packetization mode")
        }
      }
      if fragment_active {
        raise InvalidPacket("incomplete H265 FU sequence")
      }
      Bytes::from_array(output)
    }
    Av1 => av1_depacketize(payloads)
  }
}

///|
pub struct Packetizer {
  mtu : Int
  payload_type : Byte
  ssrc : UInt
  clock_rate : UInt
  codec : PayloadCodec
  include_vp8_picture_id : Bool
  mut sequence_number : UInt16
  mut timestamp : UInt
  mut picture_id : UInt16
  mut h264_sps : Bytes?
  mut h264_pps : Bytes?
}

///|
pub fn Packetizer::new(
  mtu~ : Int,
  payload_type~ : Byte,
  ssrc~ : UInt,
  clock_rate~ : UInt,
  codec~ : PayloadCodec,
  sequence_number? : UInt16 = 0,
  timestamp? : UInt = 0,
  picture_id? : UInt16 = 0,
  include_vp8_picture_id? : Bool = false,
) -> Packetizer raise RtpError {
  if mtu <= RTP_FIXED_HEADER_LENGTH {
    raise InvalidPacket("RTP packetizer MTU is too small")
  }
  if payload_type > 127 {
    raise InvalidPacket("RTP payload type must fit in seven bits")
  }
  if clock_rate == 0 {
    raise InvalidPacket("RTP clock rate must be positive")
  }
  {
    mtu,
    payload_type,
    ssrc,
    clock_rate,
    codec,
    include_vp8_picture_id,
    sequence_number,
    timestamp,
    picture_id: picture_id & 0x7fff,
    h264_sps: None,
    h264_pps: None,
  }
}

///|
pub fn Packetizer::sequence_number(self : Packetizer) -> UInt16 {
  self.sequence_number
}

///|
pub fn Packetizer::timestamp(self : Packetizer) -> UInt {
  self.timestamp
}

///|
pub fn Packetizer::clock_rate(self : Packetizer) -> UInt {
  self.clock_rate
}

///|
pub fn Packetizer::skip_samples(
  self : Packetizer,
  skipped_samples : UInt,
) -> Unit {
  self.timestamp = self.timestamp + skipped_samples
}

///|
pub fn Packetizer::packetize(
  self : Packetizer,
  payload : Bytes,
  samples : UInt,
  extensions? : Array[HeaderExtension] = [],
) -> Array[Packet] raise RtpError {
  let probe = Packet::new(
    payload_type=self.payload_type,
    sequence_number=self.sequence_number,
    timestamp=self.timestamp,
    ssrc=self.ssrc,
    extensions~,
    payload=b"",
  )
  let payload_mtu = self.mtu - probe.header_size()
  if payload_mtu <= 0 {
    raise InvalidPacket("RTP extensions leave no room for a payload")
  }
  let payloads = match self.codec {
    Vp8 =>
      vp8_packetize(
        payload,
        payload_mtu,
        self.picture_id,
        self.include_vp8_picture_id,
      )
    Vp9 => vp9_packetize(payload, payload_mtu, self.picture_id)
    H264 => {
      let (parts, sps, pps) = h264_packetize(
        payload,
        payload_mtu,
        self.h264_sps,
        self.h264_pps,
      )
      self.h264_sps = sps
      self.h264_pps = pps
      parts
    }
    _ => packetize_payload(self.codec, payload, payload_mtu)
  }
  let packets : Array[Packet] = []
  for index = 0; index < payloads.length(); index = index + 1 {
    packets.push(
      Packet::new(
        marker=index + 1 == payloads.length(),
        payload_type=self.payload_type,
        sequence_number=self.sequence_number,
        timestamp=self.timestamp,
        ssrc=self.ssrc,
        extensions~,
        payload=payloads[index],
      ),
    )
    self.sequence_number = self.sequence_number + 1
  }
  self.timestamp = self.timestamp + samples
  if self.codec == Vp8 || self.codec == Vp9 {
    self.picture_id = (self.picture_id + 1) & 0x7fff
  }
  packets
}
