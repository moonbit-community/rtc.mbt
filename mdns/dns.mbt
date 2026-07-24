///|
const DNS_HEADER_LENGTH : Int = 12

///|
const DNS_TYPE_A : UInt16 = 1

///|
const DNS_TYPE_AAAA : UInt16 = 28

///|
const DNS_CLASS_IN : UInt16 = 1

///|
const DNS_TYPE_ANY : UInt16 = 255

///|
fn normalize_name(value : String) -> String raise MdnsError {
  let value = value.to_lower()
  let value = if value.has_suffix(".") {
    value[0:value.length() - 1].to_owned()
  } else {
    value
  }
  if value.is_empty() || value.length() > 253 || !value.has_suffix(".local") {
    raise InvalidName("mDNS name must end in .local")
  }
  let labels = value.split(".").to_array()
  for label in labels {
    if label.is_empty() || label.length() > 63 {
      raise InvalidName("mDNS label must contain 1 through 63 characters")
    }
    if label[0] == '-' || label[label.length() - 1] == '-' {
      raise InvalidName("mDNS label cannot begin or end with a hyphen")
    }
    for character in label.code_units() {
      if !((character >= 'a' && character <= 'z') ||
        (character >= '0' && character <= '9') ||
        character == '-') {
        raise InvalidName("mDNS name contains an invalid character")
      }
    }
  }
  value
}

///|
fn encode_name(name : String) -> Bytes raise MdnsError {
  let result : Array[Byte] = []
  for label in name.split(".") {
    let encoded = @utf8.encode(label)
    if encoded.is_empty() || encoded.length() > 63 {
      raise InvalidName("invalid mDNS label length")
    }
    result.push(encoded.length().to_byte())
    for byte in encoded {
      result.push(byte)
    }
  }
  result.push(0)
  Bytes::from_array(result)
}

///|
fn dns_writer(capacity : Int) -> @codec.Writer raise MdnsError {
  @codec.Writer::new(capacity~) catch {
    InvalidLength(length) =>
      raise InvalidPacket("invalid DNS writer capacity \{length}")
    Truncated(needed~, remaining~) =>
      raise InvalidPacket(
        "unexpected DNS writer truncation \{needed}/\{remaining}",
      )
  }
}

///|
fn encode_query(name : String) -> Bytes raise MdnsError {
  let encoded_name = encode_name(name)
  let writer = dns_writer(DNS_HEADER_LENGTH + (encoded_name.length() + 4) * 2)
  writer.write_u16_be(0)
  writer.write_u16_be(0)
  writer.write_u16_be(2)
  writer.write_u16_be(0)
  writer.write_u16_be(0)
  writer.write_u16_be(0)
  writer.write_bytes(encoded_name)
  writer.write_u16_be(DNS_TYPE_A)
  writer.write_u16_be(DNS_CLASS_IN | 0x8000)
  writer.write_bytes(encoded_name)
  writer.write_u16_be(DNS_TYPE_AAAA)
  writer.write_u16_be(DNS_CLASS_IN | 0x8000)
  writer.finish()
}

///|
fn read_u16_at(data : Bytes, offset : Int) -> UInt16 raise MdnsError {
  if offset < 0 || offset + 2 > data.length() {
    raise InvalidPacket("truncated DNS 16-bit field")
  }
  (data[offset].to_uint16() << 8) | data[offset + 1].to_uint16()
}

///|
fn read_u32_at(data : Bytes, offset : Int) -> UInt raise MdnsError {
  if offset < 0 || offset + 4 > data.length() {
    raise InvalidPacket("truncated DNS 32-bit field")
  }
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn decode_name(data : Bytes, start : Int) -> (String, Int) raise MdnsError {
  if start < 0 || start >= data.length() {
    raise InvalidPacket("DNS name starts outside the packet")
  }
  let labels : Array[String] = []
  let mut cursor = start
  let mut next_offset = -1
  let mut jumps = 0
  let mut total_length = 0
  while true {
    if cursor >= data.length() {
      raise InvalidPacket("truncated DNS name")
    }
    let length = data[cursor].to_uint()
    if (length & 0xc0U) == 0xc0U {
      if cursor + 2 > data.length() {
        raise InvalidPacket("truncated DNS compression pointer")
      }
      let pointer = (((length & 0x3fU) << 8) | data[cursor + 1].to_uint()).reinterpret_as_int()
      if pointer >= cursor || pointer >= data.length() {
        raise InvalidPacket("invalid forward DNS compression pointer")
      }
      if next_offset < 0 {
        next_offset = cursor + 2
      }
      cursor = pointer
      jumps += 1
      if jumps > 32 {
        raise InvalidPacket("too many DNS compression pointers")
      }
      continue
    }
    if (length & 0xc0U) != 0U {
      raise InvalidPacket("unsupported DNS label encoding")
    }
    cursor += 1
    if length == 0U {
      if next_offset < 0 {
        next_offset = cursor
      }
      return (labels.join(".").to_lower(), next_offset)
    }
    let label_length = length.reinterpret_as_int()
    if label_length > 63 || cursor + label_length > data.length() {
      raise InvalidPacket("invalid DNS label length")
    }
    let label = @utf8.decode(data[cursor:cursor + label_length]) catch {
      Malformed(_) => raise InvalidPacket("DNS label is not valid UTF-8")
    }
    if label.contains(".") {
      raise InvalidPacket("DNS label contains a dot")
    }
    labels.push(label)
    total_length += label_length + 1
    if total_length > 254 {
      raise InvalidPacket("decoded DNS name exceeds 254 bytes")
    }
    cursor += label_length
  }
  raise InvalidPacket("unreachable DNS name parser state")
}

///|
priv struct DnsQuestion {
  name : String
  resource_type : UInt16
}

///|
fn skip_resource_records(
  data : Bytes,
  start : Int,
  count : Int,
) -> Int raise MdnsError {
  let mut offset = start
  for _record = 0; _record < count; _record = _record + 1 {
    let (_, next) = decode_name(data, offset)
    offset = next
    if offset + 10 > data.length() {
      raise InvalidPacket("truncated DNS resource header")
    }
    let data_length = read_u16_at(data, offset + 8).to_int()
    offset += 10
    if offset + data_length > data.length() {
      raise InvalidPacket("truncated DNS resource data")
    }
    offset += data_length
  }
  offset
}

///|
fn parse_query(data : Bytes) -> Array[DnsQuestion] raise MdnsError {
  if data.length() < DNS_HEADER_LENGTH {
    raise InvalidPacket("DNS packet is shorter than its header")
  }
  let flags = read_u16_at(data, 2)
  if (flags & 0x8000) != 0 || (flags & 0x7800) != 0 {
    raise InvalidPacket("packet is not a standard DNS query")
  }
  let question_count = read_u16_at(data, 4).to_int()
  let resource_count = read_u16_at(data, 6).to_int() +
    read_u16_at(data, 8).to_int() +
    read_u16_at(data, 10).to_int()
  if question_count < 1 || question_count > 32 || resource_count > 128 {
    raise InvalidPacket("DNS query contains too many records")
  }
  let questions : Array[DnsQuestion] = []
  let mut offset = DNS_HEADER_LENGTH
  for _question = 0; _question < question_count; _question = _question + 1 {
    let (name, next) = decode_name(data, offset)
    offset = next
    if offset + 4 > data.length() {
      raise InvalidPacket("truncated DNS question")
    }
    let resource_type = read_u16_at(data, offset)
    let resource_class = read_u16_at(data, offset + 2)
    offset += 4
    if (resource_class & 0x7fff) == DNS_CLASS_IN {
      questions.push({ name, resource_type })
    }
  }
  offset = skip_resource_records(data, offset, resource_count)
  if offset != data.length() {
    raise InvalidPacket("DNS query contains trailing bytes")
  }
  questions
}

///|
fn encode_answer_record(
  name : String,
  address : @transport.IpAddress,
  ttl_seconds : UInt,
) -> Bytes raise MdnsError {
  let encoded_name = encode_name(name)
  let address_bytes = address.to_bytes()
  let resource_type : UInt16 = match address {
    V4(_) => DNS_TYPE_A
    V6(_) => DNS_TYPE_AAAA
  }
  let writer = dns_writer(encoded_name.length() + 10 + address_bytes.length())
  writer.write_bytes(encoded_name)
  writer.write_u16_be(resource_type)
  writer.write_u16_be(DNS_CLASS_IN | 0x8000)
  writer.write_u32_be(ttl_seconds)
  writer.write_u16_be(address_bytes.length().to_uint16())
  writer.write_bytes(address_bytes)
  writer.finish()
}

///|
fn encode_registered_response(
  query : Bytes,
  registrations : Map[String, Array[@transport.IpAddress]],
  ttl_seconds : UInt,
) -> Bytes? raise MdnsError {
  let questions = parse_query(query)
  let records : Array[(String, @transport.IpAddress)] = []
  for question in questions {
    match registrations.get(question.name) {
      Some(addresses) =>
        for address in addresses {
          let matches = match address {
            V4(_) =>
              question.resource_type == DNS_TYPE_A ||
              question.resource_type == DNS_TYPE_ANY
            V6(_) =>
              question.resource_type == DNS_TYPE_AAAA ||
              question.resource_type == DNS_TYPE_ANY
          }
          if matches && !records.contains((question.name, address)) {
            records.push((question.name, address))
          }
        }
      None => ()
    }
  }
  if records.is_empty() {
    return None
  }
  let encoded_records : Array[Bytes] = []
  let mut total_length = DNS_HEADER_LENGTH
  for record in records {
    let (name, address) = record
    let encoded = encode_answer_record(name, address, ttl_seconds)
    total_length += encoded.length()
    encoded_records.push(encoded)
  }
  let writer = dns_writer(total_length)
  writer.write_u16_be(read_u16_at(query, 0))
  writer.write_u16_be(0x8400)
  writer.write_u16_be(0)
  writer.write_u16_be(encoded_records.length().to_uint16())
  writer.write_u16_be(0)
  writer.write_u16_be(0)
  for record in encoded_records {
    writer.write_bytes(record)
  }
  Some(writer.finish())
}

///|
priv struct DnsAnswer {
  name : String
  address : @transport.IpAddress
  ttl_seconds : UInt
}

///|
fn parse_response(data : Bytes) -> Array[DnsAnswer] raise MdnsError {
  if data.length() < DNS_HEADER_LENGTH {
    raise InvalidPacket("DNS packet is shorter than its header")
  }
  let flags = read_u16_at(data, 2)
  if (flags & 0x8000) == 0 || (flags & 0x7800) != 0 {
    raise InvalidPacket("packet is not a standard DNS response")
  }
  let question_count = read_u16_at(data, 4).to_int()
  let answer_count = read_u16_at(data, 6).to_int()
  let authority_count = read_u16_at(data, 8).to_int()
  let additional_count = read_u16_at(data, 10).to_int()
  let resource_count = answer_count + authority_count + additional_count
  if question_count > 32 || resource_count > 128 {
    raise InvalidPacket("DNS packet contains too many records")
  }
  let mut offset = DNS_HEADER_LENGTH
  for _question = 0; _question < question_count; _question = _question + 1 {
    let (_, next) = decode_name(data, offset)
    offset = next
    if offset + 4 > data.length() {
      raise InvalidPacket("truncated DNS question")
    }
    offset += 4
  }
  let answers : Array[DnsAnswer] = []
  for _record = 0; _record < resource_count; _record = _record + 1 {
    let (name, next) = decode_name(data, offset)
    offset = next
    if offset + 10 > data.length() {
      raise InvalidPacket("truncated DNS resource header")
    }
    let resource_type = read_u16_at(data, offset)
    let resource_class = read_u16_at(data, offset + 2)
    let ttl_seconds = read_u32_at(data, offset + 4)
    let data_length = read_u16_at(data, offset + 8).to_int()
    offset += 10
    if offset + data_length > data.length() {
      raise InvalidPacket("truncated DNS resource data")
    }
    if (resource_class & 0x7fff) == DNS_CLASS_IN && ttl_seconds > 0U {
      if resource_type == DNS_TYPE_A && data_length == 4 {
        answers.push({
          name,
          address: @transport.IpAddress::v4(
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
          ),
          ttl_seconds,
        })
      } else if resource_type == DNS_TYPE_AAAA && data_length == 16 {
        let address = @transport.IpAddress::v6(
          data[offset:offset + 16].to_owned(),
        ) catch {
          InvalidIpv6Length(length) =>
            raise InvalidPacket("invalid AAAA length \{length}")
          InvalidAddress(message) => raise InvalidPacket(message)
        }
        answers.push({ name, address, ttl_seconds })
      }
    }
    offset += data_length
  }
  if offset != data.length() {
    raise InvalidPacket("DNS packet contains trailing bytes")
  }
  answers
}
