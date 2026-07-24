///|
pub(all) suberror AddressError {
  InvalidIpv6Length(Int)
  InvalidAddress(String)
} derive(Debug, Eq)

///|
pub enum IpAddress {
  V4(UInt)
  V6(Bytes)
} derive(Debug, Eq)

///|
pub fn IpAddress::v4(a : Byte, b : Byte, c : Byte, d : Byte) -> IpAddress {
  V4(
    (a.to_uint() << 24) | (b.to_uint() << 16) | (c.to_uint() << 8) | d.to_uint(),
  )
}

///|
pub fn IpAddress::v6(bytes : Bytes) -> IpAddress raise AddressError {
  if bytes.length() != 16 {
    raise InvalidIpv6Length(bytes.length())
  }
  V6(bytes)
}

///|
pub fn IpAddress::loopback_v4() -> IpAddress {
  IpAddress::v4(127, 0, 0, 1)
}

///|
pub fn IpAddress::to_bytes(self : IpAddress) -> Bytes {
  match self {
    V4(value) =>
      Bytes::from_array([
        (value >> 24).to_byte(),
        (value >> 16).to_byte(),
        (value >> 8).to_byte(),
        value.to_byte(),
      ])
    V6(bytes) => bytes
  }
}

///|
fn parse_decimal_octet(value : StringView) -> Byte raise AddressError {
  if value.is_empty() || value.length() > 3 {
    raise InvalidAddress("invalid IPv4 octet")
  }
  let mut result = 0
  for character in value.code_units() {
    if character < '0' || character > '9' {
      raise InvalidAddress("invalid IPv4 digit")
    }
    result = result * 10 + (character - '0').to_int()
    if result > 255 {
      raise InvalidAddress("IPv4 octet exceeds 255")
    }
  }
  result.to_byte()
}

///|
fn parse_ipv4(value : StringView) -> IpAddress raise AddressError {
  let parts = value.split(".").to_array()
  if parts.length() != 4 {
    raise InvalidAddress("IPv4 address must contain four octets")
  }
  IpAddress::v4(
    parse_decimal_octet(parts[0]),
    parse_decimal_octet(parts[1]),
    parse_decimal_octet(parts[2]),
    parse_decimal_octet(parts[3]),
  )
}

///|
fn hex_value(character : UInt16) -> UInt16 raise AddressError {
  if character >= '0' && character <= '9' {
    character - '0'
  } else if character >= 'a' && character <= 'f' {
    character - 'a' + 10
  } else if character >= 'A' && character <= 'F' {
    character - 'A' + 10
  } else {
    raise InvalidAddress("invalid IPv6 hex digit")
  }
}

///|
fn parse_hextet(value : StringView) -> UInt16 raise AddressError {
  if value.is_empty() || value.length() > 4 {
    raise InvalidAddress("invalid IPv6 hextet")
  }
  let mut result : UInt16 = 0
  for character in value.code_units() {
    result = (result << 4) | hex_value(character)
  }
  result
}

///|
fn parse_ipv6_side(value : StringView) -> Array[UInt16] raise AddressError {
  if value.is_empty() {
    return []
  }
  let tokens = value.split(":").to_array()
  let result : Array[UInt16] = []
  for index = 0; index < tokens.length(); index = index + 1 {
    let token = tokens[index]
    if token.is_empty() {
      raise InvalidAddress("empty IPv6 hextet outside ::")
    }
    if token.contains(".") {
      if index != tokens.length() - 1 {
        raise InvalidAddress("embedded IPv4 address must be last")
      }
      let ipv4 = parse_ipv4(token).to_bytes()
      result.push((ipv4[0].to_uint16() << 8) | ipv4[1].to_uint16())
      result.push((ipv4[2].to_uint16() << 8) | ipv4[3].to_uint16())
    } else {
      result.push(parse_hextet(token))
    }
  }
  result
}

///|
fn parse_ipv6(value : StringView) -> IpAddress raise AddressError {
  let words : Array[UInt16] = []
  match value.split_once("::") {
    Some((left, right)) => {
      if right.contains("::") {
        raise InvalidAddress("IPv6 address contains multiple :: sequences")
      }
      let left_words = parse_ipv6_side(left)
      let right_words = parse_ipv6_side(right)
      if left_words.length() + right_words.length() >= 8 {
        raise InvalidAddress("IPv6 :: must compress at least one hextet")
      }
      for word in left_words {
        words.push(word)
      }
      for zero_index = left_words.length() + right_words.length()
          zero_index < 8
          zero_index = zero_index + 1 {
        words.push(0)
      }
      for word in right_words {
        words.push(word)
      }
    }
    None => {
      let parsed = parse_ipv6_side(value)
      if parsed.length() != 8 {
        raise InvalidAddress("IPv6 address must contain eight hextets")
      }
      for word in parsed {
        words.push(word)
      }
    }
  }
  let bytes : Array[Byte] = []
  for word in words {
    bytes.push((word >> 8).to_byte())
    bytes.push(word.to_byte())
  }
  IpAddress::v6(Bytes::from_array(bytes))
}

///|
pub fn IpAddress::parse(value : String) -> IpAddress raise AddressError {
  if value.is_empty() {
    raise InvalidAddress("IP address is empty")
  }
  if value.contains(":") {
    parse_ipv6(value)
  } else {
    parse_ipv4(value)
  }
}

///|
pub fn IpAddress::to_string(self : IpAddress) -> String {
  match self {
    V4(_) => {
      let bytes = self.to_bytes()
      bytes[0].to_uint().to_string() +
      "." +
      bytes[1].to_uint().to_string() +
      "." +
      bytes[2].to_uint().to_string() +
      "." +
      bytes[3].to_uint().to_string()
    }
    V6(bytes) => {
      let words : Array[UInt16] = []
      for index = 0; index < 16; index = index + 2 {
        words.push(
          (bytes[index].to_uint16() << 8) | bytes[index + 1].to_uint16(),
        )
      }
      let mut best_start = -1
      let mut best_length = 0
      let mut index = 0
      while index < words.length() {
        if words[index] != 0 {
          index += 1
          continue
        }
        let start = index
        while index < words.length() && words[index] == 0 {
          index += 1
        }
        let length = index - start
        if length >= 2 && length > best_length {
          best_start = start
          best_length = length
        }
      }
      let mut result = ""
      index = 0
      while index < words.length() {
        if index == best_start {
          result = result + "::"
          index += best_length
          continue
        }
        if !result.is_empty() && !result.has_suffix(":") {
          result = result + ":"
        }
        result = result + words[index].to_string(radix=16)
        index += 1
      }
      result
    }
  }
}

///|
pub fn IpAddress::is_unspecified(self : IpAddress) -> Bool {
  match self {
    V4(value) => value == 0U
    V6(bytes) => {
      for byte in bytes {
        if byte != 0 {
          return false
        }
      }
      true
    }
  }
}

///|
pub struct SocketAddress {
  address : IpAddress
  port : UInt16
} derive(Debug, Eq)

///|
pub fn SocketAddress::new(
  address~ : IpAddress,
  port~ : UInt16,
) -> SocketAddress {
  { address, port }
}

///|
pub fn SocketAddress::address(self : SocketAddress) -> IpAddress {
  self.address
}

///|
pub fn SocketAddress::port(self : SocketAddress) -> UInt16 {
  self.port
}

///|
pub fn SocketAddress::to_string(self : SocketAddress) -> String {
  match self.address {
    V4(_) => self.address.to_string() + ":" + self.port.to_string()
    V6(_) => "[" + self.address.to_string() + "]:" + self.port.to_string()
  }
}

///|
pub(all) enum TransportProtocol {
  Udp
  Tcp
} derive(Debug, Eq)

///|
pub(all) enum EcnCodepoint {
  Ect0
  Ect1
  CongestionExperienced
} derive(Debug, Eq)
