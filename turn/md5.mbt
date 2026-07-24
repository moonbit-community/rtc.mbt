///|
fn rotate_left(value : UInt, shift : Int) -> UInt {
  (value << shift) | (value >> (32 - shift))
}

///|
fn read_u32_le(data : Array[Byte], offset : Int) -> UInt {
  data[offset].to_uint() |
  (data[offset + 1].to_uint() << 8) |
  (data[offset + 2].to_uint() << 16) |
  (data[offset + 3].to_uint() << 24)
}

///|
fn append_u32_le(output : Array[Byte], value : UInt) -> Unit {
  output.push(value.to_byte())
  output.push((value >> 8).to_byte())
  output.push((value >> 16).to_byte())
  output.push((value >> 24).to_byte())
}

///|
fn md5(data : Bytes) -> Bytes {
  let shifts : Array[Int] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5,
    9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16,
    23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ]
  let constants : Array[UInt] = [
    0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU, 0x4787c62aU,
    0xa8304613U, 0xfd469501U, 0x698098d8U, 0x8b44f7afU, 0xffff5bb1U, 0x895cd7beU,
    0x6b901122U, 0xfd987193U, 0xa679438eU, 0x49b40821U, 0xf61e2562U, 0xc040b340U,
    0x265e5a51U, 0xe9b6c7aaU, 0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U,
    0x21e1cde6U, 0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U,
    0x676f02d9U, 0x8d2a4c8aU, 0xfffa3942U, 0x8771f681U, 0x6d9d6122U, 0xfde5380cU,
    0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U, 0x289b7ec6U, 0xeaa127faU,
    0xd4ef3085U, 0x04881d05U, 0xd9d4d039U, 0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U,
    0xf4292244U, 0x432aff97U, 0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U,
    0xffeff47dU, 0x85845dd1U, 0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
    0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U,
  ]
  let padded = data.to_array()
  let bit_length = data.length().to_uint64() * 8UL
  padded.push(0x80)
  while padded.length() % 64 != 56 {
    padded.push(0)
  }
  for shift = 0; shift < 64; shift = shift + 8 {
    padded.push((bit_length >> shift).to_byte())
  }
  let mut a0 = 0x67452301U
  let mut b0 = 0xefcdab89U
  let mut c0 = 0x98badcfeU
  let mut d0 = 0x10325476U
  for offset = 0; offset < padded.length(); offset = offset + 64 {
    let words : Array[UInt] = []
    for index = 0; index < 16; index = index + 1 {
      words.push(read_u32_le(padded, offset + index * 4))
    }
    let mut a = a0
    let mut b = b0
    let mut c = c0
    let mut d = d0
    for index = 0; index < 64; index = index + 1 {
      let (function_value, word_index) = if index < 16 {
        ((b & c) | (b.lnot() & d), index)
      } else if index < 32 {
        ((d & b) | (d.lnot() & c), (5 * index + 1) % 16)
      } else if index < 48 {
        (b ^ c ^ d, (3 * index + 5) % 16)
      } else {
        (c ^ (b | d.lnot()), 7 * index % 16)
      }
      let previous_d = d
      d = c
      c = b
      b = b +
        rotate_left(
          a + function_value + constants[index] + words[word_index],
          shifts[index],
        )
      a = previous_d
    }
    a0 += a
    b0 += b
    c0 += c
    d0 += d
  }
  let output : Array[Byte] = []
  append_u32_le(output, a0)
  append_u32_le(output, b0)
  append_u32_le(output, c0)
  append_u32_le(output, d0)
  Bytes::from_array(output)
}

///|
pub fn long_term_key(
  username : String,
  realm : String,
  password : String,
) -> Bytes {
  md5(@utf8.encode(username + ":" + realm + ":" + password))
}
