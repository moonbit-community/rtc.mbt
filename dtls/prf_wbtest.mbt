///|
fn sequential_bytes(start : Byte) -> Bytes {
  let bytes : Array[Byte] = []
  for offset = 0; offset < 32; offset = offset + 1 {
    bytes.push(start + offset.to_byte())
  }
  Bytes::from_array(bytes)
}

///|
fn upstream_pre_master_secret() -> Bytes {
  b"\xdf\x4a\x29\x1b\xaa\x1e\xb7\xcf\xa6\x93\x4b\x29\xb4\x74\xba\xad" +
  b"\x26\x97\xe2\x9f\x1f\x92\x0d\xcc\x77\xc8\xa0\xa0\x88\x44\x76\x24"
}

///|
fn upstream_master_secret() -> Bytes {
  b"\x91\x6a\xbf\x9d\xa5\x59\x73\xe1\x36\x14\xae\x0a\x3f\x5d\x3f\x37" +
  b"\xb0\x23\xba\x12\x9a\xee\x02\xcc\x91\x34\x33\x81\x27\xcd\x70\x49" +
  b"\x78\x1c\x8e\x19\xfc\x1e\xb2\xa7\x38\x7a\xc0\x6a\xe2\x37\x34\x4c"
}

///|
test "TLS 1.2 PRF matches the pinned rtc-dtls master-secret vector" {
  let actual = p_hash_secret(
    @crypto.Secret::from_bytes(upstream_pre_master_secret()),
    append_three(
      b"master secret",
      sequential_bytes(0x00),
      sequential_bytes(0x70),
    ),
    48,
  )
  assert_eq(actual, upstream_master_secret())
}

///|
test "AES-128-GCM key expansion matches the pinned rtc-dtls vector" {
  let keys = encryption_keys_for_secret(
    @crypto.Secret::from_bytes(upstream_master_secret()),
    sequential_bytes(0x00),
    sequential_bytes(0x70),
  )
  assert_eq(
    keys.client_write_key,
    b"\x1b\x7d\x11\x7c\x7d\x5f\x69\x0b\xc2\x63\xca\xe8\xef\x60\xaf\x0f",
  )
  assert_eq(
    keys.server_write_key,
    b"\x18\x78\xac\xc2\x2a\xd8\xbd\xd8\xc6\x01\xa6\x17\x12\x6f\x63\x54",
  )
  assert_eq(keys.client_write_iv, b"\x0e\xb2\x09\x06")
  assert_eq(keys.server_write_iv, b"\xf7\x81\xfa\xd2")
}

///|
test "TLS exporter PRF seed is deterministic" {
  let seed = append_three(
    b"EXTRACTOR-dtls_srtp",
    sequential_bytes(0x00),
    sequential_bytes(0x70),
  )
  let secret = @crypto.Secret::from_bytes(upstream_master_secret())
  let first = p_hash_secret(secret, seed, 60)
  let second = p_hash_secret(secret, seed, 60)
  assert_eq(first, second)
  assert_eq(first.length(), 60)
}
