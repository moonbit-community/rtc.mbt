///|
fn srtp_test_key() -> Bytes {
  b"\x0d\xcd\x21\x3e\x4c\xbc\xf2\x8f\x01\x7f\x69\x94\x40\x1e\x28\x89"
}

///|
fn srtp_test_salt() -> Bytes {
  b"\x62\x77\x60\x38\xc0\x6d\xc9\x41\x9f\x6d\xd9\x43\x3e\x7c"
}

///|
fn srtp_packet(sequence_number : UInt16) -> @rtp.Packet raise @rtp.RtpError {
  @rtp.Packet::new(
    payload_type=0,
    sequence_number~,
    timestamp=0U,
    ssrc=0U,
    payload=b"\x00\x01\x02\x03\x04\x05",
  )
}

///|
test "AES-CM SRTP matches the pinned cipher vector with an RTP v2 header" {
  let sender = @srtp.Context::new(
    profile=Aes128CmHmacSha1_80,
    master_key=srtp_test_key(),
    master_salt=srtp_test_salt(),
  )
  let receiver = @srtp.Context::new(
    profile=Aes128CmHmacSha1_80,
    master_key=srtp_test_key(),
    master_salt=srtp_test_salt(),
  )
  let plaintext = srtp_packet(5000).marshal()
  let expected = b"\x80\x00\x13\x88\x00\x00\x00\x00\x00\x00\x00\x00" +
    b"\x6d\xd3\x7e\xd5\x99\xb7\xfb\xe2\x58\x74\x7f\xe7\x30\xf9\xb4\x62"
  let encrypted = sender.encrypt_rtp(plaintext)
  assert_eq(encrypted, expected)
  assert_eq(receiver.decrypt_rtp(encrypted), plaintext)
}

///|
test "all negotiated SRTP profiles protect RTP and reject tampering and replay" {
  let profiles : Array[@srtp.ProtectionProfile] = [
    Aes128CmHmacSha1_80,
    Aes128CmHmacSha1_32,
    AeadAes128Gcm,
    AeadAes256Gcm,
  ]
  for profile in profiles {
    let key = Bytes::make(profile.key_length(), 0x11)
    let salt = Bytes::make(profile.salt_length(), 0x22)
    let sender = @srtp.Context::new(profile~, master_key=key, master_salt=salt)
    let receiver = @srtp.Context::new(
      profile~,
      master_key=key,
      master_salt=salt,
    )
    let packet = @rtp.Packet::new(
      marker=true,
      payload_type=96,
      sequence_number=65535,
      timestamp=0x10203040U,
      ssrc=0xaabbccddU,
      extensions=[@rtp.HeaderExtension::new(id=1, payload=b"\x01\x02")],
      payload=Bytes::make(700, 0x5a),
    )
    let encrypted = sender.protect_rtp(packet)
    assert_true(encrypted != packet.marshal())
    assert_eq(receiver.unprotect_rtp(encrypted), packet)
    ignore(receiver.decrypt_rtp(encrypted)) catch {
      ReplayRejected => ()
      _ => fail("unexpected duplicate SRTP error")
    }
    let corrupted = encrypted.to_array()
    corrupted[corrupted.length() - 1] = corrupted[corrupted.length() - 1] ^ 0x01
    let fresh_receiver = @srtp.Context::new(
      profile~,
      master_key=key,
      master_salt=salt,
    )
    ignore(fresh_receiver.decrypt_rtp(Bytes::from_array(corrupted))) catch {
      AuthenticationFailed => continue
      _ => fail("unexpected corrupted SRTP error")
    }
    fail("corrupted SRTP authentication tag was accepted")
  }
}

///|
test "SRTP rollover counter advances across sequence wraparound" {
  let sender = @srtp.Context::new(
    profile=Aes128CmHmacSha1_80,
    master_key=srtp_test_key(),
    master_salt=srtp_test_salt(),
  )
  let receiver = @srtp.Context::new(
    profile=Aes128CmHmacSha1_80,
    master_key=srtp_test_key(),
    master_salt=srtp_test_salt(),
  )
  let sequences : Array[UInt16] = [65534, 65535, 0, 1]
  for sequence in sequences {
    let packet = srtp_packet(sequence)
    assert_eq(receiver.unprotect_rtp(sender.protect_rtp(packet)), packet)
  }
}

///|
test "AES-CM and AEAD SRTCP protect compound RTCP and reject replay" {
  let profiles : Array[@srtp.ProtectionProfile] = [
    Aes128CmHmacSha1_80,
    AeadAes128Gcm,
    AeadAes256Gcm,
  ]
  for profile in profiles {
    let key = Bytes::make(profile.key_length(), 0x31)
    let salt = Bytes::make(profile.salt_length(), 0x42)
    let sender = @srtp.Context::new(profile~, master_key=key, master_salt=salt)
    let receiver = @srtp.Context::new(
      profile~,
      master_key=key,
      master_salt=salt,
    )
    let report = @rtcp.SenderReportPacket::new(
      sender_ssrc=0x11223344U,
      ntp_timestamp=0x0102030405060708UL,
      rtp_timestamp=9U,
      packet_count=10U,
      octet_count=11U,
    )
    let sdes = @rtcp.SourceDescriptionPacket::new(chunks=[
      @rtcp.SourceDescriptionChunk::new(source=0x11223344U, items=[
        @rtcp.SourceDescriptionItem::new(item_type=Cname, value=b"rtc.mbt"),
      ]),
    ])
    let encrypted = sender.protect_rtcp([report.to_packet(), sdes.to_packet()])
    let decoded = receiver.unprotect_rtcp(encrypted)
    assert_eq(decoded, [report.to_packet(), sdes.to_packet()])
    ignore(receiver.decrypt_rtcp(encrypted)) catch {
      ReplayRejected => continue
      _ => fail("unexpected duplicate SRTCP error")
    }
    fail("duplicate SRTCP packet was accepted")
  }
}

///|
test "SRTP and SRTCP reject short untrusted packets without panicking" {
  let context = @srtp.Context::new(
    profile=AeadAes128Gcm,
    master_key=Bytes::make(16, 0),
    master_salt=Bytes::make(12, 0),
  )
  for packet in [b"", b"\x80", Bytes::make(11, 0)] {
    ignore(context.decrypt_rtp(packet)) catch {
      InvalidPacket(_) => continue
      _ => fail("unexpected short SRTP error")
    }
    fail("short SRTP packet was accepted")
  }
  ignore(context.decrypt_rtcp(Bytes::make(27, 0))) catch {
    InvalidPacket(_) => return
    _ => fail("unexpected short SRTCP error")
  }
  fail("short SRTCP packet was accepted")
}
