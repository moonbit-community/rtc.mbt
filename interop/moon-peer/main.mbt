///|
fn binary_fixture() -> Bytes {
  let data : Array[Byte] = []
  for index = 0; index < 2500; index = index + 1 {
    data.push(((index * 31 + 7) % 251).to_byte())
  }
  Bytes::from_array(data)
}

///|
enum InteropMode {
  ReliableMode
  PartialMode
  MediaMode
} derive(Eq)

///|
struct OutboundMedia {
  audio_ssrc : UInt
  audio_payload_type : Byte
  video_ssrc : UInt
  video_payload_type : Byte
}

///|
fn add_interop_media(
  peer : @rtc.PeerConnection,
  now : @rtc.Instant,
) -> Unit raise Error {
  let audio_codec = @media.CodecCapability::new(
    mime_type="audio/opus",
    clock_rate=48000U,
    channels=2,
    fmtp="minptime=10;useinbandfec=1",
    rtcp_feedback=["transport-cc"],
  )
  ignore(
    peer.add_track(
      @media.MediaTrack::new(
        id="moonbit-audio",
        stream_id="moonbit-media",
        kind=Audio,
        codec=audio_codec,
      ),
      now,
    ),
  )
  let video_codec = @media.CodecCapability::new(
    mime_type="video/vp8",
    clock_rate=90000U,
    rtcp_feedback=["nack", "nack pli", "transport-cc"],
  )
  ignore(
    peer.add_track(
      @media.MediaTrack::new(
        id="moonbit-video",
        stream_id="moonbit-media",
        kind=Video,
        codec=video_codec,
      ),
      now,
    ),
  )
}

///|
fn negotiated_outbound_media(
  peer : @rtc.PeerConnection,
) -> OutboundMedia raise Error {
  guard peer.local_track_ssrc("moonbit-audio") is Some(audio_ssrc) &&
    peer.local_track_payload_type("moonbit-audio") is Some(audio_payload_type) &&
    peer.local_track_ssrc("moonbit-video") is Some(video_ssrc) &&
    peer.local_track_payload_type("moonbit-video") is Some(video_payload_type) else {
    fail("external media answer omitted negotiated RTP transport parameters")
  }
  { audio_ssrc, audio_payload_type, video_ssrc, video_payload_type, }
}

///|
async fn send_interop_media(
  handle : @rtc_async.PeerHandle,
  media : OutboundMedia,
) -> Unit raise Error {
  for index = 0; index < 30; index = index + 1 {
    let sequence = (index + 1).to_uint16()
    let timestamp = ((index + 1) * 960).reinterpret_as_uint()
    let packet = try! @rtp.Packet::new(
      marker=true,
      payload_type=media.audio_payload_type,
      sequence_number=sequence,
      timestamp~,
      ssrc=media.audio_ssrc,
      payload=b"\xf8\xff\xfe",
    )
    handle.send(Rtp(track_id="moonbit-audio", packet~))
    @async_runtime.sleep(5)
  }
  for index = 0; index < 12; index = index + 1 {
    let sequence = (index + 1).to_uint16()
    let timestamp = ((index + 1) * 3000).reinterpret_as_uint()
    // A complete VP8 payload descriptor followed by a small deterministic
    // key-frame-shaped fixture. Browser acceptance is measured at RTP/SRTP
    // ingress, independently of decoder output.
    let packet = try! @rtp.Packet::new(
      marker=true,
      payload_type=media.video_payload_type,
      sequence_number=sequence,
      timestamp~,
      ssrc=media.video_ssrc,
      payload=b"\x98\x36\xbe\x88\x9e",
    )
    handle.send(Rtp(track_id="moonbit-video", packet~))
    @async_runtime.sleep(5)
  }
}

///|
async fn publish_file(path : String, contents : String) -> Unit {
  let temporary = path + ".tmp"
  @fs.write_file(temporary, contents, create_mode=CreateOrTruncate)
  @fs.rename(temporary, path)
}

///|
async fn await_file(path : String, description : String) -> String {
  for attempt = 0; attempt < 3000; attempt = attempt + 1 {
    if @fs.exists(path) {
      return @fs.read_file(path).text()
    }
    @async_runtime.sleep(10)
  }
  fail("timed out waiting for \{description}: \{path}")
}

///|
async fn await_channel_open(
  events : @rtc_async.EventStream,
  expected : @rtc.DataChannel,
) -> Unit raise @rtc_async.DriverError {
  for ;; {
    match events.next() {
      Some(DataChannelOpened(channel)) if channel.id() == expected.id() => {
        println("MoonBit DataChannel opened")
        return
      }
      Some(IceConnectionStateChanged(Checking)) =>
        println("MoonBit ICE checking")
      Some(IceConnectionStateChanged(Connected)) =>
        println("MoonBit ICE connected")
      Some(IceConnectionStateChanged(Completed)) =>
        println("MoonBit ICE completed")
      Some(IceConnectionStateChanged(Failed)) =>
        raise Io("MoonBit ICE entered Failed before DataChannel open")
      Some(ConnectionStateChanged(Connecting)) =>
        println("MoonBit peer connection connecting")
      Some(ConnectionStateChanged(Connected)) =>
        println("MoonBit peer connection connected")
      Some(ConnectionStateChanged(Failed)) =>
        raise Io("MoonBit peer connection failed before DataChannel open")
      Some(_) => ()
      None => raise Io("MoonBit event stream ended before DataChannel open")
    }
  }
}

///|
async fn await_remote_channel(
  events : @rtc_async.EventStream,
  mode : InteropMode,
) -> @rtc.DataChannel raise @rtc_async.DriverError {
  for ;; {
    match events.next() {
      Some(DataChannelOpened(channel)) if channel.label() == "interop" => {
        match mode {
          ReliableMode | MediaMode =>
            if channel.ordering() != Ordered ||
              channel.reliability() != Reliable {
              raise Io("reliable DataChannel parameters did not round-trip")
            }
          PartialMode =>
            if channel.ordering() != Unordered ||
              channel.reliability() != RetransmitCount(2) {
              raise Io("Rust partial DataChannel parameters did not round-trip")
            }
        }
        println("MoonBit remote DataChannel opened")
        return channel
      }
      Some(IceConnectionStateChanged(Checking)) =>
        println("MoonBit ICE checking")
      Some(IceConnectionStateChanged(Connected)) =>
        println("MoonBit ICE connected")
      Some(IceConnectionStateChanged(Completed)) =>
        println("MoonBit ICE completed")
      Some(IceConnectionStateChanged(Failed)) =>
        raise Io("MoonBit ICE entered Failed before remote DataChannel open")
      Some(ConnectionStateChanged(Connecting)) =>
        println("MoonBit peer connection connecting")
      Some(ConnectionStateChanged(Connected)) =>
        println("MoonBit peer connection connected")
      Some(ConnectionStateChanged(Failed)) =>
        raise Io(
          "MoonBit peer connection failed before remote DataChannel open",
        )
      Some(_) => ()
      None =>
        raise Io("MoonBit event stream ended before remote DataChannel open")
    }
  }
}

///|
async fn verify_echoes(
  messages : @rtc_async.MessageStream,
  channel : @rtc.DataChannel,
  media_mode : Bool,
) -> Unit raise @rtc_async.DriverError {
  let expected_text = "moonbit-rust-text"
  let expected_binary = binary_fixture()
  let mut saw_text = false
  let mut saw_binary = false
  while !saw_text || !saw_binary {
    match messages.next() {
      Some(DataChannel(channel_id~, message=Text(value))) if channel_id ==
        channel.id() &&
        value == expected_text => saw_text = true
      Some(DataChannel(channel_id~, message=Binary(value))) if channel_id ==
        channel.id() &&
        value == expected_binary => saw_binary = true
      Some(DataChannel(channel_id~, message=_message)) =>
        raise Io("unexpected DataChannel echo on stream \{channel_id.value()}")
      Some(Rtcp(_)) if media_mode => ()
      Some(Rtp(_)) if media_mode => ()
      Some(_) =>
        raise Io("unexpected non-DataChannel message in interop fixture")
      None =>
        raise Io("MoonBit message stream ended before both echoes arrived")
    }
  }
}

///|
async fn echo_and_verify(
  messages : @rtc_async.MessageStream,
  handle : @rtc_async.PeerHandle,
  channel : @rtc.DataChannel,
  mode : InteropMode,
) -> Unit raise @rtc_async.DriverError {
  let expected_text = "rust-moonbit-text"
  let expected_binary = binary_fixture()
  let mut saw_text = false
  let mut saw_binary = false
  let media_track_ids : Array[String] = []
  for ;; {
    let media_complete = match mode {
      MediaMode => media_track_ids.length() >= 2
      _ => true
    }
    if saw_text && saw_binary && media_complete {
      return
    }
    match messages.next() {
      Some(DataChannel(channel_id~, message=Text(value))) if channel_id ==
        channel.id() &&
        value == expected_text => {
        saw_text = true
        handle.send(DataChannel(channel_id~, message=Text(value)))
      }
      Some(DataChannel(channel_id~, message=Binary(value))) if channel_id ==
        channel.id() &&
        value == expected_binary => {
        saw_binary = true
        handle.send(DataChannel(channel_id~, message=Binary(value)))
      }
      Some(DataChannel(channel_id~, message=_message)) =>
        raise Io(
          "unexpected DataChannel payload on stream \{channel_id.value()}",
        )
      Some(Rtp(track_id~, packet=_)) if mode == MediaMode =>
        if !media_track_ids.contains(track_id) {
          media_track_ids.push(track_id)
        }
      Some(Rtcp(_)) if mode == MediaMode => ()
      Some(_) =>
        raise Io("unexpected non-DataChannel message in interop fixture")
      None =>
        raise Io("MoonBit message stream ended before both messages arrived")
    }
  }
}

///|
async fn close_channel(
  events : @rtc_async.EventStream,
  handle : @rtc_async.PeerHandle,
  channel : @rtc.DataChannel,
) -> Unit raise @rtc_async.DriverError {
  handle.close_data_channel(channel)
  for ;; {
    match events.next() {
      Some(DataChannelClosed(channel_id)) if channel_id == channel.id() =>
        return
      Some(_) => ()
      None => raise Io("MoonBit event stream ended before DataChannel close")
    }
  }
}

///|
async fn run_offerer(
  mode : InteropMode,
  local_port : UInt16,
  offer_path : String,
  answer_path : String,
  moon_result_path : String,
  rust_result_path : String,
) -> Unit {
  let local_candidate = @ice.IceCandidate::host(
    foundation="moonbit",
    @rtc.SocketAddress::new(
      address=@rtc.IpAddress::loopback_v4(),
      port=local_port,
    ),
  )
  let sample = @rtc_async.sample_clock()
  let peer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[local_candidate]),
    sample,
  )
  if mode == MediaMode {
    add_interop_media(peer, sample.monotonic())
  }
  let channel_config = match mode {
    ReliableMode => @datachannel.DataChannelConfig::new(label="interop")
    PartialMode =>
      @datachannel.DataChannelConfig::new(
        label="interop",
        ordering=Unordered,
        reliability=RetransmitCount(2),
      )
    MediaMode => @datachannel.DataChannelConfig::new(label="interop")
  }
  let channel = peer.create_data_channel(channel_config, sample.monotonic())
  let offer = peer.create_offer(sample.monotonic())
  peer.set_local_description(offer, sample.monotonic())
  publish_file(offer_path, offer.sdp())
  let answer_sdp = await_file(answer_path, "Rust answer")
  let answer = @sdp.SessionDescription::new(sdp_type=Answer, sdp=answer_sdp)
  peer.set_remote_description(answer, @rtc_async.sample_clock().monotonic())
  let outbound_media = if mode == MediaMode {
    Some(negotiated_outbound_media(peer))
  } else {
    None
  }

  let (driver, handle, events, messages) = @rtc_async.Driver::create(peer)
  @async_runtime.with_task_group <| group => {
    let driver_task = group.spawn(() => driver.run())
    await_channel_open(events, channel)
    handle.send(
      DataChannel(channel_id=channel.id(), message=Text("moonbit-rust-text")),
    )
    handle.send(
      DataChannel(channel_id=channel.id(), message=Binary(binary_fixture())),
    )
    match outbound_media {
      Some(media) => send_interop_media(handle, media)
      None => ()
    }
    verify_echoes(messages, channel, mode == MediaMode)
    publish_file(moon_result_path, "ok\n")
    ignore(await_file(rust_result_path, "Rust completion marker"))
    close_channel(events, handle, channel)
    handle.close()
    driver_task.wait()
  }
}

///|
async fn run_answerer(
  mode : InteropMode,
  local_port : UInt16,
  offer_path : String,
  answer_path : String,
  moon_result_path : String,
  rust_result_path : String,
) -> Unit {
  let local_candidate = @ice.IceCandidate::host(
    foundation="moonbit",
    @rtc.SocketAddress::new(
      address=@rtc.IpAddress::loopback_v4(),
      port=local_port,
    ),
  )
  let sample = @rtc_async.sample_clock()
  let peer = @rtc.PeerConnection::new(
    @rtc.Configuration::new(host_candidates=[local_candidate]),
    sample,
  )
  let offer_sdp = await_file(offer_path, "Rust offer")
  let offer = @sdp.SessionDescription::new(sdp_type=Offer, sdp=offer_sdp)
  peer.set_remote_description(offer, sample.monotonic())
  let answer = peer.create_answer(sample.monotonic())
  peer.set_local_description(answer, sample.monotonic())
  publish_file(answer_path, answer.sdp())

  let (driver, handle, events, messages) = @rtc_async.Driver::create(peer)
  @async_runtime.with_task_group <| group => {
    let driver_task = group.spawn(() => driver.run())
    let channel = await_remote_channel(events, mode)
    echo_and_verify(messages, handle, channel, mode)
    publish_file(moon_result_path, "ok\n")
    ignore(await_file(rust_result_path, "Rust completion marker"))
    close_channel(events, handle, channel)
    handle.close()
    driver_task.wait()
  }
}

///|
async fn main {
  guard @env.args()[1:]
    is [
      role,
      mode_text,
      local_port_text,
      offer_path,
      answer_path,
      moon_result_path,
      rust_result_path,
    ] else {
    fail(
      "usage: moon-peer ROLE MODE LOCAL_PORT OFFER_SDP ANSWER_SDP MOON_RESULT RUST_RESULT",
    )
  }
  let mode = match mode_text {
    "reliable" => ReliableMode
    "partial" => PartialMode
    "media" => MediaMode
    _ => fail("MODE must be reliable, partial, or media")
  }
  let local_port_value = @string.parse_int(local_port_text)
  if local_port_value < 1 || local_port_value > 65535 {
    fail("LOCAL_PORT must be in 1..65535")
  }
  @async_runtime.with_timeout(30000) <| () => {
    match role {
      "offer" =>
        run_offerer(
          mode,
          local_port_value.to_uint16(),
          offer_path,
          answer_path,
          moon_result_path,
          rust_result_path,
        )
      "answer" =>
        run_answerer(
          mode,
          local_port_value.to_uint16(),
          offer_path,
          answer_path,
          moon_result_path,
          rust_result_path,
        )
      _ => fail("ROLE must be offer or answer")
    }
  }
}
