///|
fn reverse_datagram(
  datagram : @rtc.OutboundDatagram,
  now : @rtc.Instant,
) -> @rtc.InboundDatagram {
  {
    now,
    context: {
      local_address: datagram.context.peer,
      peer: datagram.context.local_address,
      ecn: datagram.context.ecn,
      protocol: datagram.context.protocol,
    },
    payload: datagram.payload,
  }
}

///|
fn pump(
  left : @rtc.PeerConnection,
  right : @rtc.PeerConnection,
  now : @rtc.Instant,
) -> Unit raise @rtc.RtcError {
  for round = 0; round < 16384; round = round + 1 {
    let mut progressed = false
    while left.poll_datagram() is Some(datagram) {
      right.handle_datagram(reverse_datagram(datagram, now))
      progressed = true
    }
    while right.poll_datagram() is Some(datagram) {
      left.handle_datagram(reverse_datagram(datagram, now))
      progressed = true
    }
    if !progressed {
      return
    }
  }
  raise InvalidState("the in-memory network did not quiesce")
}

///|
fn main {
  try {
    let now = @rtc.Instant::from_milliseconds(0)
    let sample = @rtc.ClockSample::new(
      monotonic=now,
      wall=@rtc.WallTime::from_unix_nanoseconds(1700000000000000000L),
    )
    let loopback = @rtc.IpAddress::loopback_v4()
    let offerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[
        @ice.IceCandidate::host(
          foundation="offerer",
          @rtc.SocketAddress::new(address=loopback, port=50000),
        ),
      ]),
      sample,
    )
    let answerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[
        @ice.IceCandidate::host(
          foundation="answerer",
          @rtc.SocketAddress::new(address=loopback, port=50001),
        ),
      ]),
      sample,
    )
    let channel = offerer.create_data_channel(
      @datachannel.DataChannelConfig::new(label="example"),
      now,
    )
    let offer = offerer.create_offer(now)
    offerer.set_local_description(offer, now)
    answerer.set_remote_description(offer, now)
    let answer = answerer.create_answer(now)
    answerer.set_local_description(answer, now)
    offerer.set_remote_description(answer, now)
    pump(offerer, answerer, now)
    offerer.handle_message(
      DataChannel(
        channel_id=channel.id(),
        message=Text("hello from a socket-free RTC loop"),
      ),
      now,
    )
    pump(offerer, answerer, now)
    guard answerer.poll_message()
      is Some(DataChannel(message=Text(received), ..)) else {
      fail("the example DataChannel message was not delivered")
    }
    println(received)
  } catch {
    _ => abort("the Sans-I/O DataChannel example failed")
  }
}
