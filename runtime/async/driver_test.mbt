///|
async fn reserve_udp_ports() -> (UInt16, UInt16) {
  let first = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
  let second = @socket.UdpServer(@socket.Addr::parse("127.0.0.1:0"))
  let first_port = first.addr.port().to_uint16()
  let second_port = second.addr.port().to_uint16()
  first.close()
  second.close()
  (first_port, second_port)
}

///|
async fn reserve_tcp_port() -> UInt16 {
  let server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
  let port = server.addr.port().to_uint16()
  server.close()
  port
}

///|
async fn wait_for_open(
  events : @async.EventStream,
  expected : @rtc.DataChannel,
) -> Unit raise @async.DriverError {
  for ;; {
    match events.next() {
      Some(DataChannelOpened(channel)) if channel.id() == expected.id() =>
        return
      Some(_) => ()
      None => raise Closed
    }
  }
}

///|
async test "async Drivers exchange a DataChannel message over real UDP" {
  @async_runtime.with_timeout(60000) <| () => {
    let (offerer_port, answerer_port) = reserve_udp_ports()
    let loopback = @rtc.IpAddress::loopback_v4()
    let offerer_candidate = @ice.IceCandidate::host(
      foundation="offerer",
      @rtc.SocketAddress::new(address=loopback, port=offerer_port),
    )
    let answerer_candidate = @ice.IceCandidate::host(
      foundation="answerer",
      @rtc.SocketAddress::new(address=loopback, port=answerer_port),
    )
    let sample = @async.sample_clock()
    let offerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[offerer_candidate]),
      sample,
    )
    let answerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[answerer_candidate]),
      sample,
    )
    let channel = offerer.create_data_channel(
      @datachannel.DataChannelConfig::new(label="async"),
      sample.monotonic(),
    )
    let offer = offerer.create_offer(sample.monotonic())
    offerer.set_local_description(offer, sample.monotonic())
    answerer.set_remote_description(offer, sample.monotonic())
    let answer = answerer.create_answer(sample.monotonic())
    answerer.set_local_description(answer, sample.monotonic())
    offerer.set_remote_description(answer, sample.monotonic())

    let (offerer_driver, offerer_handle, offerer_events, _) = @async.Driver::create(
      offerer,
    )
    let (answerer_driver, answerer_handle, answerer_events, answerer_messages) = @async.Driver::create(
      answerer,
    )
    @async_runtime.with_task_group <| group => {
      let offerer_task = group.spawn(() => offerer_driver.run())
      let answerer_task = group.spawn(() => answerer_driver.run())
      wait_for_open(offerer_events, channel)
      wait_for_open(answerer_events, channel)
      offerer_handle.send(
        DataChannel(
          channel_id=channel.id(),
          message=Text("real UDP async driver"),
        ),
      )
      assert_eq(
        answerer_messages.next(),
        Some(
          DataChannel(
            channel_id=channel.id(),
            message=Text("real UDP async driver"),
          ),
        ),
      )
      offerer_handle.close()
      answerer_handle.close()
      offerer_task.wait()
      answerer_task.wait()
    }
  }
}

///|
async test "async Drivers exchange a DataChannel message over real ICE TCP" {
  @async_runtime.with_timeout(60000) <| () => {
    let answerer_port = reserve_tcp_port()
    let loopback = @rtc.IpAddress::loopback_v4()
    let offerer_candidate = @ice.IceCandidate::tcp_host(
      foundation="offerer-tcp",
      @rtc.SocketAddress::new(address=loopback, port=0),
      tcp_type=Active,
    )
    let answerer_candidate = @ice.IceCandidate::tcp_host(
      foundation="answerer-tcp",
      @rtc.SocketAddress::new(address=loopback, port=answerer_port),
      tcp_type=Passive,
    )
    let sample = @async.sample_clock()
    let offerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[offerer_candidate]),
      sample,
    )
    let answerer = @rtc.PeerConnection::new(
      @rtc.Configuration::new(host_candidates=[answerer_candidate]),
      sample,
    )
    let channel = offerer.create_data_channel(
      @datachannel.DataChannelConfig::new(label="async-tcp"),
      sample.monotonic(),
    )
    let offer = offerer.create_offer(sample.monotonic())
    offerer.set_local_description(offer, sample.monotonic())
    answerer.set_remote_description(offer, sample.monotonic())
    let answer = answerer.create_answer(sample.monotonic())
    answerer.set_local_description(answer, sample.monotonic())
    offerer.set_remote_description(answer, sample.monotonic())

    let (offerer_driver, offerer_handle, offerer_events, _) = @async.Driver::create(
      offerer,
    )
    let (answerer_driver, answerer_handle, answerer_events, answerer_messages) = @async.Driver::create(
      answerer,
    )
    @async_runtime.with_task_group <| group => {
      let answerer_task = group.spawn(() => answerer_driver.run())
      @async_runtime.sleep(20)
      let offerer_task = group.spawn(() => offerer_driver.run())
      wait_for_open(offerer_events, channel)
      wait_for_open(answerer_events, channel)
      offerer_handle.send(
        DataChannel(
          channel_id=channel.id(),
          message=Text("real ICE TCP async driver"),
        ),
      )
      assert_eq(
        answerer_messages.next(),
        Some(
          DataChannel(
            channel_id=channel.id(),
            message=Text("real ICE TCP async driver"),
          ),
        ),
      )
      offerer_handle.close()
      answerer_handle.close()
      offerer_task.wait()
      answerer_task.wait()
    }
  }
}

///|
test "system clock samples are monotonic-compatible and wall-clock based" {
  let first = @async.sample_clock()
  let second = @async.sample_clock()
  assert_true(second.monotonic() >= first.monotonic())
  assert_true(first.wall().as_unix_nanoseconds() > 0L)
}
