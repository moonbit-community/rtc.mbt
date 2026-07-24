///|
async test "bounded output queues retain pending events and messages" {
  let sample = sample_clock()
  let core = @rtc.PeerConnection::new(
    @rtc.Configuration::new(event_capacity=1, message_capacity=1),
    sample,
  )
  let (driver, _, events, messages) = Driver::create(core)

  driver.pending_events.push(NegotiationNeeded)
  driver.pending_events.push(Closed)
  driver.drain_core_events()
  assert_true(driver.shared.output_blocked)
  assert_eq(driver.pending_events.length(), 1)
  guard events.next() is Some(NegotiationNeeded) else {
    fail("the first pending event was not delivered")
  }
  assert_eq(driver.shared.wakeups.try_get(), Some(()))

  driver.drain_core_events()
  assert_false(driver.shared.output_blocked)
  assert_true(driver.pending_events.is_empty())
  guard events.next() is Some(Closed) else {
    fail("the second pending event was not delivered")
  }

  let first : @rtc.RtcMessage = DataChannel(
    channel_id=StreamId(1),
    message=Text("first"),
  )
  let second : @rtc.RtcMessage = DataChannel(
    channel_id=StreamId(1),
    message=Text("second"),
  )
  driver.pending_messages.push(first)
  driver.pending_messages.push(second)
  driver.drain_core_events()
  assert_true(driver.shared.output_blocked)
  assert_eq(driver.pending_messages.length(), 1)
  assert_eq(messages.next(), Some(first))
  assert_eq(driver.shared.wakeups.try_get(), Some(()))

  driver.drain_core_events()
  assert_false(driver.shared.output_blocked)
  assert_true(driver.pending_messages.is_empty())
  assert_eq(messages.next(), Some(second))
}

///|
test "backpressure classifier distinguishes control from RTP ingress" {
  assert_false(is_control_datagram(b""))
  assert_true(is_control_datagram(b"\x00"))
  assert_true(is_control_datagram(b"\x16"))
  assert_true(is_control_datagram(b"\x40"))
  assert_true(is_control_datagram(b"\x80\xc9\x00\x01"))
  assert_false(is_control_datagram(b"\x80\x60\x00\x01"))
}

///|
async test "blocked output admits control while leaving app ingress queued" {
  let core = @rtc.PeerConnection::new(
    @rtc.Configuration::new(event_capacity=1),
    sample_clock(),
  )
  let (driver, _, _, _) = Driver::create(core)
  driver.pending_events.push(NegotiationNeeded)
  driver.pending_events.push(NegotiationNeeded)
  driver.drain_core_events()
  assert_true(driver.shared.output_blocked)
  let now = @rtc.Instant::from_milliseconds(0L)
  let address = @rtc.SocketAddress::new(
    address=@rtc.IpAddress::loopback_v4(),
    port=5000,
  )
  let control : @rtc.InboundDatagram = {
    now,
    context: { local_address: address, peer: address, ecn: None, protocol: Udp },
    payload: b"\x16",
  }
  put_network_input(driver.shared, Inbound(control))
  put_input(
    driver.shared,
    SendMessage(DataChannel(channel_id=StreamId(1), message=Text("deferred"))),
  )
  guard get_control_until_timeout(driver.shared, None, now, 1000)
    is Some(Inbound(selected)) else {
    fail("control ingress was not selected while output was blocked")
  }
  assert_eq(selected.payload, b"\x16")
  guard driver.shared.inputs.try_get() is Some(SendMessage(_)) else {
    fail("application ingress was not left queued")
  }
}

///|
async test "close remains independent while output is backpressured" {
  @async_runtime.with_timeout(1000) <| () => {
    let core = @rtc.PeerConnection::new(
      @rtc.Configuration::new(event_capacity=1),
      sample_clock(),
    )
    let (driver, handle, _, _) = Driver::create(core)
    driver.pending_events.push(NegotiationNeeded)
    driver.pending_events.push(NegotiationNeeded)
    @async_runtime.with_task_group <| group => {
      let task = group.spawn(() => {
        let result : Result[Unit, DriverError] = try {
          driver.run()
          Ok(())
        } catch {
          error => Err(error)
        }
        result
      })
      @async_runtime.sleep(10)
      handle.close()
      match task.wait() {
        Ok(_) => ()
        Err(Core(error)) =>
          match error {
            InvalidConfiguration(message) =>
              fail("close reported invalid configuration: " + message)
            InvalidState(message) =>
              fail("close reported invalid state: " + message)
            BackpressureExceeded => fail("close reported core backpressure")
            CryptoUnavailable(message) =>
              fail("close reported unavailable crypto: " + message)
            Closed => fail("close reported a closed core")
            _ => fail("close reported another core error")
          }
        Err(BackpressureExceeded) => fail("driver close reported backpressure")
        Err(Cancelled) => fail("driver close was cancelled")
        Err(Closed) => fail("driver closed before cleanup completed")
        Err(Io(message)) => fail("driver close reported I/O: " + message)
      }
    }
  }
}

///|
async test "sustained output backpressure closes with an explicit error" {
  @async_runtime.with_timeout(1000) <| () => {
    let core = @rtc.PeerConnection::new(
      @rtc.Configuration::new(event_capacity=1),
      sample_clock(),
    )
    let (driver, _, _, _) = create_driver(core, 20L)
    driver.pending_events.push(NegotiationNeeded)
    driver.pending_events.push(NegotiationNeeded)
    let outcome : Result[Unit, DriverError] = try {
      driver.run()
      Ok(())
    } catch {
      error => Err(error)
    }
    match outcome {
      Err(BackpressureExceeded) => ()
      Err(Core(_)) => fail("sustained backpressure reported a core error")
      Err(Cancelled) => fail("sustained backpressure was cancelled")
      Err(Closed) => fail("sustained backpressure reported closed")
      Err(Io(message)) =>
        fail("sustained backpressure reported I/O: " + message)
      Ok(_) => fail("sustained backpressure did not close the driver")
    }
  }
}
