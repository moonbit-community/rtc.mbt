///|
struct NetworkTestFailure {
  role : String
  stage : String
  error : Error
}

///|
struct NetworkTestDiagnostics {
  transport : String
  started : Int64
  mut offerer_port : UInt16
  mut answerer_port : UInt16
  stages : Map[String, (String, Int64)]
  lines : Array[String]
  failures : Array[NetworkTestFailure]
  mut first_error : Error?
}

///|
fn NetworkTestDiagnostics::new(transport : String) -> NetworkTestDiagnostics {
  {
    transport,
    started: @async_runtime.now(),
    offerer_port: 0,
    answerer_port: 0,
    stages: {},
    lines: [],
    failures: [],
    first_error: None,
  }
}

///|
fn NetworkTestDiagnostics::stage(
  self : NetworkTestDiagnostics,
  role : String,
  stage : String,
) -> Unit {
  let now = @async_runtime.now()
  let elapsed = now - self.started
  if self.stages.get(role) is Some((previous, since)) {
    self.lines.push(
      "t=\{elapsed}ms role=\{role} completed=\{previous} duration=\{now - since}ms",
    )
  }
  self.stages[role] = (stage, now)
  self.lines.push("t=\{elapsed}ms role=\{role} stage=\{stage}")
}

///|
fn NetworkTestDiagnostics::record_error(
  self : NetworkTestDiagnostics,
  role : String,
  error : Error,
) -> Unit {
  // No suspension between checking and writing: async tasks share one event loop.
  if self.first_error is None {
    self.first_error = Some(error)
  }
  let now = @async_runtime.now()
  let (stage, since) = self.stages.get(role).unwrap_or(("setup", self.started))
  self.failures.push({ role, stage, error, })
  self.lines.push(
    "t=\{now - self.started}ms role=\{role} stage=\{stage} duration=\{now - since}ms error=\{error}",
  )
}

///|
async fn NetworkTestDiagnostics::run(
  self : NetworkTestDiagnostics,
  role : String,
  body : async () -> Unit,
) -> Unit {
  let outcome : Result[Unit?, Error] = Ok(
    @async_runtime.handle_cancellation(body),
  ) catch {
    error => Err(error)
  }
  // Record before the error reaches TaskGroup and cancels sibling tasks.
  match outcome {
    Ok(Some(_)) => ()
    Ok(None) => {
      let error : Error = @async.DriverError::Cancelled
      self.record_error(role, error)
      raise error
    }
    Err(error) => {
      self.record_error(role, error)
      raise error
    }
  }
}

///|
async fn NetworkTestDiagnostics::with_group(
  self : NetworkTestDiagnostics,
  body : async (@async_runtime.TaskGroup[Unit]) -> Unit,
  timeout_ms? : Int = 60000,
  report_failure? : Bool = true,
) -> Unit {
  try
    @async_runtime.with_task_group <| group => {
      self.stage("watchdog", "deadline")
      group.spawn_bg(no_wait=true) <| () => {
        // TimeoutError is read-only in async's public API. Let with_timeout
        // create it in this isolated watcher before cancelling our test group.
        // Normal group exit cancels the watcher without reporting a failure.
        let blocked : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
        let outcome : Result[Unit, Error] = try {
          @async_runtime.with_timeout(timeout_ms, () => blocked.get())
          Ok(())
        } catch {
          error => Err(error)
        }
        if outcome is Err(error) {
          self.record_error("watchdog", error)
          raise error
        }
      }
      self.run("test", () => body(group))
    }
  catch {
    error => {
      self.record_error("task-group", error)
      if report_failure {
        println(
          "network test failed: transport=\{self.transport} offerer_port=\{self.offerer_port} answerer_port=\{self.answerer_port}",
        )
        for line in self.lines {
          println(line)
        }
        for role, (stage, since) in self.stages {
          println(
            "role=\{role} last_stage=\{stage} duration=\{@async_runtime.now() - since}ms",
          )
        }
      }
      match self.first_error {
        Some(first) => raise first
        None => raise error
      }
    }
  }
}

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
  let diagnostics = NetworkTestDiagnostics::new("UDP")
  diagnostics.with_group() <| group => {
    diagnostics.stage("test", "reserve ports")
    let (offerer_port, answerer_port) = reserve_udp_ports()
    diagnostics.offerer_port = offerer_port
    diagnostics.answerer_port = answerer_port
    diagnostics.stage("test", "setup")
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
    diagnostics.stage("test", "negotiation")
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
    diagnostics.stage("test", "driver setup")
    diagnostics.stage("offerer", "driver run")
    let offerer_task = group.spawn(() => {
      diagnostics.run("offerer", () => offerer_driver.run())
    })
    diagnostics.stage("answerer", "driver run")
    let answerer_task = group.spawn(() => {
      diagnostics.run("answerer", () => answerer_driver.run())
    })
    diagnostics.stage("test", "offerer channel open")
    diagnostics.stage("offerer", "channel open")
    wait_for_open(offerer_events, channel)
    diagnostics.stage("test", "answerer channel open")
    diagnostics.stage("answerer", "channel open")
    wait_for_open(answerer_events, channel)
    diagnostics.stage("test", "send")
    diagnostics.stage("offerer", "send")
    offerer_handle.send(
      DataChannel(
        channel_id=channel.id(),
        message=Text("real UDP async driver"),
      ),
    )
    diagnostics.stage("test", "receive")
    diagnostics.stage("answerer", "receive")
    assert_eq(
      answerer_messages.next(),
      Some(
        DataChannel(
          channel_id=channel.id(),
          message=Text("real UDP async driver"),
        ),
      ),
    )
    diagnostics.stage("test", "close")
    diagnostics.stage("offerer", "close")
    offerer_handle.close()
    diagnostics.stage("answerer", "close")
    answerer_handle.close()
    diagnostics.stage("test", "offerer exit")
    diagnostics.stage("offerer", "wait for exit")
    offerer_task.wait()
    diagnostics.stage("offerer", "exited")
    diagnostics.stage("test", "answerer exit")
    diagnostics.stage("answerer", "wait for exit")
    answerer_task.wait()
    diagnostics.stage("answerer", "exited")
    diagnostics.stage("test", "done")
  }
}

///|
async test "async Drivers exchange a DataChannel message over real ICE TCP" {
  let diagnostics = NetworkTestDiagnostics::new("ICE TCP")
  diagnostics.with_group() <| group => {
    diagnostics.stage("test", "reserve ports")
    let answerer_port = reserve_tcp_port()
    diagnostics.answerer_port = answerer_port
    diagnostics.stage("test", "setup")
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
    diagnostics.stage("test", "negotiation")
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
    diagnostics.stage("test", "driver setup")
    diagnostics.stage("answerer", "driver run")
    let answerer_task = group.spawn(() => {
      diagnostics.run("answerer", () => answerer_driver.run())
    })
    diagnostics.stage("test", "listener startup delay")
    @async_runtime.sleep(20)
    diagnostics.stage("offerer", "driver run")
    let offerer_task = group.spawn(() => {
      diagnostics.run("offerer", () => offerer_driver.run())
    })
    diagnostics.stage("test", "offerer channel open")
    diagnostics.stage("offerer", "channel open")
    wait_for_open(offerer_events, channel)
    diagnostics.stage("test", "answerer channel open")
    diagnostics.stage("answerer", "channel open")
    wait_for_open(answerer_events, channel)
    diagnostics.stage("test", "send")
    diagnostics.stage("offerer", "send")
    offerer_handle.send(
      DataChannel(
        channel_id=channel.id(),
        message=Text("real ICE TCP async driver"),
      ),
    )
    diagnostics.stage("test", "receive")
    diagnostics.stage("answerer", "receive")
    assert_eq(
      answerer_messages.next(),
      Some(
        DataChannel(
          channel_id=channel.id(),
          message=Text("real ICE TCP async driver"),
        ),
      ),
    )
    diagnostics.stage("test", "close")
    diagnostics.stage("offerer", "close")
    offerer_handle.close()
    diagnostics.stage("answerer", "close")
    answerer_handle.close()
    diagnostics.stage("test", "offerer exit")
    diagnostics.stage("offerer", "wait for exit")
    offerer_task.wait()
    diagnostics.stage("offerer", "exited")
    diagnostics.stage("test", "answerer exit")
    diagnostics.stage("answerer", "wait for exit")
    answerer_task.wait()
    diagnostics.stage("answerer", "exited")
    diagnostics.stage("test", "done")
  }
}

///|
async test "network diagnostics retain the first task error after sibling cancellation" {
  let diagnostics = NetworkTestDiagnostics::new("regression")
  let ready : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let blocked : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let outcome : Result[Unit, Error] = try {
    diagnostics.with_group(report_failure=false) <| group => {
      diagnostics.stage("offerer", "send")
      group.spawn_bg(() => {
        diagnostics.run("offerer", () => {
          ready.get()
          raise @async.DriverError::Io("original task failure")
        })
      })
      diagnostics.stage("answerer", "receive")
      group.spawn_bg(() => {
        diagnostics.run("answerer", () => {
          ready.put(())
          blocked.get()
        })
      })
      diagnostics.stage("test", "wait for tasks")
      blocked.get()
    }
    Ok(())
  } catch {
    error => Err(error)
  }
  match outcome {
    Err(@async.DriverError::Io(message)) =>
      assert_eq(message, "original task failure")
    _ => fail("the original task error was replaced")
  }
  let first = diagnostics.failures[0]
  assert_eq(first.role, "offerer")
  assert_eq(first.stage, "send")
  assert_true(first.error is @async.DriverError::Io(_))
  assert_true(
    diagnostics.failures
    .iter()
    .any(failure => {
      failure.role == "answerer" &&
      failure.stage == "receive" &&
      failure.error is @async.DriverError::Cancelled
    }),
  )
  assert_true(
    diagnostics.failures
    .iter()
    .any(failure => {
      failure.role == "test" && failure.error is @async.DriverError::Cancelled
    }),
  )
}

///|
async test "network diagnostics retain TimeoutError after task cancellation" {
  let diagnostics = NetworkTestDiagnostics::new("regression")
  let ready : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let blocked : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let outcome : Result[Unit, Error] = try {
    diagnostics.with_group(timeout_ms=20, report_failure=false) <| group => {
      diagnostics.stage("answerer", "receive")
      group.spawn_bg(() => {
        diagnostics.run("answerer", () => {
          ready.put(())
          blocked.get()
        })
      })
      ready.get()
      diagnostics.stage("test", "receive")
      blocked.get()
    }
    Ok(())
  } catch {
    error => Err(error)
  }
  assert_true(outcome is Err(@async_runtime.TimeoutError))
  let first = diagnostics.failures[0]
  assert_eq(first.role, "watchdog")
  assert_eq(first.stage, "deadline")
  assert_true(first.error is @async_runtime.TimeoutError)
  assert_true(
    diagnostics.failures
    .iter()
    .any(failure => {
      failure.role == "answerer" &&
      failure.error is @async.DriverError::Cancelled
    }),
  )
  assert_true(
    diagnostics.failures
    .iter()
    .any(failure => {
      failure.role == "test" && failure.error is @async.DriverError::Cancelled
    }),
  )
}

///|
async test "network diagnostics retain a test body error before cancellation" {
  let diagnostics = NetworkTestDiagnostics::new("regression")
  let ready : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let blocked : @async_runtime.Queue[Unit] = Queue(kind=Unbounded)
  let outcome : Result[Unit, Error] = try {
    diagnostics.with_group(report_failure=false) <| group => {
      diagnostics.stage("offerer", "driver run")
      group.spawn_bg(() => {
        diagnostics.run("offerer", () => {
          ready.put(())
          blocked.get()
        })
      })
      ready.get()
      diagnostics.stage("test", "send")
      raise @async.DriverError::Io("original body failure")
    }
    Ok(())
  } catch {
    error => Err(error)
  }
  match outcome {
    Err(@async.DriverError::Io(message)) =>
      assert_eq(message, "original body failure")
    _ => fail("the original body error was replaced")
  }
  assert_eq(diagnostics.failures[0].role, "test")
  assert_eq(diagnostics.failures[0].stage, "send")
  assert_true(
    diagnostics.failures
    .iter()
    .any(failure => {
      failure.role == "offerer" &&
      failure.error is @async.DriverError::Cancelled
    }),
  )
}

///|
async test "network diagnostics cancel the watchdog silently on success" {
  let diagnostics = NetworkTestDiagnostics::new("regression")
  diagnostics.with_group() <| _ => { diagnostics.stage("test", "done") }
  assert_true(diagnostics.first_error is None)
  assert_true(diagnostics.failures.is_empty())
}

///|
test "system clock samples are monotonic-compatible and wall-clock based" {
  let first = @async.sample_clock()
  let second = @async.sample_clock()
  assert_true(second.monotonic() >= first.monotonic())
  assert_true(first.wall().as_unix_nanoseconds() > 0L)
}
