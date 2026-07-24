///|
test "monotonic and wall clocks advance from the same sample" {
  let sample = @transport.ClockSample::new(
    monotonic=@transport.Instant::from_milliseconds(1000L),
    wall=@transport.WallTime::from_unix_nanoseconds(1700000000000000000L),
  )
  let clock = @transport.ManualClock::new(sample)
  clock.advance(@transport.Duration::milliseconds(250L))
  let advanced = clock.sample()
  inspect(advanced.monotonic().as_milliseconds(), content="1250")
  inspect(advanced.wall().as_unix_nanoseconds(), content="1700000000250000000")
}

///|
test "duration since saturates at zero" {
  let earlier = @transport.Instant::from_milliseconds(20L)
  let later = @transport.Instant::from_milliseconds(10L)
  inspect(
    later.saturating_duration_since(earlier).as_milliseconds(),
    content="0",
  )
}

///|
test "negative injected monotonic time is rejected" {
  try @transport.Instant::from_milliseconds(-1L) catch {
    NegativeMonotonicTime(value) => inspect(value, content="-1")
    NegativeDuration(_) | TimeOverflow => fail("unexpected error")
  } noraise {
    _ => fail("expected negative monotonic time to fail")
  }
}
