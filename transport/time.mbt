///|
pub(all) suberror TimeError {
  NegativeMonotonicTime(Int64)
  NegativeDuration(Int64)
  TimeOverflow
} derive(Debug, Eq)

///|
pub struct Duration(Int64) derive(Debug, Eq, Compare)

///|
pub fn Duration::milliseconds(value : Int64) -> Duration raise TimeError {
  if value < 0L {
    raise NegativeDuration(value)
  }
  Duration(value)
}

///|
pub fn Duration::zero() -> Duration {
  Duration(0L)
}

///|
pub fn Duration::as_milliseconds(self : Duration) -> Int64 {
  self.0
}

///|
pub struct Instant(Int64) derive(Debug, Eq, Compare)

///|
pub fn Instant::from_milliseconds(value : Int64) -> Instant raise TimeError {
  if value < 0L {
    raise NegativeMonotonicTime(value)
  }
  Instant(value)
}

///|
pub fn Instant::as_milliseconds(self : Instant) -> Int64 {
  self.0
}

///|
pub fn Instant::checked_add(
  self : Instant,
  duration : Duration,
) -> Instant raise TimeError {
  let max_int64 = 9223372036854775807L
  if self.0 > max_int64 - duration.0 {
    raise TimeOverflow
  }
  Instant(self.0 + duration.0)
}

///|
pub fn Instant::saturating_duration_since(
  self : Instant,
  earlier : Instant,
) -> Duration {
  if self.0 <= earlier.0 {
    Duration::zero()
  } else {
    Duration(self.0 - earlier.0)
  }
}

///|
pub struct WallTime(Int64) derive(Debug, Eq, Compare)

///|
pub fn WallTime::from_unix_nanoseconds(value : Int64) -> WallTime {
  WallTime(value)
}

///|
pub fn WallTime::as_unix_nanoseconds(self : WallTime) -> Int64 {
  self.0
}

///|
pub struct ClockSample {
  monotonic : Instant
  wall : WallTime
} derive(Debug, Eq)

///|
pub fn ClockSample::new(monotonic~ : Instant, wall~ : WallTime) -> ClockSample {
  { monotonic, wall, }
}

///|
pub fn ClockSample::monotonic(self : ClockSample) -> Instant {
  self.monotonic
}

///|
pub fn ClockSample::wall(self : ClockSample) -> WallTime {
  self.wall
}

///|
pub fn ClockSample::wall_at(
  self : ClockSample,
  instant : Instant,
) -> WallTime raise TimeError {
  let max_int64 = 9223372036854775807L
  let min_int64 = -9223372036854775807L - 1L
  let max_delta_ms = 9223372036854L
  let delta_ms = instant.0 - self.monotonic.0
  if delta_ms > max_delta_ms || delta_ms < -max_delta_ms {
    raise TimeOverflow
  }
  let delta_ns = delta_ms * 1000000L
  if delta_ns > 0L && self.wall.0 > max_int64 - delta_ns {
    raise TimeOverflow
  }
  if delta_ns < 0L && self.wall.0 < min_int64 - delta_ns {
    raise TimeOverflow
  }
  WallTime(self.wall.0 + delta_ns)
}

///|
pub struct ManualClock {
  mut monotonic : Instant
  mut wall : WallTime
}

///|
pub fn ManualClock::new(sample : ClockSample) -> ManualClock {
  { monotonic: sample.monotonic, wall: sample.wall, }
}

///|
pub fn ManualClock::sample(self : ManualClock) -> ClockSample {
  ClockSample::new(monotonic=self.monotonic, wall=self.wall)
}

///|
pub fn ManualClock::advance(
  self : ManualClock,
  duration : Duration,
) -> Unit raise TimeError {
  let next_monotonic = self.monotonic.checked_add(duration)
  let sample = ClockSample::new(monotonic=self.monotonic, wall=self.wall)
  let next_wall = sample.wall_at(next_monotonic)
  self.monotonic = next_monotonic
  self.wall = next_wall
}
