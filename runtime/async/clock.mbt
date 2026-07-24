///|
extern "C" fn monotonic_milliseconds() -> Int64 = "moonbit_rtc_monotonic_milliseconds"

///|
extern "C" fn realtime_nanoseconds() -> Int64 = "moonbit_rtc_realtime_nanoseconds"

///|
pub fn sample_clock() -> @rtc.ClockSample raise DriverError {
  let monotonic = @rtc.Instant::from_milliseconds(monotonic_milliseconds()) catch {
    _ => raise Io("system monotonic clock returned an invalid value")
  }
  @rtc.ClockSample::new(
    monotonic~,
    wall=@rtc.WallTime::from_unix_nanoseconds(realtime_nanoseconds()),
  )
}

///|
fn driver_now() -> @rtc.Instant raise DriverError {
  @rtc.Instant::from_milliseconds(monotonic_milliseconds()) catch {
    _ => raise Io("system monotonic clock returned an invalid value")
  }
}
