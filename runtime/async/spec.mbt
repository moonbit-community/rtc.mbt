///|
pub(all) suberror DriverError {
  Core(@rtc.RtcError)
  BackpressureExceeded
  Cancelled
  Closed
  Io(String)
} derive(Debug, Eq)

///|
/// The concrete driver and stream types are implemented in `driver.mbt`.
