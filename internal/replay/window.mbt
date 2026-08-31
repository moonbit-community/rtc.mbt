///|
pub(all) suberror ReplayWindowError {
  InvalidWidth(Int)
} derive(Debug, Eq)

///|
pub(all) enum ReplayDecision {
  AcceptedNew
  AcceptedOutOfOrder
  Duplicate
  TooOld
} derive(Debug, Eq)

///|
pub struct ReplayWindow {
  width : Int
  mut initialized : Bool
  mut max_sequence : UInt64
  mut bitmap : UInt64
}

///|
pub fn ReplayWindow::new(
  width? : Int = 64,
) -> ReplayWindow raise ReplayWindowError {
  if width < 1 || width > 64 {
    raise InvalidWidth(width)
  }
  { width, initialized: false, max_sequence: 0UL, bitmap: 0UL, }
}

///|
pub fn ReplayWindow::check_and_mark(
  self : ReplayWindow,
  sequence : UInt64,
) -> ReplayDecision {
  if !self.initialized {
    self.initialized = true
    self.max_sequence = sequence
    self.bitmap = 1UL
    return AcceptedNew
  }
  let width = self.width.to_int64().reinterpret_as_uint64()
  if sequence > self.max_sequence {
    let delta = sequence - self.max_sequence
    if delta >= width {
      self.bitmap = 1UL
    } else {
      self.bitmap = (self.bitmap << delta.to_int()) | 1UL
    }
    self.max_sequence = sequence
    return AcceptedNew
  }
  let distance = self.max_sequence - sequence
  if distance >= width {
    return TooOld
  }
  let mask = 1UL << distance.to_int()
  if (self.bitmap & mask) != 0UL {
    Duplicate
  } else {
    self.bitmap = self.bitmap | mask
    AcceptedOutOfOrder
  }
}

///|
pub fn ReplayWindow::highest(self : ReplayWindow) -> UInt64? {
  if self.initialized {
    Some(self.max_sequence)
  } else {
    None
  }
}
