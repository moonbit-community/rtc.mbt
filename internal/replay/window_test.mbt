///|
test "replay window accepts new and unseen out-of-order packets" {
  let window = @replay.ReplayWindow::new(width=8)
  debug_inspect(window.check_and_mark(10UL), content="AcceptedNew")
  debug_inspect(window.check_and_mark(12UL), content="AcceptedNew")
  debug_inspect(window.check_and_mark(11UL), content="AcceptedOutOfOrder")
  debug_inspect(window.check_and_mark(11UL), content="Duplicate")
  debug_inspect(window.highest(), content="Some(12)")
}

///|
test "replay window rejects values outside the configured history" {
  let window = @replay.ReplayWindow::new(width=4)
  ignore(window.check_and_mark(100UL))
  debug_inspect(window.check_and_mark(96UL), content="TooOld")
  debug_inspect(window.check_and_mark(97UL), content="AcceptedOutOfOrder")
}

///|
test "large jumps discard the prior bitmap" {
  let window = @replay.ReplayWindow::new()
  ignore(window.check_and_mark(1UL))
  ignore(window.check_and_mark(100UL))
  debug_inspect(window.check_and_mark(1UL), content="TooOld")
  debug_inspect(window.check_and_mark(99UL), content="AcceptedOutOfOrder")
}
