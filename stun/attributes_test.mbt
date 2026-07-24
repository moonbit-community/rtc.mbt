///|
test "typed STUN errors and unknown attributes round-trip" {
  let role_conflict = ResponseError::with_default_reason(487)
  let encoded = Attribute::from_error(role_conflict)
  assert_eq(encoded.to_error(), role_conflict)
  assert_eq(encoded.value(), b"\x00\x00\x04\x57Role Conflict")
  let unknown = Attribute::from_unknown_attributes([0x0002, 0x1234, 0xffff])
  assert_eq(unknown.to_unknown_attributes(), [0x0002, 0x1234, 0xffff])
}

///|
test "STUN error responses retain request method and transaction id" {
  let request = Message::new(
    class=Request,
    stun_method=Binding,
    transaction_id=TransactionId::from_bytes(b"0123456789ab"),
  )
  let response = Message::error_response(
    request,
    ResponseError::with_default_reason(400),
  )
  assert_eq(response.class(), ErrorResponse)
  assert_eq(response.stun_method(), Binding)
  assert_eq(response.transaction_id(), request.transaction_id())
  guard response.first_attribute(ErrorCode) is Some(attribute) else {
    fail("missing ERROR-CODE")
  }
  assert_eq(attribute.to_error().code(), 400)
}

///|
test "ICE network cost and TURN integer attributes validate their domains" {
  let network_cost = Attribute::network_cost(7, 999)
  assert_eq(network_cost.as_network_cost(), (7, 999))
  assert_eq(Attribute::lifetime(600).as_u32(), 600U)
  assert_eq(Attribute::channel_number(0x4000).value(), b"\x40\x00\x00\x00")
  try Attribute::channel_number(0x3fff) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("invalid TURN channel number was accepted")
  }
}

///|
test "text and error attributes reject invalid UTF-8 and excessive input" {
  let invalid = Attribute::new(attribute_type=Username, value=b"\xff")
  try invalid.as_text() catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("invalid UTF-8 was accepted")
  }
  try Attribute::username("x".repeat(514)) catch {
    InvalidMessage(_) => ()
    _ => fail("unexpected STUN error")
  } noraise {
    _ => fail("oversized username was accepted")
  }
}
