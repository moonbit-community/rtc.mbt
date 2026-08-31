///|
fn is_ice_character(value : UInt16) -> Bool {
  (value >= 'a' && value <= 'z') ||
  (value >= 'A' && value <= 'Z') ||
  (value >= '0' && value <= '9') ||
  value == '+' ||
  value == '/'
}

///|
pub struct IceCredentials {
  username_fragment : String
  password : String
} derive(Debug, Eq)

///|
pub fn IceCredentials::new(
  username_fragment~ : String,
  password~ : String,
) -> IceCredentials raise IceError {
  if username_fragment.length() < 4 || username_fragment.length() > 256 {
    raise InvalidCredentials
  }
  if password.length() < 22 || password.length() > 256 {
    raise InvalidCredentials
  }
  for character in username_fragment.code_units() {
    if !is_ice_character(character) {
      raise InvalidCredentials
    }
  }
  for character in password.code_units() {
    if character < 0x21 || character > 0x7e {
      raise InvalidCredentials
    }
  }
  { username_fragment, password, }
}

///|
pub fn IceCredentials::username_fragment(self : IceCredentials) -> String {
  self.username_fragment
}

///|
pub fn IceCredentials::password(self : IceCredentials) -> String {
  self.password
}
