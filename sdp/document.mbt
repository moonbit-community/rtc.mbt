///|
pub struct SdpField {
  kind : Byte
  value : String
} derive(Debug, Eq)

///|
pub fn SdpField::new(kind~ : Byte, value~ : String) -> SdpField raise SdpError {
  if kind < b'a' || kind > b'z' {
    raise InvalidSyntax("SDP field kind must be a lowercase ASCII letter")
  }
  if value.contains("\r") || value.contains("\n") {
    raise InvalidSyntax("SDP field value contains a line break")
  }
  { kind, value, }
}

///|
pub fn SdpField::kind(self : SdpField) -> Byte {
  self.kind
}

///|
pub fn SdpField::value(self : SdpField) -> String {
  self.value
}

///|
fn SdpField::marshal(self : SdpField) -> String {
  String::from_array([self.kind.to_char()]) + "=" + self.value
}

///|
pub struct SdpAttribute {
  key : String
  value : String?
} derive(Debug, Eq)

///|
pub fn SdpAttribute::new(
  key~ : String,
  value? : String,
) -> SdpAttribute raise SdpError {
  if key.is_empty() ||
    key.contains(":") ||
    key.contains(" ") ||
    key.contains("\r") ||
    key.contains("\n") {
    raise InvalidSyntax("invalid SDP attribute key")
  }
  match value {
    Some(value) if value.contains("\r") || value.contains("\n") =>
      raise InvalidSyntax("SDP attribute value contains a line break")
    _ => ()
  }
  { key, value, }
}

///|
pub fn SdpAttribute::key(self : SdpAttribute) -> String {
  self.key
}

///|
pub fn SdpAttribute::value(self : SdpAttribute) -> String? {
  self.value
}

///|
fn SdpAttribute::parse(value : String) -> SdpAttribute raise SdpError {
  match value.split_once(":") {
    Some((key, value)) =>
      SdpAttribute::new(key=key.to_owned(), value=value.to_owned())
    None => SdpAttribute::new(key=value)
  }
}

///|
fn SdpAttribute::marshal(self : SdpAttribute) -> String {
  match self.value {
    Some(value) => self.key + ":" + value
    None => self.key
  }
}

///|
fn decimal_uint(value : StringView, context : String) -> UInt raise SdpError {
  @string.from_str(value) catch {
    _ => raise InvalidSyntax("invalid decimal \{context}")
  }
}

///|
fn decimal_uint64(
  value : StringView,
  context : String,
) -> UInt64 raise SdpError {
  @string.from_str(value) catch {
    _ => raise InvalidSyntax("invalid decimal \{context}")
  }
}

///|
fn space_tokens(value : String) -> Array[String] {
  value
  .split(" ")
  .filter(part => !part.is_empty())
  .map(part => part.to_owned())
  .to_array()
}

///|
pub struct MediaDescription {
  media_kind : String
  port : UInt16
  port_count : UInt16?
  protocol : String
  formats : Array[String]
  fields : Array[SdpField]
} derive(Debug, Eq)

///|
pub fn MediaDescription::new(
  media_kind~ : String,
  port~ : UInt16,
  port_count? : UInt16,
  protocol~ : String,
  formats~ : Array[String],
  fields? : Array[SdpField] = [],
) -> MediaDescription raise SdpError {
  if media_kind.is_empty() || protocol.is_empty() || formats.is_empty() {
    raise InvalidSyntax("SDP media line has an empty required token")
  }
  match port_count {
    Some(0) => raise InvalidSyntax("SDP media port count must be positive")
    _ => ()
  }
  {
    media_kind,
    port,
    port_count,
    protocol,
    formats: formats.copy(),
    fields: fields.copy(),
  }
}

///|
fn MediaDescription::parse(value : String) -> MediaDescription raise SdpError {
  let tokens = space_tokens(value)
  if tokens.length() < 4 {
    raise InvalidSyntax("SDP media line requires at least four tokens")
  }
  let port_tokens = tokens[1].split("/").to_array()
  if port_tokens.length() < 1 || port_tokens.length() > 2 {
    raise InvalidSyntax("invalid SDP media port")
  }
  let port = decimal_uint(port_tokens[0], "media port")
  if port > 0xffffU {
    raise InvalidSyntax("SDP media port exceeds 65535")
  }
  let port_count = if port_tokens.length() == 2 {
    let count = decimal_uint(port_tokens[1], "media port count")
    if count == 0U || count > 0xffffU {
      raise InvalidSyntax("invalid SDP media port count")
    }
    Some(count.to_uint16())
  } else {
    None
  }
  match port_count {
    Some(count) =>
      MediaDescription::new(
        media_kind=tokens[0],
        port=port.to_uint16(),
        port_count=count,
        protocol=tokens[2],
        formats=tokens[3:].to_owned(),
      )
    None =>
      MediaDescription::new(
        media_kind=tokens[0],
        port=port.to_uint16(),
        protocol=tokens[2],
        formats=tokens[3:].to_owned(),
      )
  }
}

///|
fn MediaDescription::marshal_media_line(self : MediaDescription) -> String {
  let port = match self.port_count {
    Some(count) => "\{self.port}/\{count}"
    None => self.port.to_string()
  }
  self.media_kind +
  " " +
  port +
  " " +
  self.protocol +
  " " +
  self.formats.join(" ")
}

///|
pub fn MediaDescription::media_kind(self : MediaDescription) -> String {
  self.media_kind
}

///|
pub fn MediaDescription::port(self : MediaDescription) -> UInt16 {
  self.port
}

///|
pub fn MediaDescription::port_count(self : MediaDescription) -> UInt16? {
  self.port_count
}

///|
pub fn MediaDescription::protocol(self : MediaDescription) -> String {
  self.protocol
}

///|
pub fn MediaDescription::formats(self : MediaDescription) -> Array[String] {
  self.formats.copy()
}

///|
pub fn MediaDescription::fields(self : MediaDescription) -> Array[SdpField] {
  self.fields.copy()
}

///|
pub fn MediaDescription::add_field(
  self : MediaDescription,
  field : SdpField,
) -> Unit {
  self.fields.push(field)
}

///|
pub fn MediaDescription::add_attribute(
  self : MediaDescription,
  attribute : SdpAttribute,
) -> Unit raise SdpError {
  self.fields.push(SdpField::new(kind=b'a', value=attribute.marshal()))
}

///|
pub fn MediaDescription::attributes(
  self : MediaDescription,
  key : String,
) -> Array[SdpAttribute] raise SdpError {
  let result : Array[SdpAttribute] = []
  for field in self.fields {
    if field.kind == b'a' {
      let attribute = SdpAttribute::parse(field.value)
      if attribute.key == key {
        result.push(attribute)
      }
    }
  }
  result
}

///|
pub fn MediaDescription::attribute(
  self : MediaDescription,
  key : String,
) -> SdpAttribute? raise SdpError {
  let attributes = self.attributes(key)
  if attributes.is_empty() {
    None
  } else {
    Some(attributes[0])
  }
}

///|
pub struct SdpDocument {
  session_fields : Array[SdpField]
  media_descriptions : Array[MediaDescription]
} derive(Debug, Eq)

///|
pub fn SdpDocument::new(
  session_fields~ : Array[SdpField],
  media_descriptions? : Array[MediaDescription] = [],
) -> SdpDocument raise SdpError {
  let document = {
    session_fields: session_fields.copy(),
    media_descriptions: media_descriptions.copy(),
  }
  document.validate()
  document
}

///|
fn SdpDocument::validate(self : SdpDocument) -> Unit raise SdpError {
  if self.session_fields.length() < 4 {
    raise InvalidSyntax("SDP is missing mandatory session fields")
  }
  if self.session_fields[0].kind != b'v' ||
    self.session_fields[1].kind != b'o' ||
    self.session_fields[2].kind != b's' {
    raise InvalidSyntax("SDP must begin with v=, o=, and s= fields")
  }
  if self.session_fields[0].value != "0" {
    raise InvalidSyntax("unsupported SDP version")
  }
  let mut versions = 0
  let mut origins = 0
  let mut names = 0
  let mut timings = 0
  for field in self.session_fields {
    match field.kind {
      b'v' => versions += 1
      b'o' => origins += 1
      b's' => names += 1
      b't' => timings += 1
      b'm' => raise InvalidSyntax("media field appears in session fields")
      _ => ()
    }
  }
  if versions != 1 || origins != 1 || names != 1 || timings < 1 {
    raise InvalidSyntax("invalid count of mandatory SDP session fields")
  }
  let origin = space_tokens(self.session_fields[1].value)
  if origin.length() != 6 {
    raise InvalidSyntax("SDP origin requires six tokens")
  }
  ignore(decimal_uint64(origin[1], "origin session id"))
  ignore(decimal_uint64(origin[2], "origin session version"))
}

///|
pub fn SdpDocument::parse(sdp : String) -> SdpDocument raise SdpError {
  if sdp.is_empty() {
    raise InvalidSyntax("SDP is empty")
  }
  let raw_lines = sdp.split("\n").to_array()
  let session_fields : Array[SdpField] = []
  let media_descriptions : Array[MediaDescription] = []
  let mut current_media : MediaDescription? = None
  for index = 0; index < raw_lines.length(); index = index + 1 {
    let raw = raw_lines[index]
    let line = if raw.has_suffix("\r") { raw[0:raw.length() - 1] } else { raw }
    if line.is_empty() {
      if index == raw_lines.length() - 1 {
        continue
      }
      raise InvalidSyntax("SDP contains an empty line")
    }
    if line.contains("\r") {
      raise InvalidSyntax("SDP contains a bare carriage return")
    }
    if line.length() < 2 || line[1] != '=' {
      raise InvalidSyntax("SDP line does not use the <type>=<value> form")
    }
    let kind = line[0].to_byte()
    let value = line[2:].to_owned()
    if kind == b'm' {
      let media = MediaDescription::parse(value)
      media_descriptions.push(media)
      current_media = Some(media)
    } else {
      let field = SdpField::new(kind~, value~)
      match current_media {
        Some(media) => media.fields.push(field)
        None => session_fields.push(field)
      }
    }
  }
  SdpDocument::new(session_fields~, media_descriptions~)
}

///|
pub fn SdpDocument::marshal(self : SdpDocument) -> String {
  let lines : Array[String] = []
  for field in self.session_fields {
    lines.push(field.marshal())
  }
  for media in self.media_descriptions {
    lines.push("m=" + media.marshal_media_line())
    for field in media.fields {
      lines.push(field.marshal())
    }
  }
  lines.join("\r\n") + "\r\n"
}

///|
pub fn SdpDocument::session_fields(self : SdpDocument) -> Array[SdpField] {
  self.session_fields.copy()
}

///|
pub fn SdpDocument::media_descriptions(
  self : SdpDocument,
) -> Array[MediaDescription] {
  self.media_descriptions.copy()
}

///|
pub fn SdpDocument::session_attributes(
  self : SdpDocument,
  key : String,
) -> Array[SdpAttribute] raise SdpError {
  let result : Array[SdpAttribute] = []
  for field in self.session_fields {
    if field.kind == b'a' {
      let attribute = SdpAttribute::parse(field.value)
      if attribute.key == key {
        result.push(attribute)
      }
    }
  }
  result
}

///|
pub fn SdpDocument::session_attribute(
  self : SdpDocument,
  key : String,
) -> SdpAttribute? raise SdpError {
  let attributes = self.session_attributes(key)
  if attributes.is_empty() {
    None
  } else {
    Some(attributes[0])
  }
}
