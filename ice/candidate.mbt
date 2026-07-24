///|
pub fn CandidateType::preference(self : CandidateType) -> UInt16 {
  match self {
    Host => 126
    PeerReflexive => 110
    ServerReflexive => 100
    Relay => 0
  }
}

///|
pub fn CandidateType::to_string(self : CandidateType) -> String {
  match self {
    Host => "host"
    ServerReflexive => "srflx"
    PeerReflexive => "prflx"
    Relay => "relay"
  }
}

///|
fn CandidateType::parse(value : String) -> CandidateType raise IceError {
  match value.to_lower() {
    "host" => Host
    "srflx" => ServerReflexive
    "prflx" => PeerReflexive
    "relay" => Relay
    _ => raise InvalidCandidate("unknown ICE candidate type")
  }
}

///|
pub fn TcpCandidateType::to_string(self : TcpCandidateType) -> String {
  match self {
    Active => "active"
    Passive => "passive"
    SimultaneousOpen => "so"
  }
}

///|
fn TcpCandidateType::parse(value : String) -> TcpCandidateType raise IceError {
  match value.to_lower() {
    "active" => Active
    "passive" => Passive
    "so" => SimultaneousOpen
    _ => raise InvalidCandidate("unknown ICE TCP candidate type")
  }
}

///|
fn valid_mdns_name(value : String) -> Bool {
  if value.length() > 253 ||
    value.is_empty() ||
    !value.to_lower().has_suffix(".local") {
    return false
  }
  for character in value.code_units() {
    if !((character >= 'a' && character <= 'z') ||
      (character >= 'A' && character <= 'Z') ||
      (character >= '0' && character <= '9') ||
      character == '-' ||
      character == '.') {
      return false
    }
  }
  true
}

///|
pub fn CandidateAddress::parse(
  value : String,
) -> CandidateAddress raise IceError {
  if value.to_lower().has_suffix(".local") {
    if !valid_mdns_name(value) {
      raise InvalidCandidate("invalid mDNS candidate name")
    }
    return MdnsName(value.to_lower())
  }
  let address = @transport.IpAddress::parse(value) catch {
    InvalidIpv6Length(_) | InvalidAddress(_) =>
      raise InvalidCandidate("invalid ICE candidate IP address")
  }
  IpAddress(address)
}

///|
pub fn CandidateAddress::to_string(self : CandidateAddress) -> String {
  match self {
    IpAddress(address) => address.to_string()
    MdnsName(name) => name
  }
}

///|
fn validate_token(value : String, context : String) -> Unit raise IceError {
  if value.is_empty() ||
    value.contains(" ") ||
    value.contains("\r") ||
    value.contains("\n") {
    raise InvalidCandidate("invalid ICE \{context}")
  }
}

///|
pub fn IceCandidate::new(
  foundation~ : String,
  component~ : UInt16,
  protocol~ : @transport.TransportProtocol,
  priority~ : UInt,
  address~ : CandidateAddress,
  port~ : UInt16,
  candidate_type~ : CandidateType,
  related_address? : CandidateAddress,
  related_port? : UInt16,
  tcp_type? : TcpCandidateType,
  extensions? : Array[(String, String)] = [],
) -> IceCandidate raise IceError {
  validate_token(foundation, "foundation")
  if component == 0 {
    raise InvalidCandidate("ICE component must be nonzero")
  }
  match address {
    MdnsName(name) if !valid_mdns_name(name) =>
      raise InvalidCandidate("invalid mDNS candidate name")
    _ => ()
  }
  match (protocol, tcp_type) {
    (Udp, Some(_)) =>
      raise InvalidCandidate("UDP candidate cannot have tcptype")
    (Tcp, None) => raise InvalidCandidate("TCP candidate requires tcptype")
    _ => ()
  }
  if port == 0 && !(protocol == Tcp && tcp_type == Some(Active)) {
    raise InvalidCandidate("ICE candidate port must be nonzero")
  }
  match (related_address, related_port) {
    (Some(_), None) | (None, Some(_)) =>
      raise InvalidCandidate(
        "related ICE address and port must appear together",
      )
    _ => ()
  }
  for extension in extensions {
    let (key, value) = extension
    validate_token(key, "extension key")
    validate_token(value, "extension value")
  }
  {
    foundation,
    component,
    protocol,
    priority,
    address,
    port,
    candidate_type,
    related_address,
    related_port,
    tcp_type,
    extensions: extensions.copy(),
  }
}

///|
pub fn IceCandidate::host(
  foundation~ : String,
  address : @transport.SocketAddress,
  local_preference? : UInt16 = 65535,
) -> IceCandidate raise IceError {
  IceCandidate::new(
    foundation~,
    component=1,
    protocol=Udp,
    priority=IceCandidate::priority_value(
      candidate_type=Host,
      local_preference~,
      component=1,
    ),
    address=IpAddress(address.address()),
    port=address.port(),
    candidate_type=Host,
  )
}

///|
pub fn IceCandidate::tcp_host(
  foundation~ : String,
  address : @transport.SocketAddress,
  tcp_type~ : TcpCandidateType,
  local_preference? : UInt16 = 65535,
) -> IceCandidate raise IceError {
  if tcp_type == Active && address.port() != 0 {
    raise InvalidCandidate("active ICE TCP host candidate must use port zero")
  }
  if tcp_type != Active && address.port() == 0 {
    raise InvalidCandidate(
      "passive ICE TCP host candidate requires a listening port",
    )
  }
  IceCandidate::new(
    foundation~,
    component=1,
    protocol=Tcp,
    priority=IceCandidate::priority_value(
      candidate_type=Host,
      local_preference~,
      component=1,
    ),
    address=IpAddress(address.address()),
    port=address.port(),
    candidate_type=Host,
    tcp_type~,
  )
}

///|
pub fn IceCandidate::priority_value(
  candidate_type~ : CandidateType,
  local_preference~ : UInt16,
  component~ : UInt16,
) -> UInt raise IceError {
  if component == 0 || component > 256 {
    raise InvalidCandidate("ICE component must be between 1 and 256")
  }
  (candidate_type.preference().to_uint() << 24) |
  (local_preference.to_uint() << 8) |
  (256U - component.to_uint())
}

///|
fn parse_uint64(value : String, context : String) -> UInt64 raise IceError {
  @strconv.from_str(value) catch {
    _ => raise InvalidCandidate("invalid ICE \{context}")
  }
}

///|
pub fn IceCandidate::parse(value : String) -> IceCandidate raise IceError {
  let value = match value.strip_prefix("candidate:") {
    Some(stripped) => stripped.to_owned()
    None => value
  }
  let tokens = value
    .split(" ")
    .filter(token => !token.is_empty())
    .map(token => token.to_owned())
    .to_array()
  if tokens.length() < 8 || tokens[6].to_lower() != "typ" {
    raise InvalidCandidate(
      "ICE candidate requires foundation, component, transport, priority, address, port, and type",
    )
  }
  let component = parse_uint64(tokens[1], "component")
  if component == 0UL || component > 0xffffUL {
    raise InvalidCandidate("ICE component is out of range")
  }
  let protocol : @transport.TransportProtocol = match tokens[2].to_lower() {
    "udp" => Udp
    "tcp" => Tcp
    _ => raise InvalidCandidate("unknown ICE transport protocol")
  }
  let priority = parse_uint64(tokens[3], "priority")
  if priority > 0xffffffffUL {
    raise InvalidCandidate("ICE priority is out of range")
  }
  let port = parse_uint64(tokens[5], "port")
  if port > 0xffffUL {
    raise InvalidCandidate("ICE port is out of range")
  }
  let candidate_type = CandidateType::parse(tokens[7])
  let mut related_address : CandidateAddress? = None
  let mut related_port : UInt16? = None
  let mut tcp_type : TcpCandidateType? = None
  let extensions : Array[(String, String)] = []
  if (tokens.length() - 8) % 2 != 0 {
    raise InvalidCandidate("ICE candidate extensions must be key-value pairs")
  }
  for index = 8; index < tokens.length(); index = index + 2 {
    let key = tokens[index].to_lower()
    let extension_value = tokens[index + 1]
    match key {
      "raddr" => {
        if related_address is Some(_) {
          raise InvalidCandidate("duplicate ICE related address")
        }
        related_address = Some(CandidateAddress::parse(extension_value))
      }
      "rport" => {
        if related_port is Some(_) {
          raise InvalidCandidate("duplicate ICE related port")
        }
        let parsed = parse_uint64(extension_value, "related port")
        if parsed > 0xffffUL {
          raise InvalidCandidate("ICE related port is out of range")
        }
        related_port = Some(parsed.to_uint16())
      }
      "tcptype" => {
        if tcp_type is Some(_) {
          raise InvalidCandidate("duplicate ICE TCP type")
        }
        tcp_type = Some(TcpCandidateType::parse(extension_value))
      }
      _ => extensions.push((tokens[index], extension_value))
    }
  }
  IceCandidate::new(
    foundation=tokens[0],
    component=component.to_uint16(),
    protocol~,
    priority=priority.to_uint(),
    address=CandidateAddress::parse(tokens[4]),
    port=port.to_uint16(),
    candidate_type~,
    related_address?,
    related_port?,
    tcp_type?,
    extensions~,
  )
}

///|
pub fn IceCandidate::foundation(self : IceCandidate) -> String {
  self.foundation
}

///|
pub fn IceCandidate::component(self : IceCandidate) -> UInt16 {
  self.component
}

///|
pub fn IceCandidate::protocol(
  self : IceCandidate,
) -> @transport.TransportProtocol {
  self.protocol
}

///|
pub fn IceCandidate::priority(self : IceCandidate) -> UInt {
  self.priority
}

///|
pub fn IceCandidate::address(self : IceCandidate) -> CandidateAddress {
  self.address
}

///|
pub fn IceCandidate::port(self : IceCandidate) -> UInt16 {
  self.port
}

///|
pub fn IceCandidate::candidate_type(self : IceCandidate) -> CandidateType {
  self.candidate_type
}

///|
pub fn IceCandidate::related_address(self : IceCandidate) -> CandidateAddress? {
  self.related_address
}

///|
pub fn IceCandidate::related_port(self : IceCandidate) -> UInt16? {
  self.related_port
}

///|
pub fn IceCandidate::tcp_type(self : IceCandidate) -> TcpCandidateType? {
  self.tcp_type
}

///|
pub fn IceCandidate::extensions(self : IceCandidate) -> Array[(String, String)] {
  self.extensions.copy()
}

///|
pub fn IceCandidate::marshal(self : IceCandidate) -> String {
  let protocol = match self.protocol {
    Udp => "udp"
    Tcp => "tcp"
  }
  let mut result = self.foundation +
    " " +
    self.component.to_string() +
    " " +
    protocol +
    " " +
    self.priority.to_string() +
    " " +
    self.address.to_string() +
    " " +
    self.port.to_string() +
    " typ " +
    self.candidate_type.to_string()
  match (self.related_address, self.related_port) {
    (Some(address), Some(port)) =>
      result = result +
        " raddr " +
        address.to_string() +
        " rport " +
        port.to_string()
    _ => ()
  }
  match self.tcp_type {
    Some(tcp_type) => result = result + " tcptype " + tcp_type.to_string()
    None => ()
  }
  for extension in self.extensions {
    let (key, value) = extension
    result = result + " " + key + " " + value
  }
  result
}

///|
pub fn IceCandidate::to_sdp_attribute(self : IceCandidate) -> String {
  "candidate:" + self.marshal()
}

///|
pub fn IceCandidate::socket_address(
  self : IceCandidate,
) -> @transport.SocketAddress? {
  match self.address {
    IpAddress(address) =>
      Some(@transport.SocketAddress::new(address~, port=self.port))
    MdnsName(_) => None
  }
}

///|
pub fn IceCandidate::base_socket_address(
  self : IceCandidate,
) -> @transport.SocketAddress? {
  match self.candidate_type {
    ServerReflexive =>
      match (self.related_address, self.related_port) {
        (Some(IpAddress(address)), Some(port)) =>
          Some(@transport.SocketAddress::new(address~, port~))
        _ => self.socket_address()
      }
    Host | PeerReflexive | Relay => self.socket_address()
  }
}

///|
pub fn IceCandidate::resolve_mdns(
  self : IceCandidate,
  address : @transport.IpAddress,
) -> IceCandidate raise IceError {
  guard self.address is MdnsName(_) else {
    raise InvalidCandidate("candidate does not contain an mDNS name")
  }
  let related_address = self.related_address
  let related_port = self.related_port
  let tcp_type = self.tcp_type
  IceCandidate::new(
    foundation=self.foundation,
    component=self.component,
    protocol=self.protocol,
    priority=self.priority,
    address=IpAddress(address),
    port=self.port,
    candidate_type=self.candidate_type,
    related_address?,
    related_port?,
    tcp_type?,
    extensions=self.extensions,
  )
}

///|
pub fn IceCandidate::with_mdns_name(
  self : IceCandidate,
  name : String,
) -> IceCandidate raise IceError {
  if self.candidate_type != Host || self.protocol != Udp {
    raise InvalidCandidate(
      "only UDP host candidates can be advertised through mDNS",
    )
  }
  let related_address = self.related_address
  let related_port = self.related_port
  let tcp_type = self.tcp_type
  IceCandidate::new(
    foundation=self.foundation,
    component=self.component,
    protocol=self.protocol,
    priority=self.priority,
    address=CandidateAddress::parse(name),
    port=self.port,
    candidate_type=self.candidate_type,
    related_address?,
    related_port?,
    tcp_type?,
    extensions=self.extensions,
  )
}
