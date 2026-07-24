///|
priv suberror DriverStopping

///|
priv suberror StreamEnded

///|
priv suberror StreamFailed {
  StreamFailed(DriverError)
}

///|
priv enum DriverInput {
  SendMessage(@rtc.RtcMessage)
  CloseDataChannel(@rtc.DataChannel)
  Inbound(@rtc.InboundDatagram)
  CoreIo(@rtc.IoEvent)
  OutputDrained
}

///|
struct Shared {
  inputs : @async_runtime.Queue[DriverInput]
  control_inputs : @async_runtime.Queue[DriverInput]
  wakeups : @async_runtime.Queue[Unit]
  close_requests : @async_runtime.Queue[Unit]
  events : @async_runtime.Queue[@rtc.PeerEvent]
  messages : @async_runtime.Queue[@rtc.RtcMessage]
  mut run_started : Bool
  mut closing : Bool
  mut terminated : Bool
  mut output_blocked : Bool
  mut output_blocked_since : @rtc.Instant?
  mut prefer_control_input : Bool
  backpressure_timeout_ms : Int64
}

///|
pub struct Driver {
  core : @rtc.PeerConnection
  shared : Shared
  receive_mtu : Int
  pending_events : Array[@rtc.PeerEvent]
  pending_messages : Array[@rtc.RtcMessage]
}

///|
pub struct PeerHandle {
  shared : Shared
}

///|
pub struct EventStream {
  shared : Shared
}

///|
pub struct MessageStream {
  shared : Shared
}

///|
priv struct BoundSocket {
  local_address : @rtc.SocketAddress
  socket : @socket.UdpServer
}

///|
priv enum DriverStream {
  Plain(@socket.Tcp)
  Secure(@tls.Tls, @socket.Tcp)
}

///|
priv struct BoundStream {
  connection : @rtc.ConnectionId
  stream : DriverStream
}

///|
priv struct BoundListener {
  listener : @rtc.ListenerId
  local_address : @rtc.SocketAddress
  server : @socket.TcpServer
}

///|
priv struct StreamRuntime {
  streams : Array[BoundStream]
  listeners : Array[BoundListener]
  pending_connections : Array[@rtc.ConnectionId]
  mut next_accepted_connection : UInt64
}

///|
fn StreamRuntime::new() -> StreamRuntime {
  {
    streams: [],
    listeners: [],
    pending_connections: [],
    next_accepted_connection: 0x8000000000000000UL,
  }
}

///|
fn DriverStream::close(self : DriverStream) -> Unit {
  match self {
    Plain(socket) => socket.close()
    Secure(tls, socket) => {
      tls.close()
      socket.close()
    }
  }
}

///|
async fn DriverStream::read_some(self : DriverStream) -> Bytes? {
  match self {
    Plain(socket) => socket.read_some(max_len=65536)
    Secure(tls, _) => tls.read_some(max_len=65536)
  }
}

///|
async fn DriverStream::write(self : DriverStream, bytes : Bytes) -> Unit {
  match self {
    Plain(socket) => socket.write(bytes)
    Secure(tls, _) => tls.write(bytes)
  }
}

///|
fn StreamRuntime::stream(
  self : StreamRuntime,
  connection : @rtc.ConnectionId,
) -> BoundStream? {
  for stream in self.streams {
    if stream.connection == connection {
      return Some(stream)
    }
  }
  None
}

///|
fn StreamRuntime::has_listener(
  self : StreamRuntime,
  listener : @rtc.ListenerId,
) -> Bool {
  self.listeners.any(bound => bound.listener == listener)
}

///|
fn StreamRuntime::begin_connection(
  self : StreamRuntime,
  connection : @rtc.ConnectionId,
) -> Bool {
  if self.stream(connection) is Some(_) ||
    self.pending_connections.contains(connection) {
    return false
  }
  self.pending_connections.push(connection)
  true
}

///|
fn StreamRuntime::remove_pending(
  self : StreamRuntime,
  connection : @rtc.ConnectionId,
) -> Bool {
  for index = 0; index < self.pending_connections.length(); index = index + 1 {
    if self.pending_connections[index] == connection {
      ignore(self.pending_connections.remove(index))
      return true
    }
  }
  false
}

///|
fn StreamRuntime::promote_connection(
  self : StreamRuntime,
  bound : BoundStream,
) -> Bool {
  if !self.remove_pending(bound.connection) ||
    self.stream(bound.connection) is Some(_) {
    return false
  }
  self.streams.push(bound)
  true
}

///|
fn StreamRuntime::add_accepted_stream(
  self : StreamRuntime,
  bound : BoundStream,
) -> Bool {
  if self.stream(bound.connection) is Some(_) ||
    self.pending_connections.contains(bound.connection) {
    return false
  }
  self.streams.push(bound)
  true
}

///|
fn StreamRuntime::close_stream(
  self : StreamRuntime,
  connection : @rtc.ConnectionId,
) -> Bool {
  let mut found = self.remove_pending(connection)
  for index = 0; index < self.streams.length(); index = index + 1 {
    if self.streams[index].connection == connection {
      let stream = self.streams[index]
      ignore(self.streams.remove(index))
      stream.stream.close()
      found = true
      break
    }
  }
  found
}

///|
fn StreamRuntime::close_listener(
  self : StreamRuntime,
  listener : @rtc.ListenerId,
) -> Bool {
  for index = 0; index < self.listeners.length(); index = index + 1 {
    if self.listeners[index].listener == listener {
      let bound = self.listeners[index]
      ignore(self.listeners.remove(index))
      bound.server.close()
      return true
    }
  }
  false
}

///|
fn StreamRuntime::next_accepted_connection(
  self : StreamRuntime,
) -> @rtc.ConnectionId? {
  if self.next_accepted_connection == 0xffffffffffffffffUL {
    return None
  }
  let connection = @rtc.ConnectionId(self.next_accepted_connection)
  self.next_accepted_connection += 1UL
  Some(connection)
}

///|
fn StreamRuntime::close_all(self : StreamRuntime) -> Unit {
  while !self.streams.is_empty() {
    let stream = self.streams.pop().unwrap()
    stream.stream.close()
  }
  while !self.listeners.is_empty() {
    let listener = self.listeners.pop().unwrap()
    listener.server.close()
  }
  self.pending_connections.clear()
}

///|
fn create_driver(
  core : @rtc.PeerConnection,
  backpressure_timeout_ms : Int64,
) -> (Driver, PeerHandle, EventStream, MessageStream) {
  let shared : Shared = {
    inputs: Queue(kind=Blocking(core.driver_command_capacity())),
    control_inputs: Queue(kind=Blocking(core.driver_command_capacity())),
    wakeups: Queue(kind=Blocking(1)),
    close_requests: Queue(kind=Unbounded),
    events: Queue(kind=Blocking(core.driver_event_capacity())),
    messages: Queue(kind=Blocking(core.driver_message_capacity())),
    run_started: false,
    closing: false,
    terminated: false,
    output_blocked: false,
    output_blocked_since: None,
    prefer_control_input: true,
    backpressure_timeout_ms,
  }
  (
    {
      core,
      shared,
      receive_mtu: core.driver_receive_mtu(),
      pending_events: [],
      pending_messages: [],
    },
    { shared, },
    { shared, },
    { shared, },
  )
}

///|
pub fn Driver::create(
  core : @rtc.PeerConnection,
) -> (Driver, PeerHandle, EventStream, MessageStream) {
  create_driver(core, 30000L)
}

///|
pub fn PeerHandle::clone(self : PeerHandle) -> PeerHandle {
  { shared: self.shared }
}

///|
fn signal_driver(shared : Shared) -> Unit {
  ignore(shared.wakeups.try_put(()) catch { _ => false })
}

///|
async fn put_input(
  shared : Shared,
  input : DriverInput,
) -> Unit raise DriverError {
  if shared.closing || shared.terminated {
    raise Closed
  }
  shared.inputs.put(input) catch {
    DriverStopping => raise Closed
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("driver command queue failed")
  }
  signal_driver(shared)
}

///|
fn is_control_datagram(payload : Bytes) -> Bool {
  if payload.is_empty() {
    return false
  }
  let first = payload[0]
  if first <= 3 {
    // STUN, including TURN Data Indications.
    return true
  }
  if first >= 20 && first <= 79 {
    // DTLS records and TURN ChannelData. Encrypted DTLS application records
    // may carry SCTP acknowledgements, so they must keep flowing.
    return true
  }
  first >= 128 &&
  first <= 191 &&
  payload.length() >= 2 &&
  payload[1] >= 192 &&
  payload[1] <= 223
}

///|
fn is_control_input(input : DriverInput) -> Bool {
  match input {
    Inbound(datagram) => is_control_datagram(datagram.payload)
    // Stream framing can be arbitrarily fragmented. Preserve byte/lifecycle
    // order and keep the complete reliable transport active as control input.
    CoreIo(_) => true
    SendMessage(_) | CloseDataChannel(_) | OutputDrained => false
  }
}

///|
async fn put_network_input(
  shared : Shared,
  input : DriverInput,
) -> Unit raise DriverError {
  if shared.closing || shared.terminated {
    raise Closed
  }
  let queue = if is_control_input(input) {
    shared.control_inputs
  } else {
    shared.inputs
  }
  queue.put(input) catch {
    DriverStopping => raise Closed
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("driver network ingress queue failed")
  }
  signal_driver(shared)
}

///|
pub async fn PeerHandle::send(
  self : PeerHandle,
  message : @rtc.RtcMessage,
) -> Unit raise DriverError {
  put_input(self.shared, SendMessage(message))
}

///|
pub async fn PeerHandle::close_data_channel(
  self : PeerHandle,
  channel : @rtc.DataChannel,
) -> Unit raise DriverError {
  put_input(self.shared, CloseDataChannel(channel))
}

///|
pub async fn PeerHandle::close(self : PeerHandle) -> Unit raise DriverError {
  if self.shared.terminated || self.shared.closing {
    return
  }
  self.shared.closing = true
  self.shared.close_requests.put(()) catch {
    StreamEnded | DriverStopping => ()
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("driver close signal failed")
  }
}

///|
pub async fn EventStream::next(
  self : EventStream,
) -> @rtc.PeerEvent? raise DriverError {
  let event = self.shared.events.get() catch {
    StreamEnded => return None
    StreamFailed(error) => raise error
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("driver event stream failed")
  }
  if self.shared.output_blocked {
    signal_driver(self.shared)
  }
  Some(event)
}

///|
pub async fn MessageStream::next(
  self : MessageStream,
) -> @rtc.RtcMessage? raise DriverError {
  let message = self.shared.messages.get() catch {
    StreamEnded => return None
    StreamFailed(error) => raise error
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("driver message stream failed")
  }
  if self.shared.output_blocked {
    signal_driver(self.shared)
  }
  Some(message)
}

///|
fn async_address(
  address : @rtc.SocketAddress,
) -> @socket.Addr raise DriverError {
  @socket.Addr::parse(address.to_string()) catch {
    _ => raise Io("cannot convert RTC socket address")
  }
}

///|
fn rtc_address(address : @socket.Addr) -> @rtc.SocketAddress raise DriverError {
  let port = address.port()
  if port < 0 || port > 65535 {
    raise Io("socket port is out of range")
  }
  if !address.is_ipv6() {
    let ip = address.ip()
    return @rtc.SocketAddress::new(
      address=@rtc.IpAddress::v4(
        (ip >> 24).to_byte(),
        (ip >> 16).to_byte(),
        (ip >> 8).to_byte(),
        ip.to_byte(),
      ),
      port=port.to_uint16(),
    )
  }
  let rendered = address.to_string()
  guard rendered.strip_prefix("[") is Some(without_open) else {
    raise Io("invalid IPv6 socket address")
  }
  let parts = without_open.split("]:").to_array()
  if parts.length() != 2 || parts[0].contains("%") {
    raise Io("scoped IPv6 addresses are not supported by the async driver")
  }
  let ip = @rtc.IpAddress::parse(parts[0].to_owned()) catch {
    _ => raise Io("cannot parse IPv6 socket address")
  }
  @rtc.SocketAddress::new(address=ip, port=port.to_uint16())
}

///|
async fn bind_socket(
  local_address : @rtc.SocketAddress,
) -> BoundSocket raise DriverError {
  let address = async_address(local_address)
  let socket = @socket.UdpServer(address) catch {
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("failed to bind UDP host candidate")
  }
  if socket.addr != address {
    socket.close()
    raise Io("UDP socket bound to an unexpected address")
  }
  { local_address, socket }
}

///|
fn find_socket(
  sockets : Array[BoundSocket],
  address : @rtc.SocketAddress,
) -> BoundSocket? {
  for socket in sockets {
    if socket.local_address == address {
      return Some(socket)
    }
  }
  None
}

///|
async fn send_datagram(
  sockets : Array[BoundSocket],
  datagram : @rtc.OutboundDatagram,
) -> Unit raise DriverError {
  guard find_socket(sockets, datagram.context.local_address) is Some(bound) else {
    raise Io("core selected an unbound UDP local address")
  }
  let peer = async_address(datagram.context.peer)
  bound.socket.sendto(datagram.payload, peer) catch {
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("UDP send failed")
  }
}

///|
async fn receive_loop(
  shared : Shared,
  bound : BoundSocket,
  receive_mtu : Int,
) -> Unit raise DriverError {
  let buffer : FixedArray[Byte] = FixedArray::make(receive_mtu, b'\x00')
  for ;; {
    let (length, peer) = bound.socket.recvfrom(buffer) catch {
      error if @async_runtime.is_cancellation_error(error) => return
      _ => raise Io("UDP receive failed")
    }
    if length < 0 {
      raise Io("UDP receive returned a negative length")
    }
    let now = driver_now()
    let datagram : @rtc.InboundDatagram = {
      now,
      context: {
        local_address: bound.local_address,
        peer: rtc_address(peer),
        ecn: None,
        protocol: Udp,
      },
      payload: buffer.unsafe_reinterpret_as_bytes()[0:length].to_owned(),
    }
    put_network_input(shared, Inbound(datagram)) catch {
      Closed => return
      error => raise error
    }
  }
}

///|
async fn enqueue_core_io(shared : Shared, event : @rtc.IoEvent) -> Bool {
  put_network_input(shared, CoreIo(event)) catch {
    _ => return false
  }
  true
}

///|
async fn report_connection_error(
  shared : Shared,
  runtime : StreamRuntime,
  connection : @rtc.ConnectionId,
  reason : String,
) -> Unit {
  if !runtime.remove_pending(connection) {
    return
  }
  let now = driver_now() catch { _ => return }
  ignore(enqueue_core_io(shared, StreamError(now~, connection~, reason~)))
}

///|
fn requested_local_matches(
  requested : @rtc.SocketAddress?,
  actual : @rtc.SocketAddress,
) -> Bool {
  match requested {
    None => true
    Some(requested) =>
      requested.address() == actual.address() &&
      (requested.port() == 0 || requested.port() == actual.port())
  }
}

///|
async fn secure_stream(
  socket : @socket.Tcp,
  server_name : String?,
) -> DriverStream raise DriverError {
  let secure = try {
    match server_name {
      Some(host) => @tls.Tls::client(socket, host~)
      None => @tls.Tls::client(socket)
    }
  } catch {
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("TLS stream handshake failed")
  }
  Secure(secure, socket)
}

///|
async fn receive_stream_loop(
  shared : Shared,
  runtime : StreamRuntime,
  bound : BoundStream,
) -> Unit {
  for ;; {
    let chunk = bound.stream.read_some() catch {
      error if @async_runtime.is_cancellation_error(error) => return
      _ => {
        if runtime.stream(bound.connection) is Some(_) {
          let now = driver_now() catch { _ => return }
          ignore(
            enqueue_core_io(
              shared,
              StreamError(
                now~,
                connection=bound.connection,
                reason="stream read failed",
              ),
            ),
          )
        }
        return
      }
    }
    match chunk {
      None => {
        if runtime.stream(bound.connection) is Some(_) {
          let now = driver_now() catch { _ => return }
          ignore(
            enqueue_core_io(
              shared,
              StreamEof(now~, connection=bound.connection),
            ),
          )
        }
        return
      }
      Some(bytes) => {
        let now = driver_now() catch { _ => return }
        if !enqueue_core_io(
            shared,
            StreamBytes(now~, connection=bound.connection, bytes~),
          ) {
          return
        }
      }
    }
  }
}

///|
async fn outgoing_stream_loop(
  shared : Shared,
  runtime : StreamRuntime,
  connection : @rtc.ConnectionId,
  requested_local : @rtc.SocketAddress?,
  peer : @rtc.SocketAddress,
  use_tls : Bool,
  server_name : String?,
) -> Unit {
  let peer_address = async_address(peer) catch {
    _ => {
      report_connection_error(
        shared, runtime, connection, "invalid stream peer address",
      )
      return
    }
  }
  let socket = @socket.Tcp::connect(peer_address) catch {
    error if @async_runtime.is_cancellation_error(error) => {
      ignore(runtime.remove_pending(connection))
      return
    }
    _ => {
      report_connection_error(
        shared, runtime, connection, "TCP connection failed",
      )
      return
    }
  }
  let actual_local = rtc_address(socket.addr) catch {
    _ => {
      socket.close()
      report_connection_error(
        shared, runtime, connection, "cannot determine TCP local address",
      )
      return
    }
  }
  if !requested_local_matches(requested_local, actual_local) {
    socket.close()
    report_connection_error(
      shared, runtime, connection, "TCP connection used an unexpected local address",
    )
    return
  }
  let stream = if use_tls {
    secure_stream(socket, server_name) catch {
      Cancelled => {
        socket.close()
        ignore(runtime.remove_pending(connection))
        return
      }
      _ => {
        socket.close()
        report_connection_error(
          shared, runtime, connection, "TLS stream handshake failed",
        )
        return
      }
    }
  } else {
    Plain(socket)
  }
  let bound : BoundStream = { connection, stream }
  if !runtime.promote_connection(bound) {
    stream.close()
    return
  }
  let context : @rtc.TransportContext = {
    local_address: actual_local,
    peer,
    ecn: None,
    protocol: Tcp,
  }
  let now = driver_now() catch {
    _ => {
      ignore(runtime.close_stream(connection))
      return
    }
  }
  if !enqueue_core_io(shared, StreamConnected(now~, connection~, context~)) {
    ignore(runtime.close_stream(connection))
    return
  }
  receive_stream_loop(shared, runtime, bound)
}

///|
async fn accept_stream_loop(
  shared : Shared,
  runtime : StreamRuntime,
  bound : BoundListener,
  group : @async_runtime.TaskGroup[Unit],
) -> Unit raise DriverError {
  for ;; {
    let (socket, peer_address) = bound.server.accept() catch {
      error if @async_runtime.is_cancellation_error(error) => return
      _ =>
        if runtime.has_listener(bound.listener) {
          raise Io("TCP listener accept failed")
        } else {
          return
        }
    }
    let peer = rtc_address(peer_address) catch {
      _ => {
        socket.close()
        continue
      }
    }
    guard runtime.next_accepted_connection() is Some(connection) else {
      socket.close()
      raise Io("accepted stream identifier space is exhausted")
    }
    let stream = Plain(socket)
    let accepted : BoundStream = { connection, stream }
    if !runtime.add_accepted_stream(accepted) {
      stream.close()
      continue
    }
    let context : @rtc.TransportContext = {
      local_address: bound.local_address,
      peer,
      ecn: None,
      protocol: Tcp,
    }
    let now = driver_now()
    let enqueued = enqueue_core_io(
      shared,
      StreamAccepted(now~, listener=bound.listener, connection~, context~),
    ) catch {
      error if @async_runtime.is_cancellation_error(error) => return
      _ => raise Io("failed to queue an accepted TCP stream")
    }
    if !enqueued {
      ignore(runtime.close_stream(connection))
      return
    }
    group.spawn_bg(no_wait=true, () => {
      receive_stream_loop(shared, runtime, accepted)
    })
  }
}

///|
fn stream_failure(shared : Shared, error : DriverError?) -> Unit {
  let queue_error : Error = match error {
    Some(value) => StreamFailed(value)
    None => StreamEnded
  }
  shared.events.close(error=queue_error)
  shared.messages.close(error=queue_error)
  shared.inputs.close(error=DriverStopping, clear=true)
  shared.control_inputs.close(error=DriverStopping, clear=true)
  shared.wakeups.close(error=DriverStopping, clear=true)
  shared.close_requests.close(error=StreamEnded, clear=true)
}

///|
fn Driver::drain_core_events(self : Driver) -> Unit raise DriverError {
  while !self.pending_events.is_empty() {
    let event = self.pending_events[0]
    let inserted = self.shared.events.try_put(event) catch { _ => raise Closed }
    if !inserted {
      self.shared.output_blocked = true
      return
    }
    ignore(self.pending_events.remove(0))
  }
  while self.core.poll_event() is Some(event) {
    let inserted = self.shared.events.try_put(event) catch { _ => raise Closed }
    if !inserted {
      self.pending_events.push(event)
      break
    }
  }
  while !self.pending_messages.is_empty() {
    let message = self.pending_messages[0]
    let inserted = self.shared.messages.try_put(message) catch {
      _ => raise Closed
    }
    if !inserted {
      self.shared.output_blocked = true
      return
    }
    ignore(self.pending_messages.remove(0))
  }
  while self.core.poll_message() is Some(message) {
    let inserted = self.shared.messages.try_put(message) catch {
      _ => raise Closed
    }
    if !inserted {
      self.pending_messages.push(message)
      break
    }
  }
  self.shared.output_blocked = !self.pending_events.is_empty() ||
    !self.pending_messages.is_empty()
}

///|
fn Driver::handle_core_io(
  self : Driver,
  event : @rtc.IoEvent,
) -> Unit raise DriverError {
  self.core.handle_io_event(event) catch {
    error => raise Core(error)
  }
}

///|
async fn Driver::flush_core(
  self : Driver,
  sockets : Array[BoundSocket],
  runtime : StreamRuntime,
  group : @async_runtime.TaskGroup[Unit],
) -> Unit raise DriverError {
  while self.core.poll_io_action() is Some(action) {
    match action {
      SendDatagram(datagram) => send_datagram(sockets, datagram)
      ConnectTcp(connection~, local_address~, peer~) => {
        if !runtime.begin_connection(connection) {
          raise Io("core reused an active TCP connection identifier")
        }
        group.spawn_bg(no_wait=true, () => {
          outgoing_stream_loop(
            self.shared,
            runtime,
            connection,
            local_address,
            peer,
            false,
            None,
          )
        })
      }
      ConnectTls(connection~, local_address~, peer~, server_name~) => {
        if !runtime.begin_connection(connection) {
          raise Io("core reused an active TLS connection identifier")
        }
        group.spawn_bg(no_wait=true, () => {
          outgoing_stream_loop(
            self.shared,
            runtime,
            connection,
            local_address,
            peer,
            true,
            server_name,
          )
        })
      }
      ListenTcp(listener~, local_address~) => {
        if runtime.has_listener(listener) {
          raise Io("core reused an active TCP listener identifier")
        }
        let listen_address = async_address(local_address)
        let server = @socket.TcpServer(listen_address) catch {
          error if @async_runtime.is_cancellation_error(error) =>
            raise Cancelled
          _ => raise Io("failed to bind TCP host candidate")
        }
        let actual_address = rtc_address(server.addr) catch {
          error => {
            server.close()
            raise error
          }
        }
        if actual_address != local_address {
          server.close()
          raise Io("TCP listener bound to an unexpected address")
        }
        let bound : BoundListener = { listener, local_address, server }
        runtime.listeners.push(bound)
        group.spawn_bg(no_wait=true, () => {
          accept_stream_loop(self.shared, runtime, bound, group)
        })
      }
      WriteStream(connection~, bytes~) => {
        guard runtime.stream(connection) is Some(bound) else {
          let now = driver_now()
          self.handle_core_io(
            StreamError(
              now~,
              connection~,
              reason="core selected an unknown stream",
            ),
          )
          continue
        }
        bound.stream.write(bytes) catch {
          error if @async_runtime.is_cancellation_error(error) =>
            raise Cancelled
          _ => {
            ignore(runtime.close_stream(connection))
            let now = driver_now()
            self.handle_core_io(
              StreamError(now~, connection~, reason="stream write failed"),
            )
          }
        }
      }
      CloseStream(connection) => {
        ignore(runtime.close_stream(connection))
        self.handle_core_io(StreamClosed(now=driver_now(), connection~))
      }
      CloseListener(listener) => ignore(runtime.close_listener(listener))
    }
  }
  self.drain_core_events()
}

///|
fn duration_until(deadline : @rtc.Instant, now : @rtc.Instant) -> Int {
  let milliseconds = deadline.saturating_duration_since(now).as_milliseconds()
  if milliseconds > 2147483647L {
    2147483647
  } else {
    milliseconds.to_int()
  }
}

///|
fn try_regular_input(shared : Shared) -> DriverInput? raise DriverError {
  shared.inputs.try_get() catch {
    DriverStopping => None
    _ => raise Io("driver command queue failed")
  }
}

///|
fn try_control_input(shared : Shared) -> DriverInput? raise DriverError {
  shared.control_inputs.try_get() catch {
    DriverStopping => None
    _ => raise Io("driver control queue failed")
  }
}

///|
fn try_ready_input(
  shared : Shared,
  include_regular : Bool,
) -> DriverInput? raise DriverError {
  if include_regular && !shared.prefer_control_input {
    match try_regular_input(shared) {
      Some(input) => {
        shared.prefer_control_input = true
        return Some(input)
      }
      None => ()
    }
  }
  match try_control_input(shared) {
    Some(input) => {
      shared.prefer_control_input = false
      return Some(input)
    }
    None => ()
  }
  if include_regular {
    match try_regular_input(shared) {
      Some(input) => {
        shared.prefer_control_input = true
        return Some(input)
      }
      None => ()
    }
  }
  None
}

///|
async fn wait_for_driver_signal(
  shared : Shared,
  delay : Int?,
) -> Bool raise DriverError {
  match delay {
    Some(0) => false
    Some(delay) => {
      let signal = @async_runtime.with_timeout_opt(delay, () => {
        shared.wakeups.get()
      }) catch {
        DriverStopping => return false
        error if @async_runtime.is_cancellation_error(error) => raise Cancelled
        _ => raise Io("driver wakeup wait failed")
      }
      signal is Some(_)
    }
    None => {
      ignore(
        shared.wakeups.get() catch {
          DriverStopping => return false
          error if @async_runtime.is_cancellation_error(error) =>
            raise Cancelled
          _ => raise Io("driver wakeup wait failed")
        },
      )
      true
    }
  }
}

///|
async fn get_input_until_timeout(
  shared : Shared,
  deadline : @rtc.Instant?,
  now : @rtc.Instant,
) -> DriverInput? raise DriverError {
  match try_ready_input(shared, true) {
    Some(input) => return Some(input)
    None => ()
  }
  let delay = match deadline {
    Some(deadline) => Some(duration_until(deadline, now))
    None => None
  }
  if !wait_for_driver_signal(shared, delay) {
    return None
  }
  match try_ready_input(shared, true) {
    Some(input) => Some(input)
    None => Some(OutputDrained)
  }
}

///|
async fn get_control_until_timeout(
  shared : Shared,
  deadline : @rtc.Instant?,
  now : @rtc.Instant,
  backpressure_delay : Int,
) -> DriverInput? raise DriverError {
  match try_ready_input(shared, false) {
    Some(input) => return Some(input)
    None => ()
  }
  let delay = match deadline {
    None => backpressure_delay
    Some(deadline) => {
      let protocol_delay = duration_until(deadline, now)
      if protocol_delay < backpressure_delay {
        protocol_delay
      } else {
        backpressure_delay
      }
    }
  }
  if !wait_for_driver_signal(shared, Some(delay)) {
    return None
  }
  match try_ready_input(shared, false) {
    Some(input) => Some(input)
    None => Some(OutputDrained)
  }
}

///|
fn backpressure_delay(shared : Shared, now : @rtc.Instant) -> Int {
  let started = match shared.output_blocked_since {
    Some(value) => value
    None => {
      shared.output_blocked_since = Some(now)
      now
    }
  }
  let elapsed = now.saturating_duration_since(started).as_milliseconds()
  let remaining = shared.backpressure_timeout_ms - elapsed
  if remaining <= 0L {
    0
  } else if remaining > 2147483647L {
    2147483647
  } else {
    remaining.to_int()
  }
}

///|
async fn Driver::main_loop(
  self : Driver,
  sockets : Array[BoundSocket],
  runtime : StreamRuntime,
  group : @async_runtime.TaskGroup[Unit],
) -> Unit raise DriverError {
  self.flush_core(sockets, runtime, group)
  while !self.shared.closing {
    let now = driver_now()
    let deadline = self.core.poll_timeout()
    if self.shared.output_blocked && backpressure_delay(self.shared, now) == 0 {
      raise BackpressureExceeded
    }
    match deadline {
      Some(deadline) if duration_until(deadline, now) == 0 => {
        self.core.handle_timeout(now) catch {
          error => raise Core(error)
        }
        self.flush_core(sockets, runtime, group)
        continue
      }
      _ => ()
    }
    let input = if self.shared.output_blocked {
      let delay = backpressure_delay(self.shared, now)
      get_control_until_timeout(self.shared, deadline, now, delay)
    } else {
      self.shared.output_blocked_since = None
      get_input_until_timeout(self.shared, deadline, now)
    }
    let current = driver_now()
    match input {
      Some(SendMessage(message)) =>
        self.core.handle_message(message, current) catch {
          error => raise Core(error)
        }
      Some(CloseDataChannel(channel)) =>
        self.core.close_data_channel(channel.id(), current) catch {
          error => raise Core(error)
        }
      Some(Inbound(datagram)) =>
        self.core.handle_datagram(datagram) catch {
          error => raise Core(error)
        }
      Some(CoreIo(event)) => self.handle_core_io(event)
      Some(OutputDrained) => ()
      None =>
        if self.shared.closing {
          break
        } else if self.shared.output_blocked &&
          backpressure_delay(self.shared, current) == 0 {
          raise BackpressureExceeded
        } else {
          match deadline {
            Some(deadline) if duration_until(deadline, current) == 0 =>
              self.core.handle_timeout(current) catch {
                error => raise Core(error)
              }
            _ => ()
          }
        }
    }
    self.flush_core(sockets, runtime, group)
  }
  let now = driver_now()
  self.core.close(now) catch {
    error => raise Core(error)
  }
  self.flush_core(sockets, runtime, group)
}

///|
async fn Driver::run_impl(self : Driver) -> Unit raise DriverError {
  let sockets : Array[BoundSocket] = []
  for candidate in self.core.local_host_candidates() {
    if candidate.protocol() != Udp {
      continue
    }
    guard candidate.socket_address() is Some(local_address) else {
      raise Io("driver received an unresolved host candidate")
    }
    if find_socket(sockets, local_address) is None {
      sockets.push(bind_socket(local_address))
    }
  }
  let runtime = StreamRuntime::new()
  defer (for socket in sockets {
    socket.socket.close()
  })
  defer runtime.close_all()
  (@async_runtime.with_task_group <| group => {
    group.spawn_bg(no_wait=true) <| () => {
      self.shared.close_requests.get() catch {
        error if @async_runtime.is_cancellation_error(error) => return
        StreamEnded => return
        _ => return
      }
      self.shared.closing = true
      self.shared.inputs.close(error=DriverStopping)
      self.shared.control_inputs.close(error=DriverStopping)
      self.shared.wakeups.close(error=DriverStopping)
    }
    for socket in sockets {
      group.spawn_bg(no_wait=true, () => {
        receive_loop(self.shared, socket, self.receive_mtu)
      })
    }
    self.main_loop(sockets, runtime, group)
  }) catch {
    Core(error) => raise Core(error)
    BackpressureExceeded => raise BackpressureExceeded
    Cancelled => raise Cancelled
    Closed => raise Closed
    Io(message) => raise Io(message)
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("async task group failed")
  }
}

///|
pub async fn Driver::run(self : Driver) -> Unit raise DriverError {
  if self.shared.run_started || self.shared.terminated {
    raise Closed
  }
  self.shared.run_started = true
  let outcome : Result[Unit, DriverError] = try {
    self.run_impl()
    Ok(())
  } catch {
    Core(error) => Err(Core(error))
    BackpressureExceeded => Err(BackpressureExceeded)
    Cancelled => Err(Cancelled)
    Closed => Err(Closed)
    Io(message) => Err(Io(message))
  }
  self.shared.terminated = true
  self.shared.closing = true
  match outcome {
    Ok(_) => stream_failure(self.shared, None)
    Err(error) => {
      stream_failure(self.shared, Some(error))
      raise error
    }
  }
}

///|
pub async fn with_peer_connection(
  core : @rtc.PeerConnection,
  use_peer : async (PeerHandle, EventStream, MessageStream) -> Unit,
) -> Unit raise DriverError {
  let (driver, handle, events, messages) = Driver::create(core)
  (@async_runtime.with_task_group <| group => {
    let cleanup_handle = handle.clone()
    group.add_defer(() => cleanup_handle.close() catch { _ => () })
    let driver_task = group.spawn(() => driver.run())
    use_peer(handle, events, messages)
    cleanup_handle.close()
    driver_task.wait()
  }) catch {
    Core(error) => raise Core(error)
    BackpressureExceeded => raise BackpressureExceeded
    Cancelled => raise Cancelled
    Closed => raise Closed
    Io(message) => raise Io(message)
    error if @async_runtime.is_cancellation_error(error) => raise Cancelled
    _ => raise Io("peer connection scope failed")
  }
}
