///|
pub(all) struct AudioLevelExtension {
  level : Byte
  voice : Bool
} derive(Debug, Eq)

///|
pub fn AudioLevelExtension::new(
  level~ : Byte,
  voice? : Bool = false,
) -> AudioLevelExtension raise RtpError {
  if level > 127 {
    raise InvalidExtension("RTP audio level exceeds 127")
  }
  { level, voice, }
}

///|
pub fn AudioLevelExtension::level(self : AudioLevelExtension) -> Byte {
  self.level
}

///|
pub fn AudioLevelExtension::voice(self : AudioLevelExtension) -> Bool {
  self.voice
}

///|
pub fn AudioLevelExtension::marshal(
  self : AudioLevelExtension,
) -> Bytes raise RtpError {
  if self.level > 127 {
    raise InvalidExtension("RTP audio level exceeds 127")
  }
  Bytes::from_array([self.level | (if self.voice { 0x80 } else { 0 })])
}

///|
pub fn AudioLevelExtension::unmarshal(
  payload : Bytes,
) -> AudioLevelExtension raise RtpError {
  if payload.length() != 1 {
    raise InvalidExtension("RTP audio level extension must be one byte")
  }
  { level: payload[0] & 0x7f, voice: (payload[0] & 0x80) != 0, }
}

///|
pub(all) struct TransportCcExtension {
  transport_sequence : UInt16
} derive(Debug, Eq)

///|
pub fn TransportCcExtension::new(
  transport_sequence~ : UInt16,
) -> TransportCcExtension {
  { transport_sequence, }
}

///|
pub fn TransportCcExtension::transport_sequence(
  self : TransportCcExtension,
) -> UInt16 {
  self.transport_sequence
}

///|
pub fn TransportCcExtension::marshal(self : TransportCcExtension) -> Bytes {
  Bytes::from_array([
    (self.transport_sequence >> 8).to_byte(),
    self.transport_sequence.to_byte(),
  ])
}

///|
pub fn TransportCcExtension::unmarshal(
  payload : Bytes,
) -> TransportCcExtension raise RtpError {
  if payload.length() != 2 {
    raise InvalidExtension("RTP transport-cc extension must be two bytes")
  }
  {
    transport_sequence: ((payload[0].to_uint() << 8) | payload[1].to_uint()).to_uint16(),
  }
}

///|
pub(all) struct AbsSendTimeExtension {
  timestamp : UInt64
} derive(Debug, Eq)

///|
pub fn AbsSendTimeExtension::new(
  send_time_ntp : UInt64,
) -> AbsSendTimeExtension {
  { timestamp: (send_time_ntp >> 14) & 0xffffffUL, }
}

///|
pub fn AbsSendTimeExtension::from_timestamp(
  timestamp : UInt64,
) -> AbsSendTimeExtension raise RtpError {
  if timestamp > 0xffffffUL {
    raise InvalidExtension("absolute send time exceeds 24 bits")
  }
  { timestamp, }
}

///|
pub fn AbsSendTimeExtension::timestamp(self : AbsSendTimeExtension) -> UInt64 {
  self.timestamp
}

///|
pub fn AbsSendTimeExtension::estimate(
  self : AbsSendTimeExtension,
  receive_ntp : UInt64,
) -> UInt64 {
  let mut ntp = (receive_ntp & 0xffffffc000000000UL) |
    ((self.timestamp & 0xffffffUL) << 14)
  if receive_ntp < ntp {
    ntp -= 0x1000000UL << 14
  }
  ntp
}

///|
pub fn AbsSendTimeExtension::marshal(
  self : AbsSendTimeExtension,
) -> Bytes raise RtpError {
  if self.timestamp > 0xffffffUL {
    raise InvalidExtension("absolute send time exceeds 24 bits")
  }
  Bytes::from_array([
    (self.timestamp >> 16).to_byte(),
    (self.timestamp >> 8).to_byte(),
    self.timestamp.to_byte(),
  ])
}

///|
pub fn AbsSendTimeExtension::unmarshal(
  payload : Bytes,
) -> AbsSendTimeExtension raise RtpError {
  if payload.length() != 3 {
    raise InvalidExtension("absolute send time extension must be three bytes")
  }
  {
    timestamp: (payload[0].to_uint64() << 16) |
    (payload[1].to_uint64() << 8) |
    payload[2].to_uint64(),
  }
}

///|
pub(all) struct PlayoutDelayExtension {
  min_delay : UInt16
  max_delay : UInt16
} derive(Debug, Eq)

///|
pub fn PlayoutDelayExtension::new(
  min_delay~ : UInt16,
  max_delay~ : UInt16,
) -> PlayoutDelayExtension raise RtpError {
  if min_delay > 0x0fff || max_delay > 0x0fff {
    raise InvalidExtension("RTP playout delay exceeds 12 bits")
  }
  if min_delay > max_delay {
    raise InvalidExtension("minimum playout delay exceeds maximum")
  }
  { min_delay, max_delay, }
}

///|
pub fn PlayoutDelayExtension::min_delay(self : PlayoutDelayExtension) -> UInt16 {
  self.min_delay
}

///|
pub fn PlayoutDelayExtension::max_delay(self : PlayoutDelayExtension) -> UInt16 {
  self.max_delay
}

///|
pub fn PlayoutDelayExtension::marshal(
  self : PlayoutDelayExtension,
) -> Bytes raise RtpError {
  ignore(
    PlayoutDelayExtension::new(
      min_delay=self.min_delay,
      max_delay=self.max_delay,
    ),
  )
  Bytes::from_array([
    (self.min_delay >> 4).to_byte(),
    ((self.min_delay << 4) | (self.max_delay >> 8)).to_byte(),
    self.max_delay.to_byte(),
  ])
}

///|
pub fn PlayoutDelayExtension::unmarshal(
  payload : Bytes,
) -> PlayoutDelayExtension raise RtpError {
  if payload.length() != 3 {
    raise InvalidExtension("RTP playout delay extension must be three bytes")
  }
  let min_delay = ((payload[0].to_uint() << 4) | (payload[1].to_uint() >> 4)).to_uint16()
  let max_delay = (((payload[1].to_uint() & 0x0f) << 8) | payload[2].to_uint()).to_uint16()
  PlayoutDelayExtension::new(min_delay~, max_delay~)
}

///|
pub(all) enum CameraDirection {
  Front
  Back
} derive(Debug, Eq)

///|
pub(all) enum VideoRotation {
  Degree0
  Degree90
  Degree180
  Degree270
} derive(Debug, Eq)

///|
pub(all) struct VideoOrientationExtension {
  direction : CameraDirection
  flip : Bool
  rotation : VideoRotation
} derive(Debug, Eq)

///|
pub fn VideoOrientationExtension::new(
  direction? : CameraDirection = Front,
  flip? : Bool = false,
  rotation? : VideoRotation = Degree0,
) -> VideoOrientationExtension {
  { direction, flip, rotation, }
}

///|
pub fn VideoOrientationExtension::direction(
  self : VideoOrientationExtension,
) -> CameraDirection {
  self.direction
}

///|
pub fn VideoOrientationExtension::flip(
  self : VideoOrientationExtension,
) -> Bool {
  self.flip
}

///|
pub fn VideoOrientationExtension::rotation(
  self : VideoOrientationExtension,
) -> VideoRotation {
  self.rotation
}

///|
pub fn VideoOrientationExtension::marshal(
  self : VideoOrientationExtension,
) -> Bytes {
  let direction = match self.direction {
    Front => 0
    Back => 0x08
  }
  let rotation = match self.rotation {
    Degree0 => 0
    Degree90 => 1
    Degree180 => 2
    Degree270 => 3
  }
  Bytes::from_array([
    (direction | (if self.flip { 0x04 } else { 0 }) | rotation).to_byte(),
  ])
}

///|
pub fn VideoOrientationExtension::unmarshal(
  payload : Bytes,
) -> VideoOrientationExtension raise RtpError {
  if payload.length() != 1 {
    raise InvalidExtension("video orientation extension must be one byte")
  }
  if (payload[0] & 0xf0) != 0 {
    raise InvalidExtension("video orientation reserved bits are nonzero")
  }
  let direction = if (payload[0] & 0x08) == 0 { Front } else { Back }
  let rotation = match payload[0] & 0x03 {
    0 => Degree0
    1 => Degree90
    2 => Degree180
    _ => Degree270
  }
  { direction, flip: (payload[0] & 0x04) != 0, rotation, }
}
