///|
pub(all) suberror RtpError {
  InvalidPacket(String)
  InvalidExtension(String)
  PayloadTooLarge(Int32)
} derive(Debug, Eq)

///|
pub(all) struct HeaderExtension {
  id : Byte
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn HeaderExtension::new(
  id~ : Byte,
  payload~ : Bytes,
) -> HeaderExtension raise RtpError {
  if id == 0 {
    raise InvalidExtension("RTP extension id zero is reserved for padding")
  }
  if payload.length() > 255 {
    raise InvalidExtension("RTP extension payload exceeds 255 bytes")
  }
  { id, payload, }
}

///|
pub fn HeaderExtension::id(self : HeaderExtension) -> Byte {
  self.id
}

///|
pub fn HeaderExtension::payload(self : HeaderExtension) -> Bytes {
  self.payload
}

///|
pub(all) struct Packet {
  marker : Bool
  payload_type : Byte
  sequence_number : UInt16
  timestamp : UInt32
  ssrc : UInt32
  csrc : Array[UInt32]
  extensions : Array[HeaderExtension]
  payload : Bytes
} derive(Debug, Eq)

///|
pub fn Packet::new(
  marker~ : Bool = false,
  payload_type~ : Byte,
  sequence_number~ : UInt16,
  timestamp~ : UInt32,
  ssrc~ : UInt32,
  csrc~ : Array[UInt32] = [],
  extensions~ : Array[HeaderExtension] = [],
  payload~ : Bytes,
) -> Packet raise RtpError {
  if payload_type > 127 {
    raise InvalidPacket("RTP payload type must fit in seven bits")
  }
  if csrc.length() > 15 {
    raise InvalidPacket("RTP header contains more than 15 CSRC entries")
  }
  if payload.length() > 0xffff {
    raise PayloadTooLarge(payload.length())
  }
  {
    marker,
    payload_type,
    sequence_number,
    timestamp,
    ssrc,
    csrc: csrc.copy(),
    extensions: extensions.copy(),
    payload,
  }
}

///|
pub fn Packet::marker(self : Packet) -> Bool {
  self.marker
}

///|
pub fn Packet::payload_type(self : Packet) -> Byte {
  self.payload_type
}

///|
pub fn Packet::sequence_number(self : Packet) -> UInt16 {
  self.sequence_number
}

///|
pub fn Packet::timestamp(self : Packet) -> UInt32 {
  self.timestamp
}

///|
pub fn Packet::ssrc(self : Packet) -> UInt32 {
  self.ssrc
}

///|
pub fn Packet::csrc(self : Packet) -> Array[UInt32] {
  self.csrc.copy()
}

///|
pub fn Packet::extensions(self : Packet) -> Array[HeaderExtension] {
  self.extensions.copy()
}

///|
pub fn Packet::payload(self : Packet) -> Bytes {
  self.payload
}
