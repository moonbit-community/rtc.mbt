///|
pub(all) enum AudioLayout {
  Interleaved
  Deinterleaved
} derive(Debug, Eq)

///|
pub struct AudioBuffer {
  samples : Array[Int16]
  channels : Int
  layout : AudioLayout
} derive(Debug, Eq)

///|
pub fn AudioBuffer::new(
  samples~ : Array[Int16],
  channels~ : Int,
  layout? : AudioLayout = Interleaved,
) -> AudioBuffer raise MediaError {
  if channels <= 0 {
    raise InvalidMedia("audio channel count must be positive")
  }
  if samples.length() % channels != 0 {
    raise InvalidMedia(
      "audio sample count is not divisible by the channel count",
    )
  }
  { samples: samples.copy(), channels, layout, }
}

///|
pub fn AudioBuffer::channels(self : AudioBuffer) -> Int {
  self.channels
}

///|
pub fn AudioBuffer::frames(self : AudioBuffer) -> Int {
  self.samples.length() / self.channels
}

///|
pub fn AudioBuffer::sample_count(self : AudioBuffer) -> Int {
  self.samples.length()
}

///|
pub fn AudioBuffer::layout(self : AudioBuffer) -> AudioLayout {
  self.layout
}

///|
pub fn AudioBuffer::samples(self : AudioBuffer) -> Array[Int16] {
  self.samples.copy()
}

///|
fn AudioBuffer::sample_index(
  self : AudioBuffer,
  channel : Int,
  frame : Int,
) -> Int raise MediaError {
  if channel < 0 || channel >= self.channels {
    raise InvalidMedia("audio channel index is out of range")
  }
  if frame < 0 || frame >= self.frames() {
    raise InvalidMedia("audio frame index is out of range")
  }
  match self.layout {
    Interleaved => frame * self.channels + channel
    Deinterleaved => channel * self.frames() + frame
  }
}

///|
fn AudioBuffer::sample_unchecked(
  self : AudioBuffer,
  channel : Int,
  frame : Int,
) -> Int16 {
  let index = match self.layout {
    Interleaved => frame * self.channels + channel
    Deinterleaved => channel * self.frames() + frame
  }
  self.samples[index]
}

///|
pub fn AudioBuffer::sample(
  self : AudioBuffer,
  channel : Int,
  frame : Int,
) -> Int16 raise MediaError {
  ignore(self.sample_index(channel, frame))
  self.sample_unchecked(channel, frame)
}

///|
pub fn AudioBuffer::with_layout(
  self : AudioBuffer,
  layout : AudioLayout,
) -> AudioBuffer {
  if layout == self.layout {
    return self
  }
  let converted : Array[Int16] = []
  match layout {
    Interleaved =>
      for frame = 0; frame < self.frames(); frame = frame + 1 {
        for channel = 0; channel < self.channels; channel = channel + 1 {
          converted.push(self.sample_unchecked(channel, frame))
        }
      }
    Deinterleaved =>
      for channel = 0; channel < self.channels; channel = channel + 1 {
        for frame = 0; frame < self.frames(); frame = frame + 1 {
          converted.push(self.sample_unchecked(channel, frame))
        }
      }
  }
  { samples: converted, channels: self.channels, layout, }
}

///|
pub fn AudioBuffer::slice_frames(
  self : AudioBuffer,
  start : Int,
  end : Int,
) -> AudioBuffer raise MediaError {
  if start < 0 || end < start || end > self.frames() {
    raise InvalidMedia("audio frame range is out of bounds")
  }
  let sliced : Array[Int16] = []
  match self.layout {
    Interleaved =>
      for frame = start; frame < end; frame = frame + 1 {
        for channel = 0; channel < self.channels; channel = channel + 1 {
          sliced.push(self.sample(channel, frame))
        }
      }
    Deinterleaved =>
      for channel = 0; channel < self.channels; channel = channel + 1 {
        for frame = start; frame < end; frame = frame + 1 {
          sliced.push(self.sample(channel, frame))
        }
      }
  }
  AudioBuffer::new(samples=sliced, channels=self.channels, layout=self.layout)
}

///|
pub fn AudioBuffer::from_pcm_s16(
  data : Bytes,
  channels~ : Int,
  little_endian? : Bool = true,
  layout? : AudioLayout = Interleaved,
) -> AudioBuffer raise MediaError {
  if data.length() % 2 != 0 {
    raise InvalidMedia("signed 16-bit PCM contains a partial sample")
  }
  let samples : Array[Int16] = []
  for offset = 0; offset < data.length(); offset = offset + 2 {
    let bits = if little_endian {
      data[offset].to_uint16() | (data[offset + 1].to_uint16() << 8)
    } else {
      (data[offset].to_uint16() << 8) | data[offset + 1].to_uint16()
    }
    samples.push(Int16::reinterpret_from_uint16(bits))
  }
  AudioBuffer::new(samples~, channels~, layout~)
}

///|
pub fn AudioBuffer::to_pcm_s16(
  self : AudioBuffer,
  little_endian? : Bool = true,
) -> Bytes {
  let output : Array[Byte] = []
  for sample in self.samples {
    let bits = sample.reinterpret_as_uint16()
    if little_endian {
      output.push(bits.to_byte())
      output.push((bits >> 8).to_byte())
    } else {
      output.push((bits >> 8).to_byte())
      output.push(bits.to_byte())
    }
  }
  Bytes::from_array(output)
}
