///|
test "audio buffer converts layouts and slices complete frames" {
  let interleaved = @media.AudioBuffer::new(
    samples=[1, 10, 2, 20, 3, 30],
    channels=2,
  )
  assert_eq(interleaved.frames(), 3)
  assert_eq(interleaved.sample(0, 1), 2)
  assert_eq(interleaved.sample(1, 1), 20)
  let deinterleaved = interleaved.with_layout(Deinterleaved)
  assert_eq(deinterleaved.samples(), [1, 2, 3, 10, 20, 30])
  assert_eq(
    deinterleaved.with_layout(Interleaved).samples(),
    interleaved.samples(),
  )
  assert_eq(deinterleaved.slice_frames(1, 3).samples(), [2, 3, 20, 30])
}

///|
test "audio buffer reads and writes signed PCM in both byte orders" {
  let little = b"\x00\x80\xff\xff\x00\x00\xff\x7f"
  let buffer = @media.AudioBuffer::from_pcm_s16(little, channels=2)
  assert_eq(buffer.samples(), [
    Int16::from_int(-32768),
    Int16::from_int(-1),
    Int16::from_int(0),
    Int16::from_int(32767),
  ])
  assert_eq(buffer.to_pcm_s16(), little)
  let big = b"\x80\x00\xff\xff\x00\x00\x7f\xff"
  assert_eq(
    @media.AudioBuffer::from_pcm_s16(big, channels=2, little_endian=false).to_pcm_s16(
      little_endian=false,
    ),
    big,
  )
}

///|
test "audio buffer rejects partial samples and channel frames" {
  let mut rejected_partial_sample = false
  ignore(@media.AudioBuffer::from_pcm_s16(b"\x00", channels=1)) catch {
    InvalidMedia(_) => rejected_partial_sample = true
    _ => fail("unexpected audio buffer error")
  }
  assert_true(rejected_partial_sample)
  let mut rejected_partial_frame = false
  ignore(@media.AudioBuffer::new(samples=[1, 2, 3], channels=2)) catch {
    InvalidMedia(_) => rejected_partial_frame = true
    _ => fail("unexpected audio buffer error")
  }
  assert_true(rejected_partial_frame)
}
