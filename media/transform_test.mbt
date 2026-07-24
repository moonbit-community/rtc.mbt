///|
test "encoded transform pipeline composes payload stages with context" {
  let codec = CodecCapability::new(mime_type="video/vp8", clock_rate=90000U)
  let pipeline = EncodedTransformPipeline::new()
  pipeline.add(
    EncodedTransform::new(name="prefix", handler=(context, payload) => {
      if context.direction != TransformOutbound ||
        context.track_id != Some("video") {
        raise InvalidMedia("encoded transform context was not preserved")
      }
      b"\xaa" + payload
    }),
  )
  pipeline.add(
    EncodedTransform::new(name="suffix", handler=(_context, payload) => {
      payload + b"\xbb"
    }),
  )
  let transformed = pipeline.process(
    EncodedFrameContext::new(
      direction=TransformOutbound,
      track_id="video",
      codec~,
      ssrc=1U,
      sequence_number=2,
      timestamp=3U,
      marker=true,
    ),
    b"frame",
  )
  assert_eq(transformed, b"\xaaframe\xbb")
}

///|
test "encoded transform pipeline rejects duplicate stage names" {
  let pipeline = EncodedTransformPipeline::new()
  pipeline.add(
    EncodedTransform::new(name="same", handler=(_context, payload) => payload),
  )
  let mut rejected = false
  pipeline.add(
    EncodedTransform::new(name="same", handler=(_context, payload) => payload),
  ) catch {
    InvalidMedia(_) => rejected = true
    _ => fail("unexpected encoded transform error")
  }
  assert_true(rejected)
}
