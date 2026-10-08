///|
test "encoded transform pipeline composes payload stages with context" {
  let codec = @media.CodecCapability::new(
    mime_type="video/vp8",
    clock_rate=90000U,
  )
  let pipeline = @media.EncodedTransformPipeline::new()
  pipeline.add(
    @media.EncodedTransform::new(name="prefix", handler=(context, payload) => {
      if context.direction != TransformOutbound ||
        context.track_id != Some("video") {
        raise InvalidMedia("encoded transform context was not preserved")
      }
      b"\xaa" + payload
    }),
  )
  pipeline.add(
    @media.EncodedTransform::new(name="suffix", handler=(_context, payload) => {
      payload + b"\xbb"
    }),
  )
  let transformed = pipeline.process(
    @media.EncodedFrameContext::new(
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
  let pipeline = @media.EncodedTransformPipeline::new()
  pipeline.add(
    @media.EncodedTransform::new(name="same", handler=fn(_context, payload) {
      payload
    }),
  )
  let mut rejected = false
  pipeline.add(
    @media.EncodedTransform::new(name="same", handler=fn(_context, payload) {
      payload
    }),
  ) catch {
    InvalidMedia(_) => rejected = true
    _ => fail("unexpected encoded transform error")
  }
  assert_true(rejected)
}
