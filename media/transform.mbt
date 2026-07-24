///|
pub(all) enum TransformDirection {
  TransformInbound
  TransformOutbound
} derive(Debug, Eq)

///|
pub(all) struct EncodedFrameContext {
  direction : TransformDirection
  track_id : String?
  codec : CodecCapability
  ssrc : UInt
  sequence_number : UInt16
  timestamp : UInt
  marker : Bool
} derive(Debug, Eq)

///|
pub fn EncodedFrameContext::new(
  direction~ : TransformDirection,
  track_id? : String,
  codec~ : CodecCapability,
  ssrc~ : UInt,
  sequence_number~ : UInt16,
  timestamp~ : UInt,
  marker~ : Bool,
) -> EncodedFrameContext {
  { direction, track_id, codec, ssrc, sequence_number, timestamp, marker }
}

///|
pub struct EncodedTransform {
  name : String
  handler : (EncodedFrameContext, Bytes) -> Bytes raise MediaError
}

///|
pub fn EncodedTransform::new(
  name~ : String,
  handler~ : (EncodedFrameContext, Bytes) -> Bytes raise MediaError,
) -> EncodedTransform raise MediaError {
  if name.is_empty() || name.contains("\r") || name.contains("\n") {
    raise InvalidMedia("encoded transform name is invalid")
  }
  { name, handler }
}

///|
pub fn EncodedTransform::name(self : EncodedTransform) -> String {
  self.name
}

///|
pub struct EncodedTransformPipeline {
  stages : Array[EncodedTransform]
}

///|
pub fn EncodedTransformPipeline::new() -> EncodedTransformPipeline {
  { stages: [] }
}

///|
pub fn EncodedTransformPipeline::add(
  self : EncodedTransformPipeline,
  stage : EncodedTransform,
) -> Unit raise MediaError {
  if self.stages.any(existing => existing.name == stage.name) {
    raise InvalidMedia("encoded transform name is duplicated")
  }
  self.stages.push(stage)
}

///|
pub fn EncodedTransformPipeline::length(self : EncodedTransformPipeline) -> Int {
  self.stages.length()
}

///|
pub fn EncodedTransformPipeline::process(
  self : EncodedTransformPipeline,
  context : EncodedFrameContext,
  payload : Bytes,
) -> Bytes raise MediaError {
  let mut transformed = payload
  for stage in self.stages {
    transformed = (stage.handler)(context, transformed)
  }
  transformed
}
