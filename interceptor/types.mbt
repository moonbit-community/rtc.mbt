///|
pub(all) suberror InterceptorError {
  InvalidConfiguration(String)
  PipelineFailed(String)
} derive(Debug, Eq)

///|
pub(all) enum Direction {
  Inbound
  Outbound
} derive(Debug, Eq)

///|
pub(all) enum Packet {
  Rtp(@rtp.Packet)
  Rtcp(@rtcp.Packet)
} derive(Debug, Eq)

///|
pub(all) struct Context {
  direction : Direction
  stream_id : String?
} derive(Debug, Eq)

///|
pub fn Context::new(direction~ : Direction, stream_id? : String) -> Context {
  { direction, stream_id }
}

///|
pub fn Context::direction(self : Context) -> Direction {
  self.direction
}

///|
pub fn Context::stream_id(self : Context) -> String? {
  self.stream_id
}

///|
pub struct Stage {
  name : String
  handler : (Context, Packet) -> Array[Packet] raise InterceptorError
}

///|
pub fn Stage::new(
  name~ : String,
  handler~ : (Context, Packet) -> Array[Packet] raise InterceptorError,
) -> Stage raise InterceptorError {
  if name.is_empty() {
    raise InvalidConfiguration("interceptor stage name is empty")
  }
  { name, handler }
}

///|
pub fn Stage::name(self : Stage) -> String {
  self.name
}

///|
pub struct Pipeline {
  stages : Array[Stage]
}

///|
pub fn Pipeline::new() -> Pipeline {
  { stages: [] }
}

///|
pub fn Pipeline::add(self : Pipeline, stage : Stage) -> Unit {
  self.stages.push(stage)
}

///|
pub fn Pipeline::length(self : Pipeline) -> Int {
  self.stages.length()
}

///|
pub fn Pipeline::process(
  self : Pipeline,
  context : Context,
  packet : Packet,
) -> Array[Packet] raise InterceptorError {
  let mut current : Array[Packet] = [packet]
  for stage in self.stages {
    let next : Array[Packet] = []
    for candidate in current {
      let transformed = (stage.handler)(context, candidate)
      for output in transformed {
        next.push(output)
      }
    }
    current = next
    if current.is_empty() {
      break
    }
  }
  current
}
