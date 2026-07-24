///|
pub struct SignalingStateMachine {
  mut state : SignalingState
  mut current_local : SessionDescription?
  mut current_remote : SessionDescription?
  mut pending_local : SessionDescription?
  mut pending_remote : SessionDescription?
}

///|
pub fn SignalingStateMachine::new() -> SignalingStateMachine {
  {
    state: Stable,
    current_local: None,
    current_remote: None,
    pending_local: None,
    pending_remote: None,
  }
}

///|
pub fn SignalingStateMachine::state(
  self : SignalingStateMachine,
) -> SignalingState {
  self.state
}

///|
pub fn SignalingStateMachine::local_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  match self.pending_local {
    Some(description) => Some(description)
    None => self.current_local
  }
}

///|
pub fn SignalingStateMachine::remote_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  match self.pending_remote {
    Some(description) => Some(description)
    None => self.current_remote
  }
}

///|
pub fn SignalingStateMachine::current_local_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  self.current_local
}

///|
pub fn SignalingStateMachine::current_remote_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  self.current_remote
}

///|
pub fn SignalingStateMachine::pending_local_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  self.pending_local
}

///|
pub fn SignalingStateMachine::pending_remote_description(
  self : SignalingStateMachine,
) -> SessionDescription? {
  self.pending_remote
}

///|
fn validate_description(
  description : SessionDescription,
) -> Unit raise SdpError {
  match description.sdp_type {
    Rollback =>
      if !description.sdp.is_empty() {
        raise InvalidSyntax("rollback description must have empty SDP")
      }
    Offer | Pranswer | Answer => ignore(description.datachannel_parameters())
  }
}

///|
fn SignalingStateMachine::commit_pending(self : SignalingStateMachine) -> Unit {
  match self.pending_local {
    Some(description) => self.current_local = Some(description)
    None => ()
  }
  match self.pending_remote {
    Some(description) => self.current_remote = Some(description)
    None => ()
  }
  self.pending_local = None
  self.pending_remote = None
  self.state = Stable
}

///|
fn SignalingStateMachine::rollback_pending(
  self : SignalingStateMachine,
) -> Unit {
  self.pending_local = None
  self.pending_remote = None
  self.state = Stable
}

///|
pub fn SignalingStateMachine::set_local_description(
  self : SignalingStateMachine,
  description : SessionDescription,
) -> Unit raise SdpError {
  if self.state == Closed {
    raise InvalidState("cannot set a description after close")
  }
  validate_description(description)
  match (self.state, description.sdp_type) {
    (Stable, Offer) => {
      self.pending_local = Some(description)
      self.state = HaveLocalOffer
    }
    (HaveRemoteOffer, Pranswer) => {
      self.pending_local = Some(description)
      self.state = HaveLocalPranswer
    }
    (HaveRemoteOffer | HaveLocalPranswer, Answer) => {
      self.pending_local = Some(description)
      self.commit_pending()
    }
    (HaveLocalOffer | HaveRemotePranswer, Rollback) => self.rollback_pending()
    _ => raise InvalidState("invalid local-description signaling transition")
  }
}

///|
pub fn SignalingStateMachine::set_remote_description(
  self : SignalingStateMachine,
  description : SessionDescription,
) -> Unit raise SdpError {
  if self.state == Closed {
    raise InvalidState("cannot set a description after close")
  }
  validate_description(description)
  match (self.state, description.sdp_type) {
    (Stable, Offer) => {
      self.pending_remote = Some(description)
      self.state = HaveRemoteOffer
    }
    (HaveLocalOffer, Pranswer) => {
      self.pending_remote = Some(description)
      self.state = HaveRemotePranswer
    }
    (HaveLocalOffer | HaveRemotePranswer, Answer) => {
      self.pending_remote = Some(description)
      self.commit_pending()
    }
    (HaveRemoteOffer | HaveLocalPranswer, Rollback) => self.rollback_pending()
    _ => raise InvalidState("invalid remote-description signaling transition")
  }
}

///|
pub fn SignalingStateMachine::close(self : SignalingStateMachine) -> Unit {
  self.pending_local = None
  self.pending_remote = None
  self.state = Closed
}
