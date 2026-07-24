///|
priv suberror SubscriberClosed

///|
priv struct Subscriber {
  id : UInt
  outbound : @async_runtime.Queue[String]
}

///|
priv struct Hub {
  subscribers : Array[Subscriber]
  mut next_id : UInt
}

///|
fn Hub::new() -> Hub {
  { subscribers: [], next_id: 1U }
}

///|
fn Hub::subscribe(self : Hub) -> Subscriber {
  let subscriber : Subscriber = {
    id: self.next_id,
    outbound: Queue(kind=Unbounded),
  }
  self.next_id += 1U
  self.subscribers.push(subscriber)
  subscriber
}

///|
fn Hub::unsubscribe(self : Hub, id : UInt) -> Unit {
  for index = 0; index < self.subscribers.length(); index = index + 1 {
    if self.subscribers[index].id == id {
      let subscriber = self.subscribers[index]
      ignore(self.subscribers.remove(index))
      subscriber.outbound.close(error=SubscriberClosed, clear=true)
      return
    }
  }
}

///|
fn Hub::broadcast(self : Hub, sender : UInt, text : String) -> Unit {
  for subscriber in self.subscribers {
    if subscriber.id != sender {
      ignore(subscriber.outbound.try_put(text) catch { _ => false })
    }
  }
}

///|
async fn send_signals(
  websocket : @websocket.Conn,
  subscriber : Subscriber,
) -> Unit {
  for ;; {
    let text = subscriber.outbound.get() catch {
      SubscriberClosed => return
      _ => return
    }
    websocket.send_text(text)
  }
}

///|
async fn main {
  let hub = Hub::new()
  let address = @socket.Addr::parse("127.0.0.1:9001")
  println("RTC signaling relay listening on ws://127.0.0.1:9001")
  let server = @http.Server(address)
  server.run_forever() <| ((request, _, connection) => {
    let websocket = @websocket.from_http_server(request, connection)
    let subscriber = hub.subscribe()
    defer {
      hub.unsubscribe(subscriber.id)
      websocket.close()
    }
    @async_runtime.with_task_group <| group => {
      group.spawn_bg(no_wait=true, () => send_signals(websocket, subscriber))
      try {
        for ;; {
          let message = websocket.recv()
          match message.kind {
            Text => hub.broadcast(subscriber.id, message.read_all().text())
            Binary =>
              websocket.send_close(
                code=UnsupportedData,
                reason="signaling messages must be UTF-8 text",
              )
          }
        }
      } catch {
        @websocket.ConnectionClosed(_, _) => ()
        _ => ()
      }
    }
  })
}
