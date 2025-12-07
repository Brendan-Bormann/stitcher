# Stitcher

Connect stuff with QUIC & RUST easily. This is a dependancy for my other works.

```rust
let mut server = StitcherServer::new("127.0.0.1:8972".into());
server.accept_connections(|c| println!("server got a connection!")).await;

let mut client = StitcherClient::new("127.0.0.1:8973".into());
client.connect("127.0.0.1:8972".into()).await;
```
