# Stitcher

Connect stuff with QUIC & Rust easily. This is a dependancy for my other works.

```rust
let mut server = StitcherServer::new("127.0.0.1:3000".into());
server.accept_connections(|c| println!("server got a connection!")).await;

let mut client = StitcherClient::new("127.0.0.1:3001".into());
client.connect("127.0.0.1:3000".into()).await;
```
