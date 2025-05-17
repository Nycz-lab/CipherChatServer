## CipherChat

This is my IHK Project

its a relatively simple Chat Application that
in itself is quite basic.
However the complete Communication is end to end encrypted
and, due to being written in Rust, quite fast, safe and minimal.

Abritrary bytes can be transmitted, therefore the client handles the chat-features. Currently Images and simple String Messages are supported by the client implementation.

The Protocol used for end to end encryption is 
Signals X3DH Protocol (https://signal.org/docs/specifications/x3dh/)

The Project utilizes TLS WebSockets and a SQLite DB (for storing Public Keys) and a Message Queue System for distributing Messages even when clients are offline on the Backend. (You also are required to have a valid Certificate due to TLS or generate a self signed cert yourself and distribute it with the Client)

The Client is also written in Rust. The Tauri Framework is used for utilizing Js with React in the Frontend.

- © Nick Weber 2025