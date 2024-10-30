//! A simple echo server.
//!
//! You can test this out by running:
//!
//!     cargo run --example echo-server 127.0.0.1:12345
//!
//! And then in another window run:
//!
//!     cargo run --example client ws://127.0.0.1:12345/
//!
//! Type a message into the client window, press enter to send it and
//! see it echoed back.

use std::{
    collections::HashMap,
    env,
    fs::{self, File},
    hash::Hash,
    io::{Error, Read},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt, TryStreamExt,
};
use lazy_static::lazy_static;
use log::info;
use node::CipherNode;
use server::CipherServer;
use std::io::{self, BufReader};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
    time,
};
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use util::OpAuthPayload;

use rustls_pemfile::{certs, rsa_private_keys};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio_rustls::rustls::{Certificate, PrivateKey};

use crate::{user_handler::UserDatabase, util::MsgPayload};
type WsWrite = Arc<Mutex<SplitSink<WebSocketStream<TlsStream<TcpStream>>, Message>>>;
type WsRead = Arc<Mutex<SplitStream<WebSocketStream<TlsStream<TcpStream>>>>>;


mod user_handler;
mod util;
mod server;
mod node;

/// Entrypoint des Programms
#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = env_logger::try_init();
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost:9999".to_string());


    let server = CipherServer::new(addr).await;

    server.process().await;

    Ok(())
}