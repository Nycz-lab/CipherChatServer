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

#[derive(Clone)]
struct SessionInfo {
    WsSender: Arc<Mutex<HashMap<String, WsWrite>>>,
    WsRcvr: Arc<Mutex<HashMap<String, String>>>,
}

mod user_handler;
mod util;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let _ = env_logger::try_init();
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost:9999".to_string());

    // Create the event loop and TCP listener we'll accept connections on.
    let try_socket = TcpListener::bind(&addr).await;
    let listener = try_socket.expect("Failed to bind");
    info!("Listening on: {}", addr);

    let user_db: Arc<Mutex<UserDatabase>> = Arc::new(Mutex::new(UserDatabase::new().await));
    let session_db = SessionInfo {
        WsSender: Arc::new(Mutex::new(HashMap::new())),
        WsRcvr: Arc::new(Mutex::new(HashMap::new())),
    };

    while let Ok((stream, addr)) = listener.accept().await {
        tokio::spawn(accept_connection(
            stream,
            user_db.clone(),
            session_db.clone(),
        ));
    }

    Ok(())
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

async fn accept_connection(
    stream: TcpStream,
    user_db: Arc<tokio::sync::Mutex<UserDatabase>>,
    session_db: SessionInfo,
) {
    let addr = stream
        .peer_addr()
        .expect("connected streams should have a peer address");
    info!("Peer address: {}", addr);

    let certs = load_certs(Path::new("localhost.crt")).unwrap();
    let mut keys = load_keys(Path::new("localhost.key")).unwrap();

    let tls_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
        .unwrap();

    let tls_config = Arc::new(tls_config);
    let acceptor = TlsAcceptor::from(tls_config);

    let mut stream = acceptor.accept(stream).await.unwrap();

    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    info!("New WebSocket connection: {}", addr);

    let (mut write, mut read) = ws_stream.split();

    let ws_write = Arc::new(Mutex::new(write));
    let ws_read = Arc::new(Mutex::new(read));

    while let Some(Ok(msg)) = ws_read.lock().await.next().await {
        match msg {
            Message::Text(txt) => {
                // write.send(Message::Text(format!("Echo: {txt}"))).await.unwrap();
                let msg: MsgPayload = serde_json::from_str(&txt).unwrap();
                println!("received: {:?}", msg);
                message_handler(
                    msg,
                    &user_db,
                    session_db.clone(),
                    &mut ws_write.clone(),
                    &mut ws_read.clone(),
                )
                .await;
            }
            Message::Binary(_) => todo!(),
            Message::Ping(_) => todo!(),
            Message::Pong(_) => todo!(),
            Message::Close(_) => {
                println!("conn closed")
            }
            Message::Frame(_) => todo!(),
        }
    }

    println!("done with all teh shit");

    // // We should not forward messages other than text or binary.
    // read.try_filter(|msg| future::ready(msg.is_text() || msg.is_binary()))
    //     .forward(write)
    //     .await
    //     .expect("Failed to forward messages")
}

async fn message_handler(
    message: MsgPayload,
    user_db: &Arc<tokio::sync::Mutex<UserDatabase>>,
    session_db: SessionInfo,
    write: &mut WsWrite,
    read: &mut WsRead,
) {
    if let Some(auth) = message.auth {
        println!("is auth req");

        match auth.action.as_str() {
            "login" => login(auth, user_db, session_db, write, read).await,
            "register" => register(auth, user_db, session_db, write, read).await,
            _ => println!("no such auth action"),
        }
    }else{
        if message.content_type == "message" && message.recipient != "" && message.token != "" {
            route_message(message, user_db, session_db, write).await;
        }
    }

    
}

async fn route_message(
    mut message: MsgPayload,
    user_db: &Arc<tokio::sync::Mutex<UserDatabase>>,
    session_db: SessionInfo,
    write: &mut WsWrite,
) {


    message.author = session_db.WsRcvr.lock().await.get(&message.token).unwrap().to_string();
    let x = session_db.WsSender.lock().await;
    let send_stream = x.get(&message.recipient);

    if let Some(y) = send_stream {
        let mut send_stream = y.lock().await;

    
        let json = serde_json::to_string(&message).unwrap();

        send_stream.send(Message::Text(json)).await.unwrap();
    }
    // TODO proper error handling and shit

}

async fn login(
    auth: OpAuthPayload,
    user_db: &Arc<tokio::sync::Mutex<UserDatabase>>,
    session_db: SessionInfo,
    write: &mut WsWrite,
    read: &mut WsRead,
) {
    println!("login req");
    let username = auth.user.as_str();
    let password = auth.password.as_str();

    // TODO: Implement login logic using user_db.login(username, password)

    match user_db
        .lock()
        .await
        .login(username.to_string(), password.to_string())
    {
        Ok(token) => {
            let answer = MsgPayload {
                content_type: "auth".to_string(),
                content: "Login successful".to_string(),
                timestamp: getTimestamp(),
                auth: Some(OpAuthPayload{ action: "login".to_string(), user: username.to_string(), password: "".to_string() }),
                token: token.to_string(),
                author: "System".to_string(),
                recipient: username.to_string(),
            };
            let json = serde_json::to_string(&answer).unwrap();
            write.lock().await.send(Message::Text(json)).await.unwrap();

            let mut sender_list = session_db.WsSender.lock().await;
            let mut rcvr_list = session_db.WsRcvr.lock().await;

            if sender_list.contains_key(username) {
                sender_list.remove(username);
            }

            sender_list.insert(username.to_string(), write.clone());

            if rcvr_list.contains_key(&token.to_string()) {
                sender_list.remove(&token.to_string());
            }

            rcvr_list.insert(token.to_string(), username.to_string());
        }
        Err(error) => {
            let answer = MsgPayload {
                content_type: "auth".to_string(),
                content: format!("Login failed: {}", error).to_string(),
                timestamp: getTimestamp(),
                auth: Some(OpAuthPayload{ action: "login".to_string(), user: username.to_string(), password: "".to_string() }),
                token: "".to_string(),
                author: "System".to_string(),
                recipient: username.to_string(),
            };
            let json = serde_json::to_string(&answer).unwrap();
            write.lock().await.send(Message::Text(json)).await.unwrap();
        }
    }
}

async fn register(
    auth: OpAuthPayload,
    user_db: &Arc<tokio::sync::Mutex<UserDatabase>>,
    session_db: SessionInfo,
    write: &mut WsWrite,
    read: &mut WsRead,
) {
    println!("reg req");

    let username = auth.user.as_str();
    let password = auth.password.as_str();

    // TODO: Implement register logic using user_db.register_user(username, password)

    // Example: (Assuming UserDatabase.register_user() returns Result<(), String>)
    match user_db
        .lock()
        .await
        .register_user(username.to_string(), password.to_string())
    {
        Ok(token) => {
            let msg = MsgPayload {
                content_type: "auth".to_string(),
                content: "Registration successful".to_string(),
                timestamp: getTimestamp(),
                auth: Some(OpAuthPayload{ action: "register".to_string(), user: username.to_string(), password: "".to_string() }),
                token: token.to_string(),
                author: "System".to_string(),
                recipient: username.to_string(),
            };
            let json = serde_json::to_string(&msg).unwrap();
            write.lock().await.send(Message::Text(json)).await.unwrap();

            let mut sender_list = session_db.WsSender.lock().await;
            let mut rcvr_list = session_db.WsRcvr.lock().await;

            if sender_list.contains_key(username) {
                sender_list.remove(username);
            }

            sender_list.insert(username.to_string(), write.clone());

            if rcvr_list.contains_key(&token.to_string()) {
                sender_list.remove(&token.to_string());
            }

            rcvr_list.insert(token.to_string(), username.to_string());

            // println!("sessions: {:#?}", session_db.lock().await);
        }
        Err(error) => {
            let msg = MsgPayload {
                content_type: "auth".to_string(),
                content: format!("Registration failed {}", error).to_string(),
                timestamp: getTimestamp(),
                auth: Some(OpAuthPayload{ action: "register".to_string(), user: username.to_string(), password: "".to_string() }),
                token: "".to_string(),
                author: "System".to_string(),
                recipient: username.to_string(),
            };
            let json = serde_json::to_string(&msg).unwrap();
            write.lock().await.send(Message::Text(json)).await.unwrap();
        }
    }
}

fn getTimestamp() -> u64 {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
    timestamp
}
