use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use log::info;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use tokio_rustls::rustls::{Certificate, PrivateKey};

use crate::{node::CipherNode, user_handler::UserDatabase, util::MsgPayload};

use std::{
    env,
    fs::{self, File},
    hash::Hash,
    io::{Error, Read},
    time::{SystemTime, UNIX_EPOCH},
};

use futures_util::{
    future,
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt, TryStreamExt,
};
use lazy_static::lazy_static;
use rustls_pemfile::{certs, rsa_private_keys};
use std::io::{self, BufReader};
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio::time;
use tokio_rustls::{rustls, server::TlsStream, TlsAcceptor};
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};

pub struct CipherServer {
    session_db: Arc<Mutex<HashMap<String, Arc<Mutex<CipherNode>>>>>,
    user_db: Arc<Mutex<UserDatabase>>,
    msg_queue: Arc<Mutex<HashMap<String, Vec<MsgPayload>>>>,
    listener: TcpListener,
}

impl CipherServer {
    pub async fn new(addr: String) -> Self {
        let try_socket = TcpListener::bind(&addr).await;
        let listener = try_socket.expect("Failed to bind");
        info!("Listening on: {}", addr);

        let user_db: Arc<Mutex<UserDatabase>> = Arc::new(Mutex::new(UserDatabase::new().await));
        let session_db = Arc::new(Mutex::new(HashMap::new()));

        let msg_queue: Arc<Mutex<HashMap<String, Vec<MsgPayload>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        Self {
            session_db,
            user_db,
            msg_queue,
            listener,
        }
    }

    pub async fn process(&self) {
        while let Ok((stream, addr)) = self.listener.accept().await {
            // let node = CipherNode::new(stream, addr);

            tokio::spawn(accept_connection(
                stream,
                addr,
                self.session_db.clone(),
                self.user_db.clone(),
                self.msg_queue.clone(),
            ));

            // node.cleanup();
        }
    }
}

pub async fn accept_connection(
    stream: TcpStream,
    addr: SocketAddr,
    session_db: Arc<Mutex<HashMap<String, Arc<Mutex<CipherNode>>>>>,
    user_db: Arc<Mutex<UserDatabase>>,
    msg_queue: Arc<Mutex<HashMap<String, Vec<MsgPayload>>>>,
) {
    let addr = stream
        .peer_addr()
        .expect("connected streams should have a peer address");

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

    let ws_stream: WebSocketStream<TlsStream<TcpStream>> = tokio_tungstenite::accept_async(stream)
        .await
        .expect("Error during the websocket handshake occurred");

    let mut x = CipherNode::new(addr, session_db.clone(), user_db.clone(), msg_queue.clone());

    x.process(ws_stream).await;
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
