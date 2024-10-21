use std::{collections::HashMap, net::SocketAddr, sync::Arc, thread};

use log::info;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::rustls::{Certificate, PrivateKey};

use crate::{node, user_handler::UserDatabase, util::{MsgPayload, OpAuthPayload}, WsRead, WsWrite};

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

// #[derive(Clone)]
pub struct CipherNode {
    addr: SocketAddr,
    session_db: Arc<Mutex<HashMap<String, Arc<Mutex<CipherNode>>>>>,
    user_db: Arc<Mutex<UserDatabase>>,
    msg_queue: Arc<Mutex<HashMap<String, Vec<MsgPayload>>>>,

    ws_write: Option<WsWrite>,
    ws_read: Option<WsRead>,

    authenticated: bool,
    username: Option<String>
}

impl CipherNode {
    pub fn new(
        addr: SocketAddr,
        session_db: Arc<Mutex<HashMap<String, Arc<Mutex<CipherNode>>>>>,
        user_db: Arc<Mutex<UserDatabase>>,
        msg_queue: Arc<Mutex<HashMap<String, Vec<MsgPayload>>>>,
    ) -> Self {
        Self {
            addr,
            session_db,
            user_db,
            msg_queue,
            ws_write: None,
            ws_read: None,
            authenticated: false,
            username: None
        }
    }

    pub async fn process(mut self, ws_stream: WebSocketStream<TlsStream<TcpStream>>){
        
        info!("New WebSocket connection: {}", self.addr);

        let (mut write, mut read) = ws_stream.split();

        // let ws_write = Arc::new(Mutex::new(write));
        // let ws_read = Arc::new(Mutex::new(read));

        let brr = Arc::new(Mutex::new(read));
        self.ws_read = Some(brr.clone());
        self.ws_write = Some(Arc::new(Mutex::new(write)));

        let node_ref = Arc::new(Mutex::new(self));


        while let Some(Ok(msg)) = brr.lock().await.next().await {
            match msg {
                Message::Text(txt) => {
                    // write.send(Message::Text(format!("Echo: {txt}"))).await.unwrap();
                    let msg: MsgPayload = serde_json::from_str(&txt).unwrap();
                    println!("received: {:?}", msg);
                    node_ref.clone().lock().await.message_handler(
                        msg,
                        node_ref.clone()
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

        node_ref.lock().await.cleanup().await;

        info!("connection ended");
    }

    pub async fn cleanup(&mut self) {
        // let x = session_db.WsSender.lock().await;
        if self.username.is_none(){
            return;
        }
        
        let x = self.session_db.clone();
        x.lock().await.remove(&self.username.clone().unwrap());

    }

    async fn message_handler(
        &mut self,
        mut message: MsgPayload,
        node_ref: Arc<Mutex<CipherNode>>
    ) {
        if message.clone().auth.is_some() && message.content.is_none() {
            println!("is auth req");

            let auth = message.clone().auth.unwrap();

            match auth.action.as_str() {
                "login" => self.login(auth, node_ref).await,
                "register" => self.register(auth, node_ref).await,
                "fetch_bundle" => {
                    self.fetch_bundle(message.clone()).await
                }
                _ => println!("no such auth action"),
            }
        } else {
            if message.recipient != "" {
                self.route_message(message).await;
            }
        }
    }

    async fn send_message(&mut self, mut message: MsgPayload){

        let mut send_stream = self.ws_write.as_mut().unwrap().lock().await;

        let json = serde_json::to_string(&message).unwrap();

        send_stream.send(Message::Text(json)).await.unwrap();
    }

    async fn route_message(
        &mut self,
        mut message: MsgPayload
    ) {
        if !self.user_db.lock().await.user_exists(message.recipient.clone()) {
            info!("non existent user requested");
            return;
        }

        let username = match &self.username{
            Some(v) => v.to_string(),
            None => {
                String::from("user not found")
            },
        };

        message.author = username.clone();

        // IMPORTANT without this the lock will never be aquired
        // if one messages themselves so the server will wait indefinitely
        if message.recipient == username{

            self.send_message(message).await;
            return;
        }


        let mut x = self.session_db.lock().await;


        match x.get_mut(&message.recipient){
            Some(node) => {
                node.lock().await.send_message(message).await;
            },
            None => {
                info!("target currently not online");

                let mut queue = self.msg_queue.lock().await;

                match queue.get_mut(&message.recipient.clone()) {
                    Some(v) => {
                        v.push(message);
                    }
                    None => {
                        let mut z: Vec<MsgPayload> = Vec::new();
                        z.push(message.clone());
                        queue.insert(message.recipient, z);
                    }
                };
            },
        };
        // TODO proper error handling and shit
    }

    async fn login(
        &mut self,
        auth: OpAuthPayload,
        node_ref: Arc<Mutex<CipherNode>>
    ) {
        println!("login req");
        let username = auth.user.as_str();
        let password = auth.password.as_str();

        // TODO: Implement login logic using user_db.login(username, password)
        
        match self.user_db.clone()
            .lock()
            .await
            .login(username.to_string(), password.to_string())
        {
            Ok(token) => {
                let answer = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: "Login successful".to_string(),
                        action: "login".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: None,
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: username.to_string(),
                };
                let json = serde_json::to_string(&answer).unwrap();
                let mut send_stream = self.ws_write.clone();
                let mut send_stream = send_stream.as_mut().unwrap().lock().await;
                send_stream.send(Message::Text(json)).await.unwrap();

                //fetch missed messages from queue
                let queue_lock = self.msg_queue.clone();
                let mut queue_lock = queue_lock.lock().await;
                let queue = match queue_lock.get_mut(username) {
                    Some(v) => v,
                    None => &mut Vec::new(),
                };
                info!(
                    "the following messages were sent while user was offline {:#?}",
                    queue
                );

                thread::sleep(time::Duration::from_secs(1));

                for msg in queue.clone() {
                    let json = serde_json::to_string(&msg).unwrap();
                    send_stream.send(Message::Text(json)).await.unwrap();
                }

                queue.clear();

                self.authenticate(username.to_owned(), node_ref).await;
            }
            Err(error) => {
                
                let answer = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: format!("Login failed: {}", error).to_string(),
                        action: "login".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: None,
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: username.to_string(),
                };
                let json = serde_json::to_string(&answer).unwrap();
                let mut send_stream = self.ws_write.as_mut().unwrap().lock().await;
                send_stream.send(Message::Text(json)).await.unwrap();
            }
        }
    }

    async fn authenticate(&mut self, username: String, node_ref: Arc<Mutex<CipherNode>>){

        self.authenticated = true;

        let db = self.session_db.clone();

        let mut db = db.lock().await;


        info!("authenticated {}", username);
        self.username = Some(username.clone());        
        db.insert(username, node_ref);
        

    }

    async fn register(
        &mut self,
        auth: OpAuthPayload,
        node_ref: Arc<Mutex<CipherNode>>
    ) {
        info!("requested register");

        let username = auth.user.as_str();
        let password = auth.password.as_str();
        let keybundle = auth.keybundle.unwrap();

        // TODO: Implement register logic using user_db.register_user(username, password)

        // Example: (Assuming UserDatabase.register_user() returns Result<(), String>)
        match self.user_db.clone().lock().await.register_user(
            username.to_string(),
            password.to_string(),
            keybundle,
        ) {
            Ok(token) => {
                let msg = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: "Registration successful".to_string(),
                        action: "register".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: None,
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: username.to_string(),
                };
                let mut send_stream = self.ws_write.clone();
                let mut send_stream = send_stream.as_mut().unwrap().lock().await;
                let json = serde_json::to_string(&msg).unwrap();
                send_stream.send(Message::Text(json)).await.unwrap();

                self.authenticate(username.to_owned(), node_ref).await;


                // println!("sessions: {:#?}", session_db.lock().await);
            }
            Err(error) => {
                let msg = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: format!("Registration failed {}", error).to_string(),
                        action: "register".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: None,
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: username.to_string(),
                };
                let mut send_stream = self.ws_write.as_mut().unwrap().lock().await;
                let json = serde_json::to_string(&msg).unwrap();
                send_stream.send(Message::Text(json)).await.unwrap();
            }
        }
    }

    async fn fetch_bundle(
        &self,
        mut og_msg: MsgPayload
    ) {
        info!("requested bundle fetch");

        

        og_msg.author = self.username.clone().unwrap();

        let auth = og_msg.auth.unwrap();

        let username = auth.user.as_str();

        if !self.user_db.lock().await.user_exists(username.to_string()) {
            info!("non existent user requested");
            return;
        }

        match self.user_db.lock().await.fetch_bundle(username.to_string()) {
            Ok(bundle) => {
                let msg = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: "fetched bundle".to_string(),
                        action: "fetch_bundle".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: Some(bundle),
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: og_msg.author.to_string(),
                };
                let mut send_stream = self.ws_write.clone();
                let mut send_stream = send_stream.as_mut().unwrap().lock().await;
                let json = serde_json::to_string(&msg).unwrap();
                send_stream.send(Message::Text(json)).await.unwrap();

                // println!("sessions: {:#?}", session_db.lock().await);
            }
            Err(error) => {
                let msg = MsgPayload {
                    content: None,
                    timestamp: self.getTimestamp(),
                    auth: Some(OpAuthPayload {
                        message: format!("fetching bundle failed {}", error).to_string(),
                        action: "fetch_bundle".to_string(),
                        user: username.to_string(),
                        password: "".to_string(),
                        keybundle: None,
                    }),
                    message_id: uuid::Uuid::new_v4().to_string(),
                    author: "System".to_string(),
                    recipient: og_msg.author.to_string(),
                };
                let mut send_stream = self.ws_write.clone();
                let mut send_stream = send_stream.as_mut().unwrap().lock().await;
                let json = serde_json::to_string(&msg).unwrap();
                send_stream.send(Message::Text(json)).await.unwrap();
            }
        }
    }

    fn getTimestamp(&self) -> u64 {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();
        timestamp
    }
}
