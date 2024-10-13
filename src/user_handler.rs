use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use futures_util::stream::SplitSink;
use rusqlite::Connection;
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use sha256::{digest};

pub struct UserDatabase {
    conn: Arc<Mutex<Connection>>,
}


impl UserDatabase {
    pub async fn new() -> Self {

        let conn = create_table_it_not_exist().await;


        UserDatabase {
            conn: Arc::new(Mutex::new(conn)),
        }
    }

    pub fn register_user(&self, username: String, password: String) -> Result<Uuid, String> {

        let uuid = Uuid::new_v4();

        let password = digest(password);

        let query = format!("INSERT INTO users VALUES ('{username}', '{password}', '{uuid}')");
        println!("{}", query.clone());
        let conn = self.conn.lock().unwrap();

        match conn.execute(&query, []){
            Ok(_) => {
                println!("success!");
                Ok(uuid)},
            Err(e) => {
                println!("Error {}", e);
                Err("Couldnt register User".to_string())
            }
        }

    }

    pub fn login(&self, username: String, password: String) -> Result<Uuid, String> {

        let uuid = Uuid::new_v4();

        let password = digest(password);

        let query = format!("UPDATE users SET token = '{uuid}' WHERE name = '{username}' AND password = '{password}'");
        println!("{}", query.clone());

        let conn = self.conn.lock().unwrap();

        let num = match conn.execute(&query, []){
            Ok(num) => num,
            Err(e) => 0
        };

        if num > 0{
            println!("success!");
            Ok(uuid)
        }else{
            Err("Couldnt find User".to_string())
        }

    }
}

async fn create_table_it_not_exist() -> Connection {
    if (Path::new("test.db").exists()) {
        let connection = Connection::open("test.db").unwrap();
        connection
    } else {
        let connection = Connection::open("test.db").unwrap();

        let query = "
        CREATE TABLE users (name TEXT UNIQUE, password TEXT, token TEXT UNIQUE);
    ";
        connection.execute(query, []).unwrap();

        connection
    }
}
