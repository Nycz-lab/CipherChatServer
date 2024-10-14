use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use futures_util::stream::SplitSink;
use log::info;
use rusqlite::{params, Connection};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

use sha256::{digest};

use crate::util::KeyBundle;

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

    pub fn register_user(&self, username: String, password: String, keybundle: KeyBundle) -> Result<Uuid, String> {

        let uuid = Uuid::new_v4();

        let password = digest(password);

        let query = format!("INSERT INTO users(name, password, token) VALUES ('{username}', '{password}', '{uuid}')");
        let conn = self.conn.lock().unwrap();

        match conn.execute(&query, []){
            Ok(_) => {
                info!("successfully registered user to users!");
            },
            Err(e) => {
                println!("Error {}", e);
                return Err("Couldnt register User".to_string());
            }
        }

        let mut stmt = conn.prepare("SELECT user_id FROM users WHERE name=?1").unwrap();
        let id: Option<i32> = stmt.query_row(params![username], |row| row.get(0)).unwrap();

        let query = format!("INSERT INTO keybundles(identity, prekey, signature, user_id)
         VALUES ('{}', '{}', '{}', '{}')", keybundle.identity.public, keybundle.prekey.public, keybundle.signature.public, id.unwrap());

        match conn.execute(&query, []){
            Ok(_) => {
                println!("successfully registered bundle!");
            },
            Err(e) => {
                println!("Error {}", e);
                return Err("Couldnt register keybundle".to_string());
            }
        }

        let mut stmt = conn.prepare("SELECT bundle_id FROM keybundles WHERE user_id=?1").unwrap();
        let bundle_id: Option<i32> = stmt.query_row(params![id], |row| row.get(0)).unwrap();

        let mut stmt = conn.prepare("INSERT INTO one_time_keys(key, bundle_id) VALUES (?, ?)").unwrap();
        
        for otk in keybundle.onetime_keys{
            stmt.execute(params![otk.public, bundle_id]).unwrap();
        }


        Ok(uuid)
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
        CREATE TABLE users (
            user_id INTEGER PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL
        );
        CREATE TABLE keybundles (
            bundle_id INTEGER PRIMARY KEY,
            identity TEXT NOT NULL,
            prekey TEXT NOT NULL,
            signature TEXT NOT NULL,
            user_id      INTEGER NOT NULL,
            FOREIGN KEY (user_id)
                REFERENCES users (user_id) 
        );
        CREATE TABLE one_time_keys (
            key TEXT NOT NULL,
            bundle_id INTEGER NOT NULL,
            FOREIGN KEY (bundle_id)
                REFERENCES keybundles (bundle_id)
        );
    ";
        connection.execute_batch(query).unwrap();

        connection
    }
}
