use std::str::Utf8Error;


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MsgPayload{
  pub content: Option<MsgContent>,
  pub timestamp: u64,
  pub auth: Option<OpAuthPayload>,
  pub message_id: String,
  pub author: String,
  pub recipient: String
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OpAuthPayload{
  pub action: String,
  pub user: String,
  pub password: String,
  pub keybundle: Option<KeyBundle>,
  pub message: String,
  pub success: Option<bool>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MsgContent{
  pub ciphertext: String,
  pub nonce: String,
  pub cleartext: Option<String>
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyBundle{
  pub identity: KeyPairB64,
  pub prekey: KeyPairB64,
  pub signature: KeyPairB64,
  pub onetime_keys: Vec<KeyPairB64>,
  pub ephemeral_key: Option<KeyPairB64>
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeyPairB64{
  pub public: String,
  pub private: Option<String>
}
