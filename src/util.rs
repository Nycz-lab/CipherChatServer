use std::str::Utf8Error;


#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MsgPayload{
  pub content_type: String,
  pub content: String,
  pub timestamp: u64,
  pub auth: Option<OpAuthPayload>,
  pub token: String,
  pub author: String,
  pub recipient: String
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OpAuthPayload{
  pub action: String,
  pub user: String,
  pub password: String
}

