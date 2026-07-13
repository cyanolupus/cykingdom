use worker::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub points: i32,
    pub last_gacha_date: Option<String>,
    pub icon_url: Option<String>,
}

fn deserialize_bool_from_number<'de, D>(deserializer: D) -> std::result::Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val: f64 = serde::Deserialize::deserialize(deserializer)?;
    Ok(val > 0.5)
}

#[derive(Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub sign_count: f64,
    pub aaguid: Vec<u8>,
    #[serde(deserialize_with = "deserialize_bool_from_number")]
    pub is_backed_up: bool,
    #[serde(deserialize_with = "deserialize_bool_from_number")]
    pub is_user_verified: bool,
    pub attestation_fmt: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthChallenge {
    pub id: String,
    pub challenge: String,
    pub pending_user_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct Match {
    pub id: String,
    pub player1_id: String,
    pub player1_hand: String,
    pub player2_id: Option<String>,
    pub player2_hand: Option<String>,
    pub status: String, // 'open' or 'resolved'
    pub created_at: Option<String>,
}

pub async fn get_user_by_username(d1: &D1Database, username: &str) -> Result<Option<User>> {
    let statement = d1.prepare("SELECT * FROM users WHERE username = ?1");
    let result = statement.bind(&[username.into()])?.first::<User>(None).await?;
    Ok(result)
}

pub async fn get_user_by_id(d1: &D1Database, id: &str) -> Result<Option<User>> {
    let statement = d1.prepare("SELECT * FROM users WHERE id = ?1");
    let result = statement.bind(&[id.into()])?.first::<User>(None).await?;
    Ok(result)
}

pub async fn create_user(d1: &D1Database, id: &str, username: &str) -> Result<()> {
    let statement = d1.prepare("INSERT INTO users (id, username, points) VALUES (?1, ?2, 0)");
    statement.bind(&[id.into(), username.into()])?.run().await?;
    Ok(())
}

pub async fn update_user_icon(d1: &D1Database, id: &str, icon_url: &str) -> Result<()> {
    let statement = d1.prepare("UPDATE users SET icon_url = ?1 WHERE id = ?2");
    statement.bind(&[icon_url.into(), id.into()])?.run().await?;
    Ok(())
}

pub async fn get_top_users(d1: &D1Database, limit: usize) -> Result<Vec<User>> {
    let statement = d1.prepare("SELECT * FROM users WHERE username != 'admin' ORDER BY points DESC LIMIT ?1");
    let result = statement.bind(&[(limit as i32).into()])?.all().await?;
    let users: Vec<User> = result.results()?;
    Ok(users)
}

#[derive(serde::Deserialize)]
struct RankResult {
    rank: u32,
}

pub async fn get_user_rank(d1: &D1Database, points: i32) -> Result<u32> {
    let statement = d1.prepare("SELECT COUNT(*) + 1 as rank FROM users WHERE points > ?1 AND username != 'admin'");
    let result = statement.bind(&[points.into()])?.first::<RankResult>(None).await?;
    Ok(result.map(|r| r.rank).unwrap_or(1))
}

pub async fn save_credential(d1: &D1Database, cred: &Credential) -> Result<()> {
    let statement = d1.prepare("INSERT INTO credentials (id, user_id, public_key, sign_count, aaguid, is_backed_up, is_user_verified, attestation_fmt) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)");
    statement.bind(&[
        cred.id.clone().into(),
        cred.user_id.clone().into(),
        cred.public_key.clone().into(),
        cred.sign_count.into(),
        cred.aaguid.clone().into(),
        (if cred.is_backed_up { 1 } else { 0 }).into(),
        (if cred.is_user_verified { 1 } else { 0 }).into(),
        cred.attestation_fmt.clone().into()
    ])?.run().await?;
    Ok(())
}

pub async fn get_credentials_by_user(d1: &D1Database, user_id: &str) -> Result<Vec<Credential>> {
    let statement = d1.prepare("SELECT * FROM credentials WHERE user_id = ?1");
    let result = statement.bind(&[user_id.into()])?.all().await?;
    let creds: Vec<Credential> = result.results()?;
    Ok(creds)
}

pub async fn get_credential_by_id(d1: &D1Database, id: &str) -> Result<Option<Credential>> {
    let statement = d1.prepare("SELECT * FROM credentials WHERE id = ?1");
    let result = statement.bind(&[id.into()])?.first::<Credential>(None).await?;
    Ok(result)
}

pub async fn update_credential_sign_count(d1: &D1Database, id: &str, sign_count: i32) -> Result<()> {
    let statement = d1.prepare("UPDATE credentials SET sign_count = ?1 WHERE id = ?2");
    statement.bind(&[sign_count.into(), id.into()])?.run().await?;
    Ok(())
}

pub async fn create_auth_challenge(d1: &D1Database, id: &str, challenge: &str, pending_user_id: Option<&str>) -> Result<()> {
    let statement = d1.prepare("INSERT INTO auth_challenges (id, challenge, pending_user_id) VALUES (?1, ?2, ?3)");
    let uid_val = match pending_user_id {
        Some(uid) => worker::wasm_bindgen::JsValue::from_str(uid),
        None => worker::wasm_bindgen::JsValue::NULL,
    };
    statement.bind(&[id.into(), challenge.into(), uid_val])?.run().await?;
    Ok(())
}

pub async fn get_auth_challenge(d1: &D1Database, id: &str) -> Result<Option<AuthChallenge>> {
    let statement = d1.prepare("SELECT * FROM auth_challenges WHERE id = ?1");
    let result = statement.bind(&[id.into()])?.first::<AuthChallenge>(None).await?;
    Ok(result)
}

pub async fn delete_auth_challenge(d1: &D1Database, id: &str) -> Result<bool> {
    let statement = d1.prepare("DELETE FROM auth_challenges WHERE id = ?1");
    let result = statement.bind(&[id.into()])?.run().await?;
    Ok(result.success() && result.meta().ok().flatten().map(|m| m.changes.unwrap_or(0)).unwrap_or(0) > 0)
}

pub async fn create_session(d1: &D1Database, id: &str, user_id: &str) -> Result<()> {
    let statement = d1.prepare("INSERT INTO sessions (id, user_id) VALUES (?1, ?2)");
    statement.bind(&[id.into(), user_id.into()])?.run().await?;
    Ok(())
}

pub async fn get_session(d1: &D1Database, id: &str) -> Result<Option<Session>> {
    let statement = d1.prepare("SELECT * FROM sessions WHERE id = ?1");
    let result = statement.bind(&[id.into()])?.first::<Session>(None).await?;
    Ok(result)
}

pub async fn find_match(d1: &D1Database, user_id: &str) -> Result<Option<Match>> {
    let sql = "
        SELECT * FROM matches 
        WHERE status = 'open' 
          AND player1_id != ?1
          AND player1_id NOT IN (
              SELECT player1_id FROM matches WHERE status = 'resolved' AND player2_id = ?1 AND created_at > datetime('now', '-1 minute')
              UNION
              SELECT player2_id FROM matches WHERE status = 'resolved' AND player1_id = ?1 AND created_at > datetime('now', '-1 minute')
          )
        ORDER BY created_at ASC LIMIT 1
    ";
    let statement = d1.prepare(sql);
    let result = statement.bind(&[user_id.into()])?.first::<Match>(None).await?;
    Ok(result)
}

pub async fn create_match(d1: &D1Database, m: &Match) -> Result<()> {
    let statement = d1.prepare("INSERT INTO matches (id, player1_id, player1_hand, status) VALUES (?1, ?2, ?3, 'open')");
    statement.bind(&[
        m.id.clone().into(),
        m.player1_id.clone().into(),
        m.player1_hand.clone().into()
    ])?.run().await?;
    Ok(())
}

pub async fn resolve_match(d1: &D1Database, id: &str, p2_id: &str, p2_hand: &str) -> Result<bool> {
    let statement = d1.prepare("UPDATE matches SET player2_id = ?1, player2_hand = ?2, status = 'resolved' WHERE id = ?3 AND status = 'open'");
    let result = statement.bind(&[
        p2_id.into(),
        p2_hand.into(),
        id.into()
    ])?.run().await?;
    
    Ok(result.success() && result.meta().ok().flatten().map(|m| m.changes.unwrap_or(0)).unwrap_or(0) > 0)
}

pub async fn get_user_matches(d1: &D1Database, user_id: &str) -> Result<Vec<Match>> {
    let sql = "SELECT * FROM matches WHERE player1_id = ?1 OR player2_id = ?1 ORDER BY created_at DESC LIMIT 10";
    let statement = d1.prepare(sql);
    let result = statement.bind(&[user_id.into()])?.all().await?;
    let matches: Vec<Match> = result.results()?;
    Ok(matches)
}


#[derive(Serialize, Deserialize)]
pub struct Gift {
    pub id: String,
    pub points: i32,
    pub description: String,
    #[serde(deserialize_with = "deserialize_bool_from_number")]
    pub is_opened: bool,
    pub created_at: Option<String>,
}

pub async fn distribute_gift(d1: &D1Database, id: &str, points: i32, description: &str) -> Result<()> {
    let statement = d1.prepare("INSERT INTO gifts (id, points, description) VALUES (?1, ?2, ?3)");
    statement.bind(&[id.into(), points.into(), description.into()])?.run().await?;
    let users = get_top_users(d1, 99999).await?;
    for user in users {
        let user_gift_id = crate::api::uuid();
        let _ = d1.prepare("INSERT INTO user_gifts (id, user_id, gift_id) VALUES (?1, ?2, ?3)")
            .bind(&[user_gift_id.into(), user.id.into(), id.into()])?.run().await?;
    }
    Ok(())
}

pub async fn get_user_gifts(d1: &D1Database, user_id: &str) -> Result<Vec<Gift>> {
    let statement = d1.prepare("SELECT ug.id as id, g.points as points, g.description as description, ug.is_opened as is_opened, g.created_at as created_at FROM user_gifts ug JOIN gifts g ON ug.gift_id = g.id WHERE ug.user_id = ?1 AND ug.is_opened = 0");
    let result = statement.bind(&[user_id.into()])?.all().await?;
    result.results()
}

pub async fn get_user_gift(d1: &D1Database, user_id: &str, gift_id: &str) -> Result<Option<Gift>> {
    let statement = d1.prepare("SELECT ug.id as id, g.points as points, g.description as description, ug.is_opened as is_opened, g.created_at as created_at FROM user_gifts ug JOIN gifts g ON ug.gift_id = g.id WHERE ug.user_id = ?1 AND ug.id = ?2");
    let result = statement.bind(&[user_id.into(), gift_id.into()])?.first::<Gift>(None).await?;
    Ok(result)
}

pub async fn open_gift(d1: &D1Database, user_id: &str, gift_id: &str) -> Result<bool> {
    let statement = d1.prepare("UPDATE user_gifts SET is_opened = 1 WHERE user_id = ?1 AND id = ?2 AND is_opened = 0");
    let result = statement.bind(&[user_id.into(), gift_id.into()])?.run().await?;
    Ok(result.success() && result.meta().ok().flatten().map(|m| m.changes.unwrap_or(0)).unwrap_or(0) > 0)
}
