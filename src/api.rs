use worker::*;
use kangoufu::rp::{RelyingParty, RegistrationVerificationOptions, AuthenticationVerificationOptions, UserVerificationRequirement};
use kangoufu::DefaultEnv;
use serde::Deserialize;
use crate::db;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

fn rp(req: &Request, env: &Env) -> Result<RelyingParty> {
    let url = req.url()?;
    let host = url.host_str().unwrap_or("localhost");
    
    let origin = req.headers().get("Origin")?.unwrap_or_else(|| {
        if let Some(port) = url.port() {
            format!("{}://{}:{}", url.scheme(), host, port)
        } else {
            format!("{}://{}", url.scheme(), host)
        }
    });

    let origin_host = Url::parse(&origin)
        .ok()
        .and_then(|u: Url| u.host_str().map(|s: &str| s.to_string()))
        .unwrap_or_else(|| host.to_string());

    let mut allowed_hosts = vec!["localhost".to_string(), "127.0.0.1".to_string(), host.to_string()];
    
    if let Ok(env_domain) = env.var("ALLOWED_ORIGIN") {
        let domain_str = env_domain.to_string();
        if !domain_str.is_empty() {
            let allowed_host = Url::parse(&domain_str)
                .ok()
                .and_then(|u: Url| u.host_str().map(|s: &str| s.to_string()))
                .unwrap_or(domain_str.clone());
            allowed_hosts.push(allowed_host);
        }
    }
    
    let is_allowed = allowed_hosts.iter().any(|h| {
        origin_host == *h || origin_host.ends_with(&format!(".{}", h))
    });
    
    if !is_allowed {
        return Err(worker::Error::RustError(format!("Untrusted Origin/Host: {} (Host: {})", origin_host, host)));
    }

    let rp_id = if origin_host == "127.0.0.1" { 
        "localhost".to_string() 
    } else { 
        origin_host.strip_prefix("www.").unwrap_or(&origin_host).to_string() 
    };
    
    Ok(RelyingParty::new("サイ王国🦏", &rp_id, &origin))
}

pub async fn init_db(env: &Env) -> Result<D1Database> {
    let d1 = env.d1("DB")?;
    Ok(d1)
}

pub fn uuid() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).unwrap();
    hex::encode(buf)
}

#[derive(Deserialize, Default)]
pub struct RegisterStartReq {
    pub username: String,
    pub admin_secret: Option<String>,
}

pub async fn register_start(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    let body: RegisterStartReq = req.json().await.unwrap_or_default();
    
    if body.username.trim().is_empty() {
        return Response::error("Username is required", 400);
    }
    
    if body.username == "admin" {
        let expected = ctx.env.secret("ADMIN_SECRET").map(|s| s.to_string()).unwrap_or_else(|_| "".to_string());
        if expected.is_empty() || body.admin_secret.as_deref() != Some(expected.as_str()) {
            return Response::error("Admin secret is required and must be valid", 403);
        }
    }
    
    let existing = db::get_user_by_username(&d1, &body.username).await?;
    let user_id = if let Some(existing_user) = existing {
        let creds = db::get_credentials_by_user(&d1, &existing_user.id).await?;
        if !creds.is_empty() {
            return Response::error("既に存在するユーザー名です。サイ🦏ンインしてください。", 409);
        }
        existing_user.id
    } else {
        let new_id = uuid();
        db::create_user(&d1, &new_id, &body.username).await?;
        new_id
    };

    let rp = rp(&req, &ctx.env)?;
    let mut rand_env = DefaultEnv;
    
    let options = rp.generate_registration_options(&mut rand_env, user_id.as_bytes(), &body.username, &body.username)
        .map_err(|e| worker::Error::RustError(format!("{:?}", e)))?;
    
    let challenge_id = uuid();
    db::create_auth_challenge(&d1, &challenge_id, &options.challenge, Some(&user_id)).await?;

    let mut res = Response::from_json(&options)?;
    res.headers_mut().set("Set-Cookie", &format!("cy_challenge={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300", challenge_id))?;
    Ok(res)
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    pub client_data_json: String,
    pub attestation_object: String,
}

pub async fn register_finish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let challenge_id = cookie.split(';').find(|s| s.trim().starts_with("cy_challenge=")).map(|s| s.trim()[13..].to_string()).unwrap_or_default();
    
    let auth_chal = db::get_auth_challenge(&d1, &challenge_id).await?.ok_or_else(|| worker::Error::RustError("Challenge not found or expired".into()))?;
    let user_id = auth_chal.pending_user_id.ok_or_else(|| worker::Error::RustError("User ID missing in challenge".into()))?;

    let body: RegisterFinishReq = req.json().await?;
    
    let options = RegistrationVerificationOptions {
        expected_challenge_b64url: auth_chal.challenge,
        user_verification: UserVerificationRequirement::Preferred,
        allow_cross_origin: false,
    };

    let rp = rp(&req, &ctx.env)?;
    let verified = rp.verify_registration(&body.client_data_json, &body.attestation_object, &options)
        .map_err(|e| worker::Error::RustError(format!("{:?}", e)))?;

    let mut pk_bytes = Vec::new();
    ciborium::into_writer(&verified.public_key, &mut pk_bytes).map_err(|_| worker::Error::RustError("Failed to serialize public key".into()))?;

    let cred = db::Credential {
        id: URL_SAFE_NO_PAD.encode(&verified.credential_id),
        user_id: user_id.clone(),
        public_key: pk_bytes,
        sign_count: verified.sign_count as i32 as f64,
        aaguid: verified.aaguid.to_vec(),
        is_backed_up: verified.is_backed_up,
        is_user_verified: verified.is_user_verified,
        attestation_fmt: verified.attestation_fmt.clone(),
    };
    db::save_credential(&d1, &cred).await?;
    
    if !db::delete_auth_challenge(&d1, &challenge_id).await? {
        return Response::error("Challenge already used", 409);
    }

    let session_id = uuid();
    db::create_session(&d1, &session_id, &user_id).await?;

    let mut res = Response::ok("Registration successful")?;
    res.headers_mut().append("Set-Cookie", "cy_challenge=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")?;
    res.headers_mut().append("Set-Cookie", &format!("cy_session={}; HttpOnly; Secure; SameSite=Lax; Path=/", session_id))?;
    Ok(res)
}

#[derive(Deserialize, Default)]
pub struct LoginStartReq {
    pub username: Option<String>,
}

pub async fn login_start(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    let body: LoginStartReq = req.json().await.unwrap_or_default();
    
    let (user_id, allow_credentials) = if let Some(un) = body.username.filter(|s| !s.is_empty()) {
        let user = match db::get_user_by_username(&d1, &un).await? {
            Some(u) => u,
            None => return Response::error("User not found", 404),
        };
        let creds = db::get_credentials_by_user(&d1, &user.id).await?;
        if creds.is_empty() {
            return Response::error("No credentials", 400);
        }
        let creds_bytes: Vec<Vec<u8>> = creds
            .into_iter()
            .filter_map(|c| URL_SAFE_NO_PAD.decode(&c.id).ok())
            .filter(|b| !b.is_empty())
            .collect();
            
        if creds_bytes.is_empty() {
            return Response::error("Stored credentials are corrupted or invalid", 500);
        }
        (Some(user.id), Some(creds_bytes))
    } else {
        (None, None)
    };

    let rp = rp(&req, &ctx.env)?;
    let mut rand_env = DefaultEnv;
    
    let options = rp.generate_authentication_options(&mut rand_env, allow_credentials)
        .map_err(|e| worker::Error::RustError(format!("{:?}", e)))?;

    let challenge_id = uuid();
    db::create_auth_challenge(&d1, &challenge_id, &options.challenge, user_id.as_deref()).await?;

    let mut res = Response::from_json(&options)?;
    res.headers_mut().set("Set-Cookie", &format!("cy_challenge={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=300", challenge_id))?;
    Ok(res)
}

#[derive(Deserialize)]
pub struct LoginFinishReq {
    pub credential_id: String,
    pub client_data_json: String,
    pub authenticator_data: String,
    pub signature: String,
}

pub async fn login_finish(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let challenge_id = cookie.split(';').find(|s| s.trim().starts_with("cy_challenge=")).map(|s| s.trim()[13..].to_string()).unwrap_or_default();
    
    let auth_chal = db::get_auth_challenge(&d1, &challenge_id).await?.ok_or_else(|| worker::Error::RustError("Challenge not found or expired".into()))?;

    let body: LoginFinishReq = req.json().await?;
    let cred = db::get_credential_by_id(&d1, &body.credential_id).await?.ok_or_else(|| worker::Error::RustError("Credential not found".into()))?;
    
    if let Some(ref pending_uid) = auth_chal.pending_user_id {
        if cred.user_id != *pending_uid {
            return Response::error("Credential does not belong to the requested user", 403);
        }
    }
    
    let expected_cred_id_bytes = URL_SAFE_NO_PAD.decode(&body.credential_id).unwrap_or_default();

    let options = AuthenticationVerificationOptions {
        expected_challenge_b64url: auth_chal.challenge,
        expected_credential_id: expected_cred_id_bytes,
        user_verification: UserVerificationRequirement::Preferred,
        stored_sign_count: cred.sign_count as u32,
        allow_cross_origin: false,
        expected_app_id: None,
    };

    let pk: kangoufu::CoseKey = ciborium::from_reader(cred.public_key.as_slice()).map_err(|_| worker::Error::RustError("Failed to parse public key".into()))?;

    let rp = rp(&req, &ctx.env)?;
    let verified = rp.verify_authentication(
        &body.client_data_json,
        &body.authenticator_data,
        &body.signature,
        &pk,
        &options,
    ).map_err(|e| worker::Error::RustError(format!("{:?}", e)))?;

    let new_sign_count = verified.new_sign_count;
    db::update_credential_sign_count(&d1, &cred.id, new_sign_count as i32).await?;
    
    if !db::delete_auth_challenge(&d1, &challenge_id).await? {
        return Response::error("Challenge already used", 409);
    }

    let session_id = uuid();
    db::create_session(&d1, &session_id, &cred.user_id).await?;

    let mut res = Response::ok("Login successful")?;
    res.headers_mut().append("Set-Cookie", "cy_challenge=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")?;
    res.headers_mut().append("Set-Cookie", &format!("cy_session={}; HttpOnly; Secure; SameSite=Lax; Path=/", session_id))?;
    Ok(res)
}

pub async fn logout(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let session_id = cookie.split(';').find(|s| s.trim().starts_with("cy_session=")).map(|s| s.trim()[11..].to_string()).unwrap_or_default();
    
    if !session_id.is_empty() {
        let _ = d1.prepare("DELETE FROM sessions WHERE id = ?1").bind(&[session_id.into()])?.run().await;
    }

    let mut res = Response::ok("Logged out")?;
    res.headers_mut().set("Set-Cookie", "cy_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")?;
    Ok(res)
}

async fn get_authenticated_user(env: &Env, req: &Request) -> Result<db::User> {
    let d1 = init_db(env).await?;
    let cookie = req.headers().get("Cookie")?.unwrap_or_default();
    let session_id = cookie.split(';').find(|s| s.trim().starts_with("cy_session=")).map(|s| s.trim()[11..].to_string()).unwrap_or_default();
    let session = match db::get_session(&d1, &session_id).await? {
        Some(s) => s,
        None => return Err(worker::Error::RustError("Unauthorized".into())),
    };
    match db::get_user_by_id(&d1, &session.user_id).await? {
        Some(u) => Ok(u),
        None => Err(worker::Error::RustError("User not found".into())),
    }
}

pub async fn get_user(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    
    let d1 = init_db(&ctx.env).await?;
    let rank = db::get_user_rank(&d1, user.points).await.unwrap_or(1);
    
    Response::from_json(&serde_json::json!({
        "id": user.id,
        "username": user.username,
        "points": user.points,
        "last_gacha_date": user.last_gacha_date,
        "rank": rank,
        "icon_url": user.icon_url
    }))
}

pub async fn get_user_credentials(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let d1 = init_db(&ctx.env).await?;
    let creds = db::get_credentials_by_user(&d1, &user.id).await?;
    
    let mut result = Vec::new();
    for c in creds {
        let aaguid_fmt = if c.aaguid.len() == 16 {
            let hex_str = hex::encode(&c.aaguid);
            format!("{}-{}-{}-{}-{}", &hex_str[0..8], &hex_str[8..12], &hex_str[12..16], &hex_str[16..20], &hex_str[20..32])
        } else {
            "00000000-0000-0000-0000-000000000000".to_string()
        };
        
        let pub_key: kangoufu::cose::CoseKey = ciborium::from_reader(c.public_key.as_slice()).unwrap_or(kangoufu::cose::CoseKey::Unsupported);
        let alg_str = format!("{:?}", pub_key).split(" {").next().unwrap_or("Unknown").to_string();
        
        result.push(serde_json::json!({
            "id": c.id,
            "sign_count": c.sign_count as i32,
            "aaguid": aaguid_fmt,
            "alg": alg_str,
            "is_backed_up": c.is_backed_up,
            "is_user_verified": c.is_user_verified,
            "attestation_fmt": c.attestation_fmt,
        }));
    }
    Response::from_json(&result)
}

pub async fn get_public_profile(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let username = ctx.param("username").unwrap();
    
    if username == "admin" {
        let is_admin = match get_authenticated_user(&ctx.env, &req).await {
            Ok(u) => u.username == "admin",
            Err(_) => false,
        };
        if !is_admin {
            return Response::error("User not found", 404);
        }
    }
    
    let d1 = init_db(&ctx.env).await?;
    
    let user = match db::get_user_by_username(&d1, username).await? {
        Some(u) => u,
        None => return Response::error("User not found", 404),
    };
    
    let creds = db::get_credentials_by_user(&d1, &user.id).await?;
    let mut creds_result = Vec::new();
    for c in creds {
        let aaguid_fmt = if c.aaguid.len() == 16 {
            let hex_str = hex::encode(&c.aaguid);
            format!("{}-{}-{}-{}-{}", &hex_str[0..8], &hex_str[8..12], &hex_str[12..16], &hex_str[16..20], &hex_str[20..32])
        } else {
            "00000000-0000-0000-0000-000000000000".to_string()
        };
        
        let pub_key: kangoufu::cose::CoseKey = ciborium::from_reader(c.public_key.as_slice()).unwrap_or(kangoufu::cose::CoseKey::Unsupported);
        let alg_str = format!("{:?}", pub_key).split(" {").next().unwrap_or("Unknown").to_string();
        
        creds_result.push(serde_json::json!({
            "id": c.id,
            "sign_count": c.sign_count as i32,
            "aaguid": aaguid_fmt,
            "alg": alg_str,
            "is_backed_up": c.is_backed_up,
            "is_user_verified": c.is_user_verified,
            "attestation_fmt": c.attestation_fmt,
        }));
    }
    let rank = db::get_user_rank(&d1, user.points).await.unwrap_or(1);

    Response::from_json(&serde_json::json!({
        "username": user.username,
        "points": user.points,
        "rank": rank,
        "icon_url": user.icon_url,
        "credentials": creds_result
    }))
}

pub async fn get_ranking(_req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let d1 = init_db(&ctx.env).await?;
    let users = db::get_top_users(&d1, 10).await?;
    let ranking: Vec<serde_json::Value> = users.into_iter().map(|u| serde_json::json!({
        "username": u.username,
        "points": u.points,
        "icon_url": u.icon_url
    })).collect();
    
    Response::from_json(&serde_json::json!({ "ranking": ranking }))
}

pub async fn play_gacha(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let d1 = init_db(&ctx.env).await?;
    
    let d = js_sys::Date::new_0();
    d.set_time(d.get_time() + 9.0 * 60.0 * 60.0 * 1000.0);
    let today = d.to_iso_string().as_string().unwrap().split('T').next().unwrap().to_string();
    if user.last_gacha_date.as_deref() == Some(&today) {
        return Response::from_json(&serde_json::json!({ "message": "本日のガチャは終了しました" }));
    }
    
    let rand_val = js_sys::Math::random();
    let gained = (rand_val * 11.0).floor() as i32 + 5;
    
    let result = d1.prepare("UPDATE users SET points = points + ?1, last_gacha_date = ?2 WHERE id = ?3 AND (last_gacha_date IS NULL OR last_gacha_date != ?2)")
        .bind(&[gained.into(), today.into(), user.id.as_str().into()])?.run().await?;
        
    if result.meta().ok().flatten().map(|m| m.changes.unwrap_or(0)).unwrap_or(0) == 0 {
        return Response::from_json(&serde_json::json!({ "message": "本日のガチャは終了しました" }));
    }
        
    let updated_user = db::get_user_by_id(&d1, &user.id).await?.unwrap();
    let rank = db::get_user_rank(&d1, updated_user.points).await.unwrap_or(1);
    
    Response::from_json(&serde_json::json!({ "points": updated_user.points, "rank": rank, "message": format!("Gained {} points!", gained) }))
}

pub async fn match_history(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let d1 = init_db(&ctx.env).await?;
    let matches = db::get_user_matches(&d1, &user.id).await?;
    
    let mut history = Vec::new();
    for m in matches {
        let is_p1 = m.player1_id == user.id;
        
        let my_hand = if is_p1 { m.player1_hand.clone() } else { m.player2_hand.clone().unwrap_or_default() };
        let enemy_hand = if is_p1 { m.player2_hand.clone().unwrap_or_default() } else { m.player1_hand.clone() };
        
        let result = if m.status == "resolved" {
            let (p1_win, p2_win) = match (m.player1_hand.as_str(), m.player2_hand.as_deref().unwrap_or("")) {
                ("rock", "scissors") | ("paper", "rock") | ("scissors", "paper") => (true, false),
                (a, b) if a == b => (false, false),
                _ => (false, true),
            };
            
            if is_p1 {
                if p1_win { "win" } else if p2_win { "lose" } else { "draw" }
            } else {
                if p2_win { "win" } else if p1_win { "lose" } else { "draw" }
            }
        } else {
            ""
        };
        
        let enemy_id = if is_p1 { m.player2_id.clone() } else { Some(m.player1_id.clone()) };
        let enemy_username = if let Some(eid) = enemy_id {
            if let Ok(Some(enemy)) = db::get_user_by_id(&d1, &eid).await {
                enemy.username
            } else {
                "不明".to_string()
            }
        } else {
            "不明".to_string()
        };
        
        history.push(serde_json::json!({
            "id": m.id,
            "status": m.status,
            "player1_hand": my_hand, // Map my hand to player1_hand for frontend
            "player2_hand": enemy_hand, // Map enemy hand to player2_hand for frontend
            "result": result,
            "enemy_username": enemy_username,
            "created_at": m.created_at
        }));
    }
    
    Response::from_json(&history)
}

#[derive(Deserialize)]
pub struct PlayReq {
    pub hand: String,
}

pub async fn play_janken(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let body: PlayReq = req.json().await?;
    let bet = 5;
    
    if user.points < 5 {
        return Response::error("Not enough points (5 required)", 400);
    }
    
    let d1 = init_db(&ctx.env).await?;
    
    let result = d1.prepare("UPDATE users SET points = points - ?1 WHERE id = ?2 AND points >= ?1")
        .bind(&[bet.into(), user.id.as_str().into()])?.run().await?;
        
    if result.meta().ok().flatten().map(|m| m.changes.unwrap_or(0)).unwrap_or(0) == 0 {
        return Response::error("Not enough points (5 required) or concurrent request", 400);
    }
    
    if let Some(m) = db::find_match(&d1, &user.id).await? {
        if !db::resolve_match(&d1, &m.id, &user.id, &body.hand).await? {
            // Race condition: someone else took this match. Refund bet.
            let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
                .bind(&[bet.into(), user.id.as_str().into()])?.run().await?;
            return Response::error("Match already taken by someone else, please try again", 409);
        }
        
        let (p1_win, p2_win) = match (m.player1_hand.as_str(), body.hand.as_str()) {
            ("rock", "scissors") | ("paper", "rock") | ("scissors", "paper") => (true, false),
            (a, b) if a == b => (false, false),
            _ => (false, true),
        };
        
        let pot = bet * 2;
        if p1_win {
            let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
                .bind(&[pot.into(), m.player1_id.as_str().into()])?.run().await?;
        } else if p2_win {
            let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
                .bind(&[pot.into(), user.id.as_str().into()])?.run().await?;
        } else {
            let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
                .bind(&[bet.into(), m.player1_id.as_str().into()])?.run().await?;
            let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
                .bind(&[bet.into(), user.id.as_str().into()])?.run().await?;
        }
        let result_msg = if p2_win { "win" } else if p1_win { "lose" } else { "draw" };
        
        let updated_user = db::get_user_by_id(&d1, &user.id).await?.unwrap();
        let rank = db::get_user_rank(&d1, updated_user.points).await.unwrap_or(1);
        
        Response::from_json(&serde_json::json!({ 
            "status": "resolved",
            "enemy_hand": m.player1_hand, 
            "result": result_msg, 
            "points": updated_user.points,
            "rank": rank
        }))
    } else {
        let m = db::Match {
            id: uuid(),
            player1_id: user.id.clone(),
            player1_hand: body.hand.clone(),
            player2_id: None,
            player2_hand: None,
            status: "open".to_string(),
            created_at: None,
        };
        db::create_match(&d1, &m).await?;
        
        let updated_user = db::get_user_by_id(&d1, &user.id).await?.unwrap();
        let rank = db::get_user_rank(&d1, updated_user.points).await.unwrap_or(1);
        
        Response::from_json(&serde_json::json!({ 
            "status": "waiting",
            "message": "Waiting for opponent...",
            "points": updated_user.points,
            "rank": rank
        }))
    }
}

#[derive(Deserialize)]
struct UploadIconReq {
    icon_url: String,
}

pub async fn upload_icon(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    
    let body: UploadIconReq = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("Invalid JSON", 400),
    };
    
    if !body.icon_url.starts_with("data:image/") || body.icon_url.len() > 100_000 {
        return Response::error("Invalid or too large image", 400);
    }
    
    let d1 = init_db(&ctx.env).await?;
    db::update_user_icon(&d1, &user.id, &body.icon_url).await?;
    
    Response::from_json(&serde_json::json!({ "icon_url": body.icon_url }))
}

pub async fn list_gifts(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let d1 = init_db(&ctx.env).await?;
    let gifts = db::get_user_gifts(&d1, &user.id).await?;
    Response::from_json(&gifts)
}

pub async fn open_gift(req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    let gift_id = ctx.param("id").unwrap();
    let d1 = init_db(&ctx.env).await?;
    
    let gift = match db::get_user_gift(&d1, &user.id, gift_id).await? {
        Some(g) if !g.is_opened => g,
        _ => return Response::error("Gift not found or already opened", 404),
    };
    
    if !db::open_gift(&d1, &user.id, gift_id).await? {
        return Response::error("Gift already opened by concurrent request", 409);
    }
    
    let _ = d1.prepare("UPDATE users SET points = points + ?1 WHERE id = ?2")
        .bind(&[gift.points.into(), user.id.as_str().into()])?.run().await?;
        
    let updated_user = db::get_user_by_id(&d1, &user.id).await?.unwrap();
    let rank = db::get_user_rank(&d1, updated_user.points).await.unwrap_or(1);
    
    Response::from_json(&serde_json::json!({ "message": "Gift opened", "points": updated_user.points, "rank": rank }))
}

#[derive(Deserialize)]
struct DistributeGiftReq {
    points: i32,
    description: String,
}

pub async fn admin_distribute_gift(mut req: Request, ctx: RouteContext<()>) -> Result<Response> {
    let user = match get_authenticated_user(&ctx.env, &req).await {
        Ok(u) => u,
        Err(_) => return Response::error("Unauthorized", 401),
    };
    if user.username != "admin" {
        return Response::error("Forbidden", 403);
    }
    
    let body: DistributeGiftReq = req.json().await?;
    let d1 = init_db(&ctx.env).await?;
    
    db::distribute_gift(&d1, &uuid(), body.points, &body.description).await?;
    Response::from_json(&serde_json::json!({ "message": "Gift distributed to all users" }))
}
