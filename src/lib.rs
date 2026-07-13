use worker::*;

mod db;
mod api;

#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let router = Router::new();

    router
        .get("/", |_, _| {
            Response::from_html(include_str!("../frontend/index.html"))
        })
        .get("/style.css", |_, _| {
            let headers = Headers::new();
            headers.set("Content-Type", "text/css").unwrap();
            Ok(Response::ok(include_str!("../frontend/style.css"))?.with_headers(headers))
        })
        .get("/app.js", |_, _| {
            let headers = Headers::new();
            headers.set("Content-Type", "application/javascript").unwrap();
            Ok(Response::ok(include_str!("../frontend/app.js"))?.with_headers(headers))
        })
        .get("/favicon.svg", |_, _| {
            let headers = Headers::new();
            headers.set("Content-Type", "image/svg+xml").unwrap();
            Ok(Response::ok(include_str!("../frontend/favicon.svg"))?.with_headers(headers))
        })
        // WebAuthn endpoints
        .post_async("/api/register/start", api::register_start)
        .post_async("/api/register/finish", api::register_finish)
        .post_async("/api/login/start", api::login_start)
        .post_async("/api/login/finish", api::login_finish)
        .post_async("/api/logout", api::logout)
        
        // Public user profile
        .get_async("/api/profile/:username", api::get_public_profile)
        
        // User and profile
        .get_async("/api/user", api::get_user)
        .get_async("/api/user/credentials", api::get_user_credentials)
        .post_async("/api/user/icon", api::upload_icon)
        
        // Game endpoints
        .post_async("/api/gacha", api::play_gacha)
        .get_async("/api/history", api::match_history)
        .post_async("/api/play", api::play_janken)
        .get_async("/api/ranking", api::get_ranking)
        
        // Gifts and Admin
        .get_async("/api/gift/ready", api::list_gifts)
        .post_async("/api/gift/:id/open", api::open_gift)
        .post_async("/api/admin/gift", api::admin_distribute_gift)
        
        .run(req, env)
        .await
}
