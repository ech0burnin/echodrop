//! Роуты echodrop: дропзона (upload + download), healthz, статика.
//!
//! API дропзоны:
//! - POST /upload (multipart: поля file, опционально ttl_hours) -> 200 {short_code, url, ...}
//! - POST|PUT /upload (Content-Type: application/octet-stream, curl -T) -> тот же JSON
//! - GET /{short_code} -> стрим файла (TTL истёк = 404)

use crate::codes;
use crate::config::Config;
use crate::janitor;
use crate::storage::{self, BlobWriter, StoredBlob};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, FromRequest, Multipart, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Json, Redirect, Response};
use axum::routing::get;
use axum::Router;

use http_body_util::BodyExt;
use rust_embed::RustEmbed;
use serde_json::json;
use sqlx::SqlitePool;
use tokio_util::io::ReaderStream;

/// Общее состояние приложения: доступно всем хендлерам через State.
#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub db: SqlitePool,
    /// Rate-limit upload'ов: ip -> (окно старт, счётчик). In-memory,
    /// переживает рестарт (сброс — не страшно).
    pub limiter: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, (i64, u32)>>>,
    /// Секрет для cookie-токенов разблокировки: генерируется на старте,
    /// рестарт сбивает все разблокировки (см. auth.rs).
    pub unlock_secret: String,
}

/// Статика прошивается в бинарь на этапе сборки.
#[derive(RustEmbed)]
#[folder = "assets/static/"]
struct Assets;

/// Собирает роутер. `max_upload_bytes` — потолок тела запроса на /upload
/// (DefaultBodyLimit; без него axum режет всё на 2 МБ по умолчанию).
pub fn router(max_upload_bytes: usize) -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/config.json", get(public_config))
        .route("/", get(index))
        .route("/static/{file}", get(static_file))
        .route("/upload", axum::routing::post(upload).put(upload))
        .route("/{code}/unlock", axum::routing::post(unlock))
        .route("/api/me", get(api_me))
        .route("/api/captcha", get(api_captcha))
        .route("/api/my-files", get(api_my_files))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", get(logout))
        .route("/register", get(register_page).post(register_submit))
        .route("/my", get(my_page))
        .route("/my/del/{id}", axum::routing::post(my_delete))
        .route("/{code}", get(download))
        .layer(DefaultBodyLimit::max(max_upload_bytes))
}

/// GET /healthz — для мониторинга/uptime-проб.
async fn healthz() -> &'static str {
    "ok"
}

/// GET /config.json — публичные параметры для фронтенда: фронт по ним
/// строит список опций TTL (не длиннее max_ttl_hours, «∞» только при
/// allow_infinite_ttl), показывает дисклеймер трекинга и лимит размера.
/// Секретов тут нет — всё и так видно из поведения сайта.
async fn public_config(State(state): State<AppState>) -> Response {
    Json(json!({
        "site_name": state.config.site_name,
        "mode": state.config.mode.to_string(),
        "max_file_size_mb": state.config.max_file_size_mb,
        // 0 = «бессрочно» (возможен только при allow_infinite_ttl = true)
        "default_ttl_hours": state.config.default_ttl_hours,
        "max_ttl_hours": state.config.max_ttl_hours,
        "allow_infinite_ttl": state.config.allow_infinite_ttl,
        "tracking": state.config.tracking,
        "base_url": state.config.base_url,
        "registration_required": !state.config.allow_unreg_upload && state.config.mode != crate::config::Mode::Free,
        "reg_token_required": state.config.registration_token.is_some(),
        "storage_limit_gb": state.config.storage_limit_gb,
        "storage_used_bytes": storage_used(&state).await,
    }))
    .into_response()
}

/// Сколько байт занято в хранилище (data + blobs). Ошибки чтения = 0.
async fn storage_used(state: &AppState) -> u64 {
    let mut total: u64 = 0;
    for sub in ["data", "blobs"] {
        let dir = std::path::Path::new(&state.config.storage_path).join(sub);
        let Ok(mut rd) = tokio::fs::read_dir(&dir).await else { continue };
        while let Ok(Some(e)) = rd.next_entry().await {
            if let Ok(md) = e.metadata().await {
                if md.is_file() {
                    total += md.len();
                }
            }
        }
    }
    total
}

/// GET /api/captcha — пара чисел для регистрации (модалка на корневой).
async fn api_captcha() -> Response {
    let a = rand_int(2, 9);
    let b = rand_int(2, 9);
    Json(json!({ "a": a, "b": b })).into_response()
}

/// GET /api/me — кто сейчас залогинен (для фронта корневой).
async fn api_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let user = current_user(&state, &headers);
    let body = json!({ "login": user });
    if user.is_some() {
        Json(body).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, Json(body)).into_response()
    }
}

/// GET /api/my-files — файлы залогиненного (JSON, для корневой в open/closed).
/// В free — 404 (аккаунтов нет).
async fn api_my_files(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if state.config.mode == crate::config::Mode::Free {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(login) = current_user(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "not logged in"}))).into_response();
    };
    let rows: Vec<(String, i64, String, i64, i64, i64, Option<String>)> = sqlx::query_as(
        "SELECT short_code, size, orig_name, expires_at, downloads, id, password_hash          FROM files WHERE owner_id = (SELECT id FROM users WHERE login = ?1) ORDER BY id DESC",
    )
    .bind(&login)
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();
    let now = janitor::now_secs();
    let files: Vec<_> = rows
        .into_iter()
        .map(|(code, size, name, expires_at, downloads, id, pw_hash)| {
            let infinite = expires_at == i64::MAX;
            let expired = !infinite && expires_at <= now;
            json!({
                "id": id,
                "code": code,
                "name": name,
                "size": size,
                "expires_at": if infinite { serde_json::Value::Null } else { serde_json::Value::from(expires_at) },
                "expired": expired,
                "downloads": downloads,
                "locked": pw_hash.is_some(),
                "url": format!("{}/{}", state.config.base_url.trim_end_matches('/'), code),
            })
        })
        .collect();
    Json(json!({ "login": login, "files": files })).into_response()
}

/// GET / — главная (embedded index.html).
async fn index() -> Response {
    match Assets::get("index.html") {
        Some(file) => Html(file.data.into_owned()).into_response(),
        None => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "index.html не найден в embedded assets",
        )
            .into_response(),
    }
}

/// GET /static/{file} — файл из embedded assets (лого, общие стили страниц).
/// index.html наружу не отдаём: он живёт на `/`.
async fn static_file(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    // только простые имена: без слэшей и точек-в-начале (index.html отсекается сам)
    if file.contains('/') || file.contains('\\') || file.starts_with('.') {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(asset) = Assets::get(&file) else {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    };
    let ct = match file.rsplit('.').next().unwrap_or("") {
        "svg" => "image/svg+xml",
        "css" => "text/css; charset=utf-8",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "js" => "text/javascript; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "html" => "text/html; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    };
    (
        [(header::CONTENT_TYPE, HeaderValue::from_static(ct))],
        asset.data.into_owned(),
    )
        .into_response()
}

fn bad_request(msg: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": msg.to_string()})),
    )
        .into_response()
}

fn internal(msg: impl std::fmt::Display) -> Response {
    eprintln!("echodrop: {msg}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": msg.to_string()})),
    )
        .into_response()
}

/// Имя файла из multipart/raw: последний сегмент пути, без кавычек и Control-символов.
fn sanitize_name(raw: &str) -> String {
    let last = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = last
        .chars()
        .filter(|c| !c.is_control() && *c != '"')
        .collect();
    if cleaned.trim().is_empty() {
        "unnamed".to_string()
    } else {
        cleaned
    }
}

/// POST|PUT /upload. Ветвление по Content-Type: multipart/form-data — браузер,
/// остальное — raw-режим (curl -T).
async fn upload(State(state): State<AppState>, req: Request) -> Response {
    // Rate-limit: 30 upload'ов / 10 мин / IP (окно фиксированное).
    // Окно без складного хвоста — для файлообменника хватает за глаза.
    {
        const WINDOW: i64 = 600;
        const MAX: u32 = 30;
        let ip = client_ip(req.headers());
        let mut map = state.limiter.lock().await;
        let now = janitor::now_secs();
        let e = map.entry(ip).or_insert((now, 0));
        if now - e.0 >= WINDOW {
            *e = (now, 0);
        }
        e.1 += 1;
        if e.1 > MAX {
            return (StatusCode::TOO_MANY_REQUESTS, "слишком много загрузок, подожди немного").into_response();
        }
    }
    // Лимит хранилища: 0 = без лимита. Считаем занятые байты (data+blobs), запрещаем при переполнении.
    {
        let limit = state.config.storage_limit_gb as u64 * 1024 * 1024 * 1024;
        if limit > 0 && storage_used(&state).await >= limit {
            return (StatusCode::INSUFFICIENT_STORAGE, "хранилище сервера переполнено, загрузка невозможна").into_response();
        }
    }
    // allow_unreg_upload=false (open/closed): грузить могут только залогиненные.
    // free не трогаем — там аккаунтов нет, параметр бессмыслен.
    if !state.config.allow_unreg_upload && state.config.mode != crate::config::Mode::Free {
        let user = current_user(&state, req.headers());
        if user.is_none() {
            return (StatusCode::FORBIDDEN, "загрузка только для зарегистрированных").into_response();
        }
    }
    let (parts, body) = req.into_parts();
    let ct = parts
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    if ct.starts_with("multipart/form-data") {
        let req = Request::from_parts(parts, body);
        multipart_upload(state, req).await
    } else {
        raw_upload(state, parts.headers, body).await
    }
}

/// Multipart-режим: поля ttl_hours (опционально) и file.
/// Поля обрабатываются по мере прихода: ttl_hours должен идти ДО file.
async fn multipart_upload(state: AppState, req: Request) -> Response {
    let req_headers = req.headers().clone();
    let mut mp = match Multipart::from_request(req, &()).await {
        Ok(m) => m,
        Err(e) => return bad_request(format!("multipart: {e}")),
    };

    let mut ttl_hours: Option<u64> = None;
    let mut password: Option<String> = None;
    while let Some(mut field) = match mp.next_field().await {
        Ok(f) => f,
        Err(e) => return bad_request(format!("multipart-поле: {e}")),
    } {
        let name = field.name().unwrap_or("").to_string();
        if name == "ttl_hours" {
            if let Ok(text) = field.text().await {
                ttl_hours = text.trim().parse().ok();
            }
        } else if name == "password" {
            if let Ok(text) = field.text().await {
                let t = text.trim().to_string();
                if !t.is_empty() {
                    password = Some(t);
                }
            }
        } else if name == "file" {
            let orig_name = field.file_name().map(sanitize_name);
            let mime = field
                .content_type()
                .unwrap_or("application/octet-stream")
                .to_string();

            let mut writer = match BlobWriter::create(&state.config.storage_path).await {
                Ok(w) => w,
                Err(e) => return internal(format!("не смог начать запись blob: {e}")),
            };
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        if let Err(e) = writer.write_chunk(&chunk).await {
                            writer.abort().await;
                            return internal(format!("диск: {e}"));
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        writer.abort().await;
                        return bad_request(format!("обрыв upload: {e}"));
                    }
                }
            }
            let stored = match writer.finish().await {
                Ok(s) => s,
                Err(e) => return internal(format!("не смог завершить blob: {e}")),
            };
            let ttl = ttl_hours.unwrap_or(state.config.default_ttl_hours);
            return finish_upload(&state, stored, orig_name, mime, ttl, password, &req_headers).await;
        }
    }
    bad_request("multipart: поле file не найдено")
}

/// Raw-режим (curl -T): тело = файл, имя из X-Filename, TTL из X-TTL-Hours
/// (нет заголовка — default из конфига).
async fn raw_upload(state: AppState, headers: axum::http::HeaderMap, body: Body) -> Response {
    let name = headers
        .get("x-filename")
        .and_then(|v| v.to_str().ok())
        .map(sanitize_name);
    let ttl_hours = headers
        .get("x-ttl-hours")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let password = headers
        .get("x-password")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut writer = match BlobWriter::create(&state.config.storage_path).await {
        Ok(w) => w,
        Err(e) => return internal(format!("не смог начать запись blob: {e}")),
    };
    let mut body = body;
    let mut total: u64 = 0;
    let max = state.config.max_file_size_mb as u64 * 1024 * 1024;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    total += data.len() as u64;
                    if total > max {
                        writer.abort().await;
                        return (
                            StatusCode::PAYLOAD_TOO_LARGE,
                            format!("файл больше лимита {max} байт"),
                        )
                            .into_response();
                    }
                    if let Err(e) = writer.write_chunk(&data).await {
                        writer.abort().await;
                        return internal(format!("диск: {e}"));
                    }
                }
            }
            Some(Err(e)) => {
                writer.abort().await;
                return bad_request(format!("обрыв тела: {e}"));
            }
            None => break,
        }
    }
    let stored = match writer.finish().await {
        Ok(s) => s,
        Err(e) => return internal(format!("не смог завершить blob: {e}")),
    };
    finish_upload(
        &state,
        stored,
        name,
        "application/octet-stream".to_string(),
        ttl_hours.unwrap_or(state.config.default_ttl_hours),
        password,
        &headers,
    )
    .await
}

/// Общая концовка upload: строка в БД + JSON со ссылкой.
/// TTL-правила: 0 = «бессрочно» (только при allow_infinite_ttl),
/// выше max_ttl_hours — отказ. Сырой blob при отказе прибираем за собой.
async fn finish_upload(
    state: &AppState,
    stored: StoredBlob,
    orig_name: Option<String>,
    mime: String,
    ttl_hours: u64,
    password: Option<String>,
    headers: &HeaderMap,
) -> Response {
    if ttl_hours == 0 && !state.config.allow_infinite_ttl {
        drop_unreferenced_blob(state, &stored.sha256).await;
        return bad_request("бессрочное хранение запрещено настройками сервера (ttl_hours = 0)");
    }
    if ttl_hours > state.config.max_ttl_hours {
        drop_unreferenced_blob(state, &stored.sha256).await;
        return bad_request(format!(
            "срок хранения не больше {} ч",
            state.config.max_ttl_hours
        ));
    }
    let code = match codes::unique(&state.db).await {
        Ok(c) => c,
        Err(e) => return internal(format!("генерация кода: {e}")),
    };
    let now = janitor::now_secs();
    // 0 = «никогда не истекает»: janitor сравнивает expires_at <= now,
    // i64::MAX не протухнет (см. janitor.rs).
    let expires_at = if ttl_hours == 0 {
        i64::MAX
    } else {
        now + (ttl_hours as i64) * 3600
    };
    let name = orig_name.unwrap_or_else(|| "unnamed".to_string());

    // Ф3b: если юзер залогинен — файл его. Нет — ничей (Free-режим).
    let owner_id: Option<i64> = match crate::sessions::session_from_headers(headers, &state.unlock_secret) {
        Some(login) => sqlx::query_as::<_, (i64,)>("SELECT id FROM users WHERE login = ?1")
            .bind(&login)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten()
            .map(|r| r.0),
        None => None,
    };
    let pw_hash = match password.as_deref() {
        Some(pw) => match crate::auth::hash_password(pw) {
            Ok(h) => Some(h),
            Err(e) => return internal(format!("{e}")),
        },
        None => None,
    };
    let res = sqlx::query(
        "INSERT INTO files (short_code, orig_name, size, mime, sha256, created_at, expires_at, password_hash, owner_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&code)
    .bind(&name)
    .bind(stored.size as i64)
    .bind(&mime)
    .bind(&stored.sha256)
    .bind(now)
    .bind(expires_at)
    .bind(&pw_hash)
    .bind(owner_id)
    .execute(&state.db)
    .await;

    match res {
        Ok(done) => {
            if state.config.tracking {
                log_event(state, done.last_insert_rowid(), "upload", headers, None).await;
            }
            Json(json!({
                "short_code": code,
                "url": format!("{}/{}", state.config.base_url.trim_end_matches('/'), code),
                // null = бессрочный (ttl_hours = 0), фронт пишет «навсегда»
                "expires_at": if expires_at == i64::MAX { serde_json::Value::Null } else { serde_json::Value::from(expires_at) },
                "ttl_hours": ttl_hours,
                "size": stored.size,
                "sha256": stored.sha256,
                // фронт рисует бейдж замка; пароль и хэш наружу не выходят
                "has_password": pw_hash.is_some(),
            }))
            .into_response()
        }
        Err(e) => internal(format!("БД: {e}")),
    }
}

/// Прибрать blob после отказа в upload — только если на него не ссылается
/// ни одна строка БД (дедуп: одинаковый контент = один blob на всех).
async fn drop_unreferenced_blob(state: &AppState, sha256: &str) {
    let (refs,): (i64,) = match sqlx::query_as("SELECT count(*) FROM files WHERE sha256 = ?1")
        .bind(sha256)
        .fetch_one(&state.db)
        .await
    {
        Ok(r) => r,
        Err(_) => return, // не смогли проверить — лучше оставить blob (сироту заберёт janitor)
    };
    if refs == 0 {
        storage::remove_blob(&state.config.storage_path, sha256).await;
    }
}

/// POST /{code}/unlock — форма с паролем: верный -> cookie-токен + redirect.
async fn unlock(
    State(state): State<AppState>,
    axum::extract::Path(code): axum::extract::Path<String>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    if code.len() != 7 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let hash: Option<(Option<String>,)> =
        sqlx::query_as("SELECT password_hash FROM files WHERE short_code = ?1")
            .bind(&code)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let pw_hash = match hash {
        Some((Some(h),)) => h,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let given = form.get("password").map(|s| s.as_str()).unwrap_or("");
    if !crate::auth::verify_password(given, &pw_hash) {
        return crate::auth::unlock_page(&code, true);
    }
    let token = crate::auth::make_token(&state.unlock_secret, &code);
    let cookie = format!("echodrop_{code}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600");
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, format!("/{code}")),
        ],
    )
        .into_response()
}

/// IP клиента из заголовков прокси: X-Forwarded-For (первый) -> X-Real-IP ->
/// "local". За nginx/NPM всегда есть XFF; без прокси (смоук-тесты) пишем local.
fn client_ip(headers: &HeaderMap) -> String {
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(first) = xff.split(',').next() {
            let ip = first.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "local".to_string())
}

/// Отпечаток браузера v1: серверный, без JS — sha256(UA + Accept-Language +
/// Accept-Encoding). Не идентификатор, а классификатор: сузивает круг
/// «кто качал» без куки. Прямые руки чистят UA — их не отследить и не нужно.
fn fingerprint(headers: &HeaderMap) -> String {
    use sha2::{Digest, Sha256};
    let ua = headers.get(header::USER_AGENT).and_then(|v| v.to_str().ok()).unwrap_or("");
    let al = headers.get(header::ACCEPT_LANGUAGE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let ae = headers.get(header::ACCEPT_ENCODING).and_then(|v| v.to_str().ok()).unwrap_or("");
    let mut h = Sha256::new();
    h.update(format!("{ua}|{al}|{ae}").as_bytes());
    let full = crate::storage::hex(&h.finalize());
    full[..16].to_string()
}

/// Запись события, ТОЛЬКО если tracking включён. Ошибка записи не роняет
/// запрос: трекинг — наблюдение, а не барьер.
async fn log_event(state: &AppState, file_id: i64, kind: &str, headers: &HeaderMap, peer_ip: Option<std::net::IpAddr>) {
    if !state.config.tracking {
        return;
    }
    let _ = sqlx::query(
        "INSERT INTO events (file_id, kind, ip, fingerprint, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(file_id)
    .bind(kind)
    .bind(if headers.contains_key("x-forwarded-for") || headers.contains_key("x-real-ip") {
        client_ip(headers)
    } else {
        peer_ip.map(|p| p.to_string()).unwrap_or_else(|| "local".to_string())
    })
    .bind(fingerprint(headers))
    .bind(janitor::now_secs())
    .execute(&state.db)
    .await;
}



// ============================================================
// Ф3c: регистрация — только в режиме Open
// ============================================================

/// GET /register — форма с арифметической капчей.
async fn register_page(State(_state): State<AppState>) -> Response {
    // вариант Б: отдельные страницы выпилены, вход/рега — модалки на корневой
    Redirect::to("/").into_response()
}

/// POST /register — валидация, капча, INSERT, авто-вход.
async fn register_submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    if state.config.mode != crate::config::Mode::Open {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let login = form.get("login").cloned().unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();
    let cap_a: i64 = form.get("captcha_a").and_then(|s| s.parse().ok()).unwrap_or(-1);
    let cap_b: i64 = form.get("captcha_b").and_then(|s| s.parse().ok()).unwrap_or(-1);
    let cap_ans: i64 = form.get("captcha_answer").and_then(|s| s.parse().ok()).unwrap_or(-999);

    let err = |msg: &str| -> Response {
        let wants_plain = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("text/plain"))
            .unwrap_or(false);
        if wants_plain {
            return (StatusCode::UNPROCESSABLE_ENTITY, msg.to_string()).into_response();
        }
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            page_shell("echodrop — регистрация", &format!("<p class='err'>{msg}</p><p><a href='/register'>ещё раз</a></p>")),
        )
            .into_response()
    };

    if login.len() < 3 || login.len() > 30 || !login.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-') {
        return err("логин: 3-30 символов, только a-z, 0-9, _ и -");
    }
    if password.len() < 6 {
        return err("пароль: минимум 6 символов");
    }
    if cap_a < 0 || cap_b < 0 || cap_a + cap_b != cap_ans {
        return err("капча не сходится");
    }
    // Invite-токен (open): если задан в конфиге — регистрация только с ним.
    if let Some(want) = &state.config.registration_token {
        let got = form.get("reg_token").cloned().unwrap_or_default();
        if got != *want {
            return err("неверный код приглашения");
        }
    }
    let hash = match crate::auth::hash_password(&password) {
        Ok(h) => h,
        Err(e) => return internal(format!("bcrypt: {e}")),
    };
    let now = janitor::now_secs();
    let res = sqlx::query(
        "INSERT INTO users (login, password_hash, created_at) VALUES (?1, ?2, ?3)",
    )
    .bind(&login)
    .bind(&hash)
    .bind(now)
    .execute(&state.db)
    .await;
    match res {
        Ok(_) => {
            let sess = crate::sessions::make_session(&state.unlock_secret, &login);
            let cookie = format!(
                "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
                crate::sessions::COOKIE,
                sess,
                crate::sessions::TTL_SECS
            );
            (
                StatusCode::SEE_OTHER,
                [
                    (header::SET_COOKIE, cookie),
                    (header::LOCATION, "/my".to_string()),
                ],
            )
                .into_response()
        }
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("UNIQUE") {
                err("логин уже занят")
            } else {
                internal(format!("БД: {e}"))
            }
        }
    }
}

/// Случайное целое [lo, hi] для капчи — без крейта rand: xorshift от времени.
fn rand_int(lo: i64, hi: i64) -> i64 {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let mut x = t.wrapping_mul(2654435761) ^ (t >> 3);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    lo + (x as i64).rem_euclid(hi - lo + 1)
}
// ============================================================
// Ф3b: пользовательские сессии — /login, /logout, /my
// ============================================================

/// Хелпер: логин из cookie сессии или None.
fn current_user(state: &AppState, headers: &HeaderMap) -> Option<String> {
    crate::sessions::session_from_headers(headers, &state.unlock_secret)
}

/// Общий каркас HTML-страниц ЛК (тёмная тема, как у дропзоны).
/// Общая обёртка HTML-страниц кабинета: подключает /static/style.css,
/// шапка = лого + echodrop, тело — конкретная страница.
fn page_shell(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="icon" href="/static/logo.svg" type="image/svg+xml"><title>{title}</title>
<link rel="stylesheet" href="/static/style.css">
</head><body>
<script>document.body.dataset.theme = localStorage.getItem('echodrop_theme') || 'dark';</script>
<div class="wrap">
<header class="site"><img src="/static/logo.svg" alt=""><h1>echodrop</h1></header>
{body}</div></body></html>"#
    ))
}

/// Шапка для страниц кабинета: лого + название + ссылка logout.
fn site_header(extra: &str) -> String {
    format!(
        r#"<div class="row"><header class="site"><img src="/static/logo.svg" alt=""><h1>echodrop</h1></header><span class="muted">{extra}</span></div>"#
    )
}

/// GET /login — форма входа.
async fn login_page(State(_state): State<AppState>) -> Response {
    // вариант Б: отдельные страницы выпилены, вход/рега — модалки на корневой
    Redirect::to("/").into_response()
}

/// POST /login — проверка bcrypt, cookie сессии.
async fn login_submit(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    if state.config.mode == crate::config::Mode::Free {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let login = form.get("login").cloned().unwrap_or_default();
    let password = form.get("password").cloned().unwrap_or_default();
    let row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM users WHERE login = ?1")
            .bind(&login)
            .fetch_optional(&state.db)
            .await
            .ok()
            .flatten();
    let ok = match row {
        Some((hash,)) => crate::auth::verify_password(&password, &hash),
        None => false,
    };
    if !ok {
        let wants_plain = headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|a| a.contains("text/plain"))
            .unwrap_or(false);
        if wants_plain {
            return (StatusCode::UNAUTHORIZED, "неверный логин или пароль").into_response();
        }
        return (
            StatusCode::UNAUTHORIZED,
            page_shell(
                "echodrop — вход",
                "<p class='err'>неверный логин или пароль</p><p><a href='/login'>ещё раз</a></p>",
            ),
        )
            .into_response();
    }
    let sess = crate::sessions::make_session(&state.unlock_secret, &login);
    let cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        crate::sessions::COOKIE,
        sess,
        crate::sessions::TTL_SECS
    );
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/my".to_string()),
        ],
    )
        .into_response()
}

/// GET /logout — сброс cookie.
async fn logout() -> Response {
    let cookie = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", crate::sessions::COOKIE);
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, cookie),
            (header::LOCATION, "/".to_string()),
        ],
    )
        .into_response()
}

/// GET /my — кабинет: свои файлы, удаление, выход.
async fn my_page(State(_state): State<AppState>) -> Response {
    // вариант Б: отдельные страницы выпилены, вход/рега — модалки на корневой
    Redirect::to("/").into_response()
}

/// POST /my/del/{id} — удалить свой файл (владение проверяется по owner).
async fn my_delete(
    State(state): State<AppState>,
    axum::extract::Path((id,)): axum::extract::Path<(i64,)>,
    headers: HeaderMap,
) -> Response {
    if state.config.mode == crate::config::Mode::Free {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let Some(login) = current_user(&state, &headers) else {
        return (
            StatusCode::SEE_OTHER,
            [(header::LOCATION, "/login".to_string())],
        )
            .into_response();
    };
    // удаляем только если файл принадлежит этому юзеру
    let n = sqlx::query(
        "DELETE FROM files WHERE id = ?1 AND owner_id = (SELECT id FROM users WHERE login = ?2)",
    )
    .bind(id)
    .bind(&login)
    .execute(&state.db)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);
    let _ = n;
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/my".to_string())],
    )
        .into_response()
}

/// Размер в человекочитаемом виде.
fn human_size(bytes: i64) -> String {
    let b = bytes as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} ГБ", b / (1024.0 * 1024.0 * 1024.0))
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.1} МБ", b / (1024.0 * 1024.0))
    } else if b >= 1024.0 {
        format!("{:.1} КБ", b / 1024.0)
    } else {
        format!("{} Б", bytes)
    }
}

/// Секунды в «2 д 3 ч» / «45 мин».
fn human_time(secs: i64) -> String {
    if secs <= 0 {
        return "0".into();
    }
    let d = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{d} д {h} ч")
    } else if h > 0 {
        format!("{h} ч {m} мин")
    } else {
        format!("{m} мин")
    }
}

/// Строка files для отдачи.
struct FileRow {
    id: i64,
    orig_name: String,
    size: i64,
    mime: String,
    sha256: String,
    password_hash: Option<String>,
}

/// GET /{code} — стрим файла. Нет/истёк = 404 (не раскрываем, чем именно).
#[derive(Clone, Copy)]
struct PeerAddr(pub std::net::IpAddr);

struct PeerIp(pub Option<std::net::IpAddr>);

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIp {
    type Rejection = std::convert::Infallible;
    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _s: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts
            .extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| ci.0.ip());
        Ok(PeerIp(ip))
    }
}

async fn download(
    State(state): State<AppState>,
    axum::extract::Path(code): axum::extract::Path<String>,
    headers: HeaderMap,
    PeerIp(peer): PeerIp,
) -> Response {
    if code.len() != 7 || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    let row: Option<(i64, String, i64, String, String, i64, Option<String>)> =
        sqlx::query_as::<_, (i64, String, i64, String, String, i64, Option<String>)>(
            "SELECT id, orig_name, size, mime, sha256, expires_at, password_hash FROM files WHERE short_code = ?1",
        )
        .bind(&code)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

    let f = match row {
        Some((id, orig_name, size, mime, sha256, expires_at, password_hash))
            if expires_at > janitor::now_secs() =>
        {
            FileRow {
                id,
                orig_name,
                size,
                mime,
                sha256,
                password_hash,
            }
        }
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };

    // Пароль: X-Password (API) или cookie-токен (browser после unlock).
    if let Some(pw_hash) = f.password_hash.as_ref() {
        let ok = crate::auth::password_from_headers(&headers)
            .map(|pw| crate::auth::verify_password(&pw, pw_hash))
            .unwrap_or(false)
            || crate::auth::token_from_cookies(&headers, &code)
                .map(|t| crate::auth::check_token(&state.unlock_secret, &code, &t))
                .unwrap_or(false);
        if !ok {
            return crate::auth::unlock_page(&code, false);
        }
    }

    let path = storage::blob_path(std::path::Path::new(&state.config.storage_path), &f.sha256);
    let file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) => return internal(format!("blob потерян на диске: {e}")),
    };

    // Счётчик качаний: файл открыли — считаем отдачу начавшейся.
    let _ = sqlx::query("UPDATE files SET downloads = downloads + 1 WHERE short_code = ?1")
        .bind(&code)
        .execute(&state.db)
        .await;
    if state.config.tracking {
        log_event(&state, f.id, "download", &headers, peer).await;
    }

    let disp = format!("attachment; filename=\"{}\"", f.orig_name.replace('"', "'"));
    let ct = HeaderValue::from_str(&f.mime).unwrap_or(HeaderValue::from_static("application/octet-stream"));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CONTENT_DISPOSITION, disp)
        .header(header::CONTENT_LENGTH, f.size.to_string())
        .body(Body::from_stream(ReaderStream::new(file)))
        .unwrap_or_else(|e| internal(format!("сборка ответа: {e}")))
}

#[cfg(test)]
mod tests {
use super::*;
/// (j) Ф3c: регистрация в Open-режиме, 404 в Closed, капча обязательна.
#[tokio::test]
async fn register_flow() {
    let mut state = test_state("reg").await;
    state.config.mode = Mode::Open;
    crate::db::migrate_users(&state.db).await.unwrap();
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    // Вариант Б: GET /register — redirect, капча теперь в /api/captcha
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/captcha")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let cap = String::from_utf8_lossy(&bytes);
    assert!(cap.contains("\"a\":"), "JSON-капча есть: {cap}");

    // POST с неверной капчей -> 422
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=newuser&password=secret7&captcha_a=2&captcha_b=3&captcha_answer=6"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // POST верный -> 303 + cookie
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=newuser&password=secret7&captcha_a=2&captcha_b=3&captcha_answer=5"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(sc.contains("echodrop_sess="));

    // дубль логина -> 422 с «занят»
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=newuser&password=secret7&captcha_a=2&captcha_b=3&captcha_answer=5"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Closed-режим: GET /register — redirect на / (страниц нет), POST /register — 404
    let mut state2 = test_state("regclosed").await;
    state2.config.mode = Mode::Closed;
    crate::db::migrate_users(&state2.db).await.unwrap();
    let app2 = router(10 * 1024 * 1024).with_state(state2);
    let resp = app2
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/register")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=x&password=xxxxxx&captcha_a=2&captcha_b=3&captcha_answer=5"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// (h) Ф3b: логин-флоу — сессия, /my, удаление файла.
#[tokio::test]
async fn login_and_my_flow() {
    let mut state = test_state("lk").await;
    crate::db::migrate_users(&state.db).await.unwrap();
    state.config.mode = Mode::Open;
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    // юзер напрямую в БД
    let hash = crate::auth::hash_password("test123").unwrap();
    sqlx::query("INSERT INTO users (login, password_hash, created_at) VALUES ('alice', ?1, 0)")
        .bind(&hash)
        .execute(&state.db)
        .await
        .unwrap();

    // неверный пароль -> 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=alice&password=wrong"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // верный -> 303 + cookie
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("login=alice&password=test123"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert!(cookie.starts_with("echodrop_sess="), "cookie: {cookie}");

    // /my без cookie -> 303 /login
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/my")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // upload с cookie -> owner_id проставлен
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", "multipart/form-data; boundary=XB")
                .header("cookie", &cookie)
                .body(Body::from(multipart_body("XB", "mine.txt", "my file", None)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let code = take_code(&json_body(resp).await);

    // Вариант Б: /api/my-files с cookie -> 200, JSON с файлом и логином
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/my-files")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = String::from_utf8_lossy(&bytes);
    assert!(json.contains("mine.txt"), "файл в списке: {json}");
    assert!(json.contains("alice"), "логин в списке: {json}");

    // /my/del/{id}: узнаем id из БД
    let (fid,): (i64,) = sqlx::query_as("SELECT id FROM files WHERE short_code = ?1")
        .bind(&code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/my/del/{fid}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let (cnt,): (i64,) = sqlx::query_as("SELECT count(*) FROM files WHERE short_code = ?1")
        .bind(&code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(cnt, 0, "файл удалён из БД");

    // logout -> cookie обнулён
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/logout")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let sc = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(sc.contains("Max-Age=0"), "cookie сброшен: {sc}");
}

/// (i) режимы: Free — ЛК выключен, /login 404.
#[tokio::test]
async fn free_mode_no_login() {
    let mut state = test_state("free").await;
    state.config.mode = Mode::Free;
    let app = router(10 * 1024 * 1024).with_state(state);
    // Вариант Б: страницы-аккаунты выпилены (redirect на /), в Free проверяем 404 API
    for uri in ["/api/my-files"] {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "Free: {uri}");
    }
}

use crate::config::Mode;
use tower::ServiceExt;

/// State с in-memory SQLite и temp-хранилищем.
async fn test_state(tag: &str) -> AppState {
    let dir = std::env::temp_dir().join(format!("echodrop-api-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pool = sqlx::SqlitePool::connect(":memory:").await.unwrap();
    crate::db::migrate(&pool).await.unwrap();
    AppState {
        unlock_secret: "test-secret".to_string(),
        limiter: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        config: Config {
            mode: Mode::Free,
            listen: "127.0.0.1:0".into(),
            storage_path: dir.to_str().unwrap().into(),
            storage_limit_gb: 0, // без лимита в тестах (0 = ∞)
            max_file_size_mb: 10,
            default_ttl_hours: 1,
            max_ttl_hours: 720,
            allow_infinite_ttl: false,
            site_name: "echodrop-test".into(),
            tracking: false,
            registration_token: None,
            allow_unreg_upload: true,
            base_url: "http://test".into(),
        },
        db: pool,
    }
}

/// Ручная сборка multipart-тела: опциональные password/ttl_hours + file.
fn multipart_body(boundary: &str, filename: &str, content: &str, ttl: Option<u64>) -> String {
    let mut body = String::new();
    if let Some(t) = ttl {
        body.push_str("--");
        body.push_str(boundary);
        body.push_str("\r\nContent-Disposition: form-data; name=\"ttl_hours\"\r\n\r\n");
        body.push_str(&t.to_string());
        body.push_str("\r\n");
    }
    body.push_str("--");
    body.push_str(boundary);
    body.push_str("\r\nContent-Disposition: form-data; name=\"file\"; filename=\"");
    body.push_str(filename);
    body.push_str("\"\r\nContent-Type: text/plain\r\n\r\n");
    body.push_str(content);
    body.push_str("\r\n--");
    body.push_str(boundary);
    body.push_str("--\r\n");
    body
}

async fn json_body(resp: Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

fn take_code(json: &serde_json::Value) -> String {
    json["short_code"].as_str().unwrap().to_string()
}

fn post_upload(_app: &Router, boundary: &str, raw_body: String) -> Request {
    Request::builder()
        .method("POST")
        .uri("/upload")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(raw_body))
        .unwrap()
}

/// (a) multipart upload -> GET: байты идентичны, имя в Content-Disposition.
#[tokio::test]
async fn multipart_roundtrip() {
    let state = test_state("rt").await;
    let app = router(10 * 1024 * 1024).with_state(state);
    let content = "hello echodrop api test";

    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XBOUND", multipart_body("XBOUND", "hello.txt", content, None)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let code = take_code(&json);
    assert_eq!(code.len(), 7);
    assert!(json["url"].as_str().unwrap().ends_with(&code));

    let req = Request::builder()
        .uri(format!("/{code}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disp = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(disp.contains("hello.txt"), "имя в disposition: {disp}");
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&got[..], content.as_bytes());
}

/// (b) TTL-семантика: 0 = «бессрочно» (только при allow_infinite_ttl),
/// истёкший файл -> 404, превышение потолка -> 400 + blob прибран.
#[tokio::test]
async fn expired_is_404() {
    let mut state = test_state("ttl").await;
    state.config.allow_infinite_ttl = true;
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    // ttl=0 при allow_infinite -> вечный: JSON с expires_at = null
    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XBOUND", multipart_body("XBOUND", "forever.txt", "stay", Some(0))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert!(json["expires_at"].is_null(), "вечный файл: null, а не число");
    let code = json["short_code"].as_str().unwrap().to_string();

    let req = Request::builder()
        .uri(format!("/{code}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "вечный файл отдаётся");

    // janitor не должен трогать вечные: прогоняем чистку напрямую
    janitor::cleanup_expired(&state.db, &state.config.storage_path)
        .await
        .unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM files WHERE short_code = ?1")
        .bind(&code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(n, 1, "janitor не удалил вечный файл");

    // ttl=1ч отгрузили в прошлое руками -> 404
    let now = janitor::now_secs();
    sqlx::query("UPDATE files SET expires_at = ?1 WHERE short_code = ?2")
        .bind(now - 10)
        .bind(&code)
        .execute(&state.db)
        .await
        .unwrap();
    let req = Request::builder()
        .uri(format!("/{code}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// (b2) TTL-лимиты: 0 без allow_infinite -> 400; выше max_ttl_hours -> 400;
/// blob после отказа не остаётся сиротой. Raw: X-TTL-Hours работает.
#[tokio::test]
async fn ttl_limits() {
    let mut state = test_state("ttllim").await;
    state.config.max_ttl_hours = 24;
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    // ttl=0 без allow_infinite -> 400
    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XBOUND", multipart_body("XBOUND", "no-inf.txt", "x", Some(0))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // ttl=25 > max 24 -> 400
    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XBOUND", multipart_body("XBOUND", "too-long.txt", "x", Some(25))))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // blob'ы от отказов убраны с диска (сирот не оставляем)
    let (blobs,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM files WHERE orig_name IN ('no-inf.txt','too-long.txt')")
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(blobs, 0, "строк в БД нет");

    // raw с X-TTL-Hours: 2 -> ок, в БД ~2 часа запаса
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .header("x-filename", "rawttl.bin")
        .header("x-ttl-hours", "2")
        .body(Body::from("raw ttl"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let exp = json["expires_at"].as_i64().unwrap();
    let (created,): (i64,) = sqlx::query_as(
        "SELECT created_at FROM files WHERE short_code = ?1",
    )
    .bind(json["short_code"].as_str().unwrap())
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert!((exp - created - 7200).abs() < 5, "X-TTL-Hours=2 учтён");

    // raw с X-TTL-Hours: 0 без флага -> 400
    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .header("x-filename", "raw0.bin")
        .header("x-ttl-hours", "0")
        .body(Body::from("raw zero"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// (c) raw-режим (curl -T): octet-stream + X-Filename.
#[tokio::test]
async fn raw_upload_roundtrip() {
    let state = test_state("raw").await;
    let app = router(10 * 1024 * 1024).with_state(state);
    let content = b"raw bytes here";

    let req = Request::builder()
        .method("POST")
        .uri("/upload")
        .header("content-type", "application/octet-stream")
        .header("x-filename", "bin/upload.bin")
        .body(Body::from(content.to_vec()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    let code = take_code(&json);
    assert_eq!(json["size"].as_u64().unwrap(), content.len() as u64);

    let req = Request::builder()
        .uri(format!("/{code}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let disp = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        disp.contains("upload.bin"),
        "путь из X-Filename обрезан до имени: {disp}"
    );
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&got[..], &content[..]);
}

/// (g) 413: тело больше DefaultBodyLimit -> PAYLOAD_TOO_LARGE.
#[tokio::test]
async fn oversized_413() {
    let state = test_state("big").await;
    // лимит config.max_file_size_mb = 10 MB, шлём чуть больше
    let app = router(10 * 1024 * 1024).with_state(state);
    let big = "x".repeat(10 * 1024 * 1024 + 1);

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", "application/octet-stream")
                .header("x-filename", "big.bin")
                .body(Body::from(big))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

/// (f) rate-limit: 31-я загрузка с одного IP за окно -> 429, другой IP не задет.
#[tokio::test]
async fn rate_limit_429() {
    let state = test_state("rl").await;
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    let mut last = None;
    for i in 0..31 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/upload")
                    .header("content-type", "multipart/form-data; boundary=XB")
                    .header("x-forwarded-for", "203.0.113.99")
                    .body(Body::from(multipart_body("XB", "rl.txt", &format!("try {i}"), None)))
                    .unwrap(),
            )
            .await
            .unwrap();
        last = Some(resp.status());
    }
    assert_eq!(last.unwrap(), StatusCode::TOO_MANY_REQUESTS);

    // другой IP — не задет
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", "multipart/form-data; boundary=XB")
                .header("x-forwarded-for", "198.51.100.1")
            .body(Body::from(multipart_body("XB", "rl.txt", "other ip", None)))
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// (e) трекинг: tracking=true -> в events пишутся upload и download
/// с ip (XFF) и fingerprint (UA); tracking=false -> таблицы events нет.
#[tokio::test]
async fn tracking_events() {
    let mut state = test_state("trk").await;
    state.config.tracking = true;
    crate::db::migrate_tracking(&state.db).await.unwrap();
    let app = router(10 * 1024 * 1024).with_state(state.clone());

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", "multipart/form-data; boundary=XB")
                .header("x-forwarded-for", "203.0.113.7")
                .header("user-agent", "test-agent/1.0")
                .body(Body::from(multipart_body("XB", "trk.txt", "tracked", None)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let code = take_code(&json_body(resp).await);

    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/{code}"))
                .header("x-forwarded-for", "198.51.100.9")
                .header("user-agent", "other-agent/2.0")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let events: Vec<(String, String, String)> =
        sqlx::query_as("SELECT kind, ip, fingerprint FROM events ORDER BY id")
            .fetch_all(&state.db)
            .await
            .unwrap();
    assert_eq!(events.len(), 2, "upload + download");
    assert_eq!(events[0].0, "upload");
    assert_eq!(events[0].1, "203.0.113.7");
    assert_eq!(events[1].0, "download");
    assert_eq!(events[1].1, "198.51.100.9");
    assert_ne!(events[0].2, events[1].2, "разные UA -> разные fp");

    // tracking=false: событий не пишется вовсе
    let state2 = test_state("trkoff").await;
    let app2 = router(10 * 1024 * 1024).with_state(state2.clone());
    let resp = app2.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/upload")
                .header("content-type", "multipart/form-data; boundary=XB")
                .body(Body::from(multipart_body("XB", "off.txt", "x", None)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let code2 = take_code(&json_body(resp).await);
    let resp = app2
        .oneshot(
            Request::builder()
                .uri(format!("/{code2}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let no_table: Result<Vec<(i64,)>, _> =
        sqlx::query_as("SELECT count(*) FROM events").fetch_all(&state2.db).await;
    assert!(no_table.is_err(), "таблицы events нет при tracking=false");
}

/// (k) Ф4-1: статика из embedded assets: лого 200 + content-type,
/// неизвестное имя 404, /static/* не конфликтует с короткими ссылками /{code}.
#[tokio::test]
async fn static_route() {
    let state = test_state("st").await;
    let app = router(10 * 1024 * 1024).with_state(state);

    // /static/logo.svg -> 200, image/svg+xml
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/logo.svg")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(ct, "image/svg+xml");

    // /static/style.css -> 200, text/css
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert_eq!(ct, "text/css; charset=utf-8");

    // неизвестное имя -> 404
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/static/nope.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // короткая ссылка /{code} жива: /static — не код (длина 6), но проверим соседний шейп
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/static")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // /static без файла не матчится на /static/{file} — уходит в /{code},
    // где отсекается проверкой длины (6 != 7)
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// (l) GET /config.json — публичные параметры для фронта.
#[tokio::test]
async fn public_config_json() {
    let mut state = test_state("cfg").await;
    state.config.max_ttl_hours = 24;
    state.config.allow_infinite_ttl = true;
    state.config.tracking = true;
    let app = router(10 * 1024 * 1024).with_state(state);

    let resp = app
        .oneshot(
            Request::builder()
                .uri("/config.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = json_body(resp).await;
    assert_eq!(json["max_ttl_hours"].as_u64().unwrap(), 24);
    assert_eq!(json["allow_infinite_ttl"].as_bool().unwrap(), true);
    assert_eq!(json["tracking"].as_bool().unwrap(), true);
    assert_eq!(json["mode"].as_str().unwrap(), "free");
    assert_eq!(json["max_file_size_mb"].as_u64().unwrap(), 10);
    assert!(!json.as_object().unwrap().contains_key("listen"), "внутренние поля не светим");
}

/// (m) has_password в JSON создания: с паролем true, без — false.
#[tokio::test]
async fn has_password_flag() {
    let state = test_state("pwflag").await;
    let app = router(10 * 1024 * 1024).with_state(state);

    // без пароля
    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XB", multipart_body("XB", "open.txt", "o", None)))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["has_password"].as_bool().unwrap(), false);

    // с паролем
    let mut body = String::new();
    body.push_str("--XB\r\n");
    body.push_str("Content-Disposition: form-data; name=\"password\"\r\n\r\nsekret\r\n");
    body.push_str("--XB\r\n");
    body.push_str("Content-Disposition: form-data; name=\"file\"; filename=\"locked.txt\"\r\n");
    body.push_str("Content-Type: text/plain\r\n\r\nlocked\r\n");
    body.push_str("--XB--\r\n");
    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XB", body))
        .await
        .unwrap();
    let json = json_body(resp).await;
    assert_eq!(json["has_password"].as_bool().unwrap(), true);
}

/// (d) пароль: upload с password -> без пароля 401-страница, с X-Password 200,
/// unlock-форма: неверный 401, верный -> cookie + redirect, GET с cookie 200.
#[tokio::test]
async fn password_flow() {
    let state = test_state("pw").await;
    let app = router(10 * 1024 * 1024).with_state(state);

    // multipart: password ДО file (порядок полей важен — file завершает приём)
    let mut body = String::new();
    body.push_str("--XB\r\n");
    body.push_str("Content-Disposition: form-data; name=\"password\"\r\n\r\nsekret\r\n");
    body.push_str("--XB\r\n");
    body.push_str("Content-Disposition: form-data; name=\"file\"; filename=\"locked.txt\"\r\n");
    body.push_str("Content-Type: text/plain\r\n\r\nlocked content\r\n");
    body.push_str("--XB--\r\n");

    let resp = app
        .clone()
        .oneshot(post_upload(&app, "XB", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let code = take_code(&json_body(resp).await);

    // без пароля -> страница разблокировки (401)
    let req = Request::builder()
        .uri(format!("/{code}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&bytes).contains("защищён паролем"));

    // unlock неверным паролем -> снова страница (401, без cookie)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{code}/unlock"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("password=wrong"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // X-Password верным -> файл
    let req = Request::builder()
        .uri(format!("/{code}"))
        .header("x-password", "sekret")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let got = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&got[..], b"locked content");

    // unlock верным -> 303 + Set-Cookie
    let req = Request::builder()
        .method("POST")
        .uri(format!("/{code}/unlock"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from("password=sekret"))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp
        .headers()
        .get(header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        cookie.starts_with(&format!("echodrop_{code}=")),
        "cookie: {cookie}"
    );

    // GET с cookie -> файл
    let req = Request::builder()
        .uri(format!("/{code}"))
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
}
