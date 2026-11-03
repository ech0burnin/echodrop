//! Пароли файлов и cookie-токены разблокировки.
//!
//! Схема: у файла может быть password_hash (bcrypt). Скачивание без пароля
//! невозможно. Пароль принимается двумя путями:
//! - API: заголовок X-Password на GET /{code} (для curl/скриптов);
//! - браузер: POST /{code}/unlock с формой -> HttpOnly-cookie с токеном.
//!
//! Токен = HMAC-SHA256(secret, code), где secret живёт только в памяти
//! процесса (рестарт сервера сбивает все разблокировки — это фича, не баг:
//! сессия разблокировки не переживает перезапуск).

use axum::http::{header, HeaderMap, StatusCode};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Хэширует пароль. cost 8: ~30 мс — на порядок быстрее дефолтного 12,
/// для файлообменника запас прочности достаточный.
pub fn hash_password(pw: &str) -> Result<String, String> {
    bcrypt::hash(pw, 8).map_err(|e| format!("bcrypt: {e}"))
}

/// Сверяет пароль с хэшем.
pub fn verify_password(pw: &str, hash: &str) -> bool {
    bcrypt::verify(pw, hash).unwrap_or(false)
}

/// Cookie-токен разблокировки конкретного файла.
pub fn make_token(secret: &str, code: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac ключ любой длины");
    mac.update(code.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Проверяет токен из cookie.
pub fn check_token(secret: &str, code: &str, token: &str) -> bool {
    // сравнение без раннего выхода: constant-time по духу
    let expect = make_token(secret, code);
    let a = expect.as_bytes();
    let b = token.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Достаёт пароль из X-Password (API-путь).
pub fn password_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-password")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Достаёт токен из Cookie: echodrop_<code>=<token>.
pub fn token_from_cookies(headers: &HeaderMap, code: &str) -> Option<String> {
    let cookies = headers.get(header::COOKIE)?.to_str().ok()?;
    let prefix = format!("echodrop_{code}=");
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&prefix) {
            return Some(rest.split(';').next().unwrap_or(rest).to_string());
        }
    }
    None
}

/// Рендер мини-страницы разблокировки.
pub fn unlock_page(code: &str, wrong: bool) -> axum::response::Response {
    let msg = if wrong {
        "<p class='err'>неверный пароль</p>"
    } else {
        ""
    };
    let html = format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>echodrop — доступ</title>
<link rel="stylesheet" href="/static/style.css">
<style>
 body {{ display:flex;align-items:center;justify-content:center;min-height:100vh; }}
 .card {{ padding:32px;width:min(92vw,360px);text-align:center; }}
 h1 {{ font-size:20px;margin:0 0 4px;letter-spacing:2px; }}
 p.sub {{ margin:0 0 20px; }}
 input[type=password] {{ width:100%; }}
 button {{ margin-top:12px;width:100%; }}
 .err {{ margin:0 0 12px; }}
</style></head><body><div class="card panel">
<h1><img src="/static/logo.svg" alt="" style="height:24px;vertical-align:middle;filter:invert(1)"> echodrop</h1><p class="sub">файл защищён паролем</p>{msg}
<form method="post" action="/{code}/unlock">
 <input type="password" name="password" placeholder="пароль" autofocus required>
 <button type="submit">открыть</button>
</form></div></body></html>"#
    );
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

use axum::response::IntoResponse;

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
