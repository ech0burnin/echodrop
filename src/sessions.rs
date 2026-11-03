//! Пользовательские сессии (Ф3b).
//!
//! Cookie echodrop_sess = login|expires|hmac. Подпись — HMAC-SHA256
//! производным секретом: user_secret = HMAC(unlock_secret, "user-sessions").
//! Тот же секрет на процесс: рестарт сбрасывает сессии (как с разблокировками
//! файлов — единая философия: ничего долгоживущего в памяти).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Имя cookie сессии.
pub const COOKIE: &str = "echodrop_sess";

/// Жизнь сессии: 7 дней.
pub const TTL_SECS: i64 = 7 * 24 * 3600;

/// Производный секрет пользовательских сессий.
fn user_secret(unlock_secret: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(unlock_secret.as_bytes()).expect("hmac ключ");
    mac.update(b"user-sessions");
    mac.finalize().into_bytes().to_vec()
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sign(secret: &[u8], payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac ключ");
    mac.update(payload.as_bytes());
    hex(&mac.finalize().into_bytes())
}

/// Собирает cookie-значение сессии для логина (сейчас + TTL).
pub fn make_session(unlock_secret: &str, login: &str) -> String {
    let secret = user_secret(unlock_secret);
    let expires = chrono_now() + TTL_SECS;
    let payload = format!("{login}|{expires}");
    format!("{payload}|{}", sign(&secret, &payload))
}

/// Проверяет cookie-значение: подпись и срок. None = нет/просрочена/кривая.
pub fn parse_session(unlock_secret: &str, cookie_value: &str) -> Option<String> {
    let secret = user_secret(unlock_secret);
    let mut parts = cookie_value.splitn(3, '|');
    let login = parts.next()?;
    let expires: i64 = parts.next()?.parse().ok()?;
    let sig = parts.next()?;
    if login.is_empty() {
        return None;
    }
    let payload = format!("{login}|{expires}");
    let expect = sign(&secret, &payload);
    // constant-time сравнение
    let a = expect.as_bytes();
    let b = sig.as_bytes();
    if a.len() != b.len() {
        return None;
    }
    if a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) != 0 {
        return None;
    }
    if expires <= chrono_now() {
        return None;
    }
    Some(login.to_string())
}

/// Достаёт echodrop_sess из заголовка Cookie.
pub fn session_from_headers(
    headers: &axum::http::HeaderMap,
    unlock_secret: &str,
) -> Option<String> {
    let cookies = headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    let prefix = format!("{COOKIE}=");
    for pair in cookies.split(';') {
        let pair = pair.trim();
        if let Some(rest) = pair.strip_prefix(&prefix) {
            let val = rest.split(';').next().unwrap_or(rest);
            return parse_session(unlock_secret, val);
        }
    }
    None
}

/// Текущий unix-time без зависимости от chrono (уже есть janitor::now_secs,
/// но модуль сессий независим — свой тонкий геттер).
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_roundtrip() {
        let s = make_session("topsecret", "alice");
        assert_eq!(parse_session("topsecret", &s).as_deref(), Some("alice"));
    }

    #[test]
    fn session_wrong_secret() {
        let s = make_session("topsecret", "alice");
        assert_eq!(parse_session("other", &s), None);
    }

    #[test]
    fn session_tampered() {
        let s = make_session("topsecret", "alice");
        let mut tampered = s.clone();
        // подменим логин в payload, подпись останется старой
        tampered.replace_range(0..5, "hacker");
        assert_eq!(parse_session("topsecret", &tampered), None);
    }
}
