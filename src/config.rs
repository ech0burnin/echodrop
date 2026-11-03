//! Конфигурация echodrop.
//!
//! Приоритет источников (кто позже — тот и прав):
//!   1. встроенные дефолты (serde default на полях);
//!   2. файл `echodrop.toml` рядом с бинарём (можно частичный — недостающее из дефолтов);
//!   3. переменные окружения `ECHODROP_*` (для systemd/докера удобнее, чем править файл).
//!
//! Ошибка в любом источнике — стартуем с понятным сообщением, молча гадать не умеем.

use serde::Deserialize;
use std::fmt;

/// Режим работы сайта. Отвечает за то, кто может заводить аккаунты:
/// - `free`   — только дропзона, личных кабинетов нет (по умолчанию);
/// - `open`   — свободная регистрация;
/// - `closed` — регистрация закрыта, входят только существующие пользователи.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Free,
    Open,
    Closed,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Free
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Mode::Free => "free",
            Mode::Open => "open",
            Mode::Closed => "closed",
        })
    }
}

impl std::str::FromStr for Mode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "free" => Ok(Mode::Free),
            "open" => Ok(Mode::Open),
            "closed" => Ok(Mode::Closed),
            other => Err(format!(
                "неизвестный режим {other:?} — ожидается free | open | closed"
            )),
        }
    }
}

/// Главный конфиг приложения. Все поля с дефолтами, поэтому частичный
/// `echodrop.toml` валиден: что не указано — берётся из `default_*` ниже.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Режим работы: free / open / closed (см. [Mode]).
    #[serde(default = "default_mode")]
    pub mode: Mode,
    /// Куда биндим сокет: "ip:port".
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Каталог для загруженных файлов.
    #[serde(default = "default_storage_path")]
    pub storage_path: String,
    /// Потолок размера файла в мегабайтах.
    #[serde(default = "default_max_file_size_mb")]
    pub max_file_size_mb: u64,
    /// Время жизни файла по умолчанию, часы (168 = неделя).
    #[serde(default = "default_default_ttl_hours")]
    pub default_ttl_hours: u64,
    /// Имя сайта — идёт в шапку страниц и `<title>`.
    #[serde(default = "default_site_name")]
    pub site_name: String,
    /// Публичный адрес сайта, из него строятся короткие ссылки.
    #[serde(default = "default_base_url")]
    pub base_url: String,
    /// Трекинг связей файл-IP-fingerprint (upload+download). false = данные
    /// ВООБЩЕ не собираются, таблица events не создаётся. Осознанный выбор
    /// приватности владельца инстанса.
    #[serde(default)]
    pub tracking: bool,
}

fn default_mode() -> Mode {
    Mode::Free
}
fn default_listen() -> String {
    "0.0.0.0:8080".to_string()
}
fn default_storage_path() -> String {
    "./data".to_string()
}
fn default_max_file_size_mb() -> u64 {
    100
}
fn default_default_ttl_hours() -> u64 {
    168
}
fn default_site_name() -> String {
    "echodrop".to_string()
}
fn default_base_url() -> String {
    "http://localhost:8080".to_string()
}

impl Config {
    /// Собирает конфиг: дефолты → `echodrop.toml` → env `ECHODROP_*`.
    /// Возвращает ошибку одной строкой — её видно и в journalctl, и в консоли.
    pub fn load() -> Result<Self, String> {
        // Шаг 1. Дефолты: пустой TOML + serde-дефолты полей дают полную структуру.
        let mut cfg: Config = toml::from_str("").map_err(|e| format!("дефолтный конфиг сломан: {e}"))?;

        // Шаг 2. Файл конфигурации, если существует. Отсутствие — не ошибка.
        match std::fs::read_to_string("echodrop.toml") {
            Ok(text) => {
                cfg = toml::from_str(&text)
                    .map_err(|e| format!("не смог разобрать echodrop.toml: {e}"))?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("не смог прочитать echodrop.toml: {e}")),
        }

        // Шаг 3. Оверрайды окружением. Пустая переменная игнорируется.
        if let Ok(v) = std::env::var("ECHODROP_MODE") {
            if !v.is_empty() {
                cfg.mode = v.parse().map_err(|e| format!("ECHODROP_MODE: {e}"))?;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_LISTEN") {
            if !v.is_empty() {
                cfg.listen = v;
            }
        }
        // Порт отдельно: ECHODROP_PORT подменяет только порт, IP из listen сохраняется.
        if let Ok(v) = std::env::var("ECHODROP_PORT") {
            if !v.is_empty() {
                let port: u16 = v.parse().map_err(|_| format!("ECHODROP_PORT: {v:?} — не число 0-65535"))?;
                let ip = cfg
                    .listen
                    .rsplit_once(':')
                    .map(|(ip, _)| ip.to_string())
                    .unwrap_or_else(|| "0.0.0.0".to_string());
                cfg.listen = format!("{ip}:{port}");
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_STORAGE_PATH") {
            if !v.is_empty() {
                cfg.storage_path = v;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_MAX_FILE_SIZE_MB") {
            if !v.is_empty() {
                cfg.max_file_size_mb =
                    v.parse().map_err(|_| format!("ECHODROP_MAX_FILE_SIZE_MB: {v:?} — не число"))?;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_DEFAULT_TTL_HOURS") {
            if !v.is_empty() {
                cfg.default_ttl_hours =
                    v.parse().map_err(|_| format!("ECHODROP_DEFAULT_TTL_HOURS: {v:?} — не число"))?;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_SITE_NAME") {
            if !v.is_empty() {
                cfg.site_name = v;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_BASE_URL") {
            if !v.is_empty() {
                cfg.base_url = v;
            }
        }
        if let Ok(v) = std::env::var("ECHODROP_TRACKING") {
            if !v.is_empty() {
                cfg.tracking = v.parse().map_err(|_| format!("ECHODROP_TRACKING: {v:?} — ожидается true|false"))?;
            }
        }

        Ok(cfg)
    }
}
