//! Короткие коды файлов: base62, 7 символов, проверка коллизий в БД.
//!
//! base62 (0-9a-zA-Z) даёт 62^7 ≈ 3.5 триллиона комбинаций — при наших
//! объёмах коллизии редки как снег в июне, но проверка всё равно нужна:
//! UNIQUE-индекс в SQLite не простит повтор. 8 попыток с запасом хватит
//! всей вселенной (вероятность 8 коллизий подряд ничтожна).

use rand::Rng;
use sqlx::SqlitePool;

const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CODE_LEN: usize = 7;

/// Случайный код заданной длины.
pub fn random(len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

/// Код, гарантированно свободный в таблице files.
/// Возвращает ошибку, если БД недоступна или 8 попыток подряд дали коллизию
/// (последнее практически невозможно — см. модульный комментарий).
pub async fn unique(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    for _ in 0..8 {
        let code = random(CODE_LEN);
        let taken: Option<(i64,)> = sqlx::query_as("SELECT id FROM files WHERE short_code = ?1")
            .bind(&code)
            .fetch_optional(pool)
            .await?;
        if taken.is_none() {
            return Ok(code);
        }
    }
    Err(sqlx::Error::RowNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape() {
        let c = random(CODE_LEN);
        assert_eq!(c.len(), CODE_LEN);
        assert!(c.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
