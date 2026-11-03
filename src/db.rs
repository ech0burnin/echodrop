//! База данных echodrop: SQLite через sqlx.
//!
//! Почему runtime-запросы (sqlx::query), а не макросы (query!):
//! макросы проверяют SQL на этапе компиляции, но требуют `cargo sqlx prepare`
//! и файл .sqlx в репо. Для учебного проекта лишняя магия — обычные
//! query(...) с проверкой в рантайме (тестами) проще и понятнее.
//!
//! Схема живёт тут же, миграционного фреймворка нет: CREATE TABLE IF NOT EXISTS
//! при старте — для наших масштабов этого хватает, эволюцию схемы будем
//! делать аккуратными ALTER в коде по мере надобности.

use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

/// Создаёт пул соединений к БД по пути (например, `data/echodrop.db`).
///
/// - `create_if_missing` — файл БД рождается сам при первом старте;
/// - WAL — режим журнала: читатели не блокируют писателя, для веба must-have;
/// - foreign_keys — включить внешние ключи (в SQLite они по умолчанию ВЫКЛ,
///   классическая ловушка).
/// Пул маленький (max 4): SQLite не любит много параллельных писателей.
pub async fn create_pool(path: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(format!("sqlite://{path}").as_str())?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true);
    SqlitePoolOptions::new().max_connections(4).connect_with(opts).await
}

/// Схема. Вызывается при каждом старте — IF NOT EXISTS делает это идемпотентным.
/// Время — unix-секунды: проще сравнивать с TTL и не возиться с таймзонами.
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS files (
            id            INTEGER PRIMARY KEY,
            short_code    TEXT UNIQUE NOT NULL,
            orig_name     TEXT NOT NULL,
            size          INTEGER NOT NULL,
            mime          TEXT NOT NULL,
            sha256        TEXT NOT NULL,
            created_at    INTEGER NOT NULL,
            expires_at    INTEGER NOT NULL,
            password_hash TEXT NULL,
            downloads     INTEGER NOT NULL DEFAULT 0,
            owner_id      INTEGER NULL
        )",
    )
    .execute(pool)
    .await?;

    // Индексы: short_code дёргается на каждом скачивании (UNIQUE уже даёт
    // индекс, но явный — dokumentiruem намерение), expires_at — чистильщик
    // сканирует каждую минуту.
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_files_expires ON files(expires_at)")
        .execute(pool)
        .await?;
    Ok(())
}

/// Таблица пользователей (Ф3a). В отличие от events — создаётся ВСЕГДА,
/// независимо от режима: CLI-подкоманды `user add/del/list` и сервер
/// работают с одной и той же таблицей, пароль — bcrypt-хэш (auth.rs).
pub async fn migrate_users(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY,
            login         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at    INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    Ok(())
}

/// Таблица связей файл-IP-fingerprint. Вызывается ТОЛЬКО при
/// config.tracking=true: при false таблицы нет вовсе, данные не
/// собираются никуда — приватность по умолчанию (решение по приватности).
pub async fn migrate_tracking(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY,
            file_id     INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
            kind        TEXT NOT NULL,          -- upload | download
            ip          TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            created_at  INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_events_file ON events(file_id)")
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ф1a-критерий: БД создаётся с нуля, схема на месте, SELECT проходит.
    /// Временный файл — в tempdir, чтобы тест не гадил в data/.
    #[tokio::test]
    async fn db_creates_and_counts() {
        let dir = std::env::temp_dir().join(format!("echodrop-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let path_str = path.to_str().unwrap();

        let pool = create_pool(path_str).await.expect("пул создан");
        migrate(&pool).await.expect("миграция прошла");

        let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM files")
            .fetch_one(&pool)
            .await
            .expect("SELECT прошёл");
        assert_eq!(n, 0, "таблица пустая после создания");

        pool.close().await;
        let _ = std::fs::remove_file(&path); // прибираем + wal/shm
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }
}
