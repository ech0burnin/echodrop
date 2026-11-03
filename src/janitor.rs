//! Чистильщик (janitor): фоновая задача, прибирающая протухшее.
//!
//! Две работы:
//! 1. expiry: строки с expires_at <= now удаляются из БД; blob на диске —
//!    только если на него не осталось других строк (дедуп: один blob может
//!    обслуживать несколько загрузок одного и того же контента);
//! 2. сироты: blob-файлы без строки в БД (остались от упавших загрузок) и
//!    забытые временные .tmp-файлы старше часа. Запускается раз в 10 тиков,
//!    чтобы не дёргать диск зря.

use crate::storage;
use sqlx::SqlitePool;
use std::time::Duration;

/// Запускает вечный цикл чистки (интервал 60 сек) в фоне.
pub fn spawn(pool: SqlitePool, storage_path: String) {
    tokio::spawn(async move {
        let mut iv = tokio::time::interval(Duration::from_secs(60));
        let mut tick: u32 = 0;
        loop {
            iv.tick().await;
            if let Err(e) = cleanup_expired(&pool, &storage_path).await {
                eprintln!("echodrop janitor: expiry-очистка упала: {e}");
            }
            tick = tick.wrapping_add(1);
            if tick % 10 == 0 {
                if let Err(e) = sweep_orphans(&pool, &storage_path).await {
                    eprintln!("echodrop janitor: обход сирот упал: {e}");
                }
            }
        }
    });
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Удаляет протухшие строки. Возвращает число удалённых.
pub async fn cleanup_expired(pool: &SqlitePool, storage_path: &str) -> Result<u64, sqlx::Error> {
    let expired: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, sha256 FROM files WHERE expires_at <= ?1")
            .bind(now_secs())
            .fetch_all(pool)
            .await?;
    if expired.is_empty() {
        return Ok(0);
    }
    let mut n = 0u64;
    for (id, sha) in &expired {
        sqlx::query("DELETE FROM files WHERE id = ?1").bind(id).execute(pool).await?;
        // blob можно сносить, только если ссылок больше нет (дедуп!)
        let (refs,): (i64,) = sqlx::query_as("SELECT count(*) FROM files WHERE sha256 = ?1")
            .bind(sha)
            .fetch_one(pool)
            .await?;
        if refs == 0 {
            storage::remove_blob(storage_path, sha).await;
        }
        n += 1;
    }
    Ok(n)
}

/// Обход диска: blob без строки в БД и старые .tmp — в расход.
/// Возвращает число удалённых файлов.
pub async fn sweep_orphans(pool: &SqlitePool, storage_path: &str) -> Result<u64, sqlx::Error> {
    use tokio::fs;
    let mut removed = 0u64;
    let mut dirs = match fs::read_dir(storage_path).await {
        Ok(d) => d,
        Err(_) => return Ok(0),
    };
    while let Ok(Some(sub)) = dirs.next_entry().await {
        let p = sub.path();
        if !p.is_dir() {
            continue;
        }
        let mut files = match fs::read_dir(&p).await {
            Ok(f) => f,
            Err(_) => continue,
        };
        while let Ok(Some(f)) = files.next_entry().await {
            let fp = f.path();
            let name = f.file_name().to_string_lossy().to_string();
            if name.starts_with(".tmp-") {
                // недокачанное: убираем, если старше часа
                if let Ok(meta) = f.metadata().await {
                    if let Ok(modified) = meta.modified() {
                        if modified.elapsed().map(|d| d.as_secs() > 3600).unwrap_or(false) {
                            let _ = fs::remove_file(&fp).await;
                            removed += 1;
                        }
                    }
                }
                continue;
            }
            if name.len() == 64 {
                let (refs,): (i64,) = sqlx::query_as("SELECT count(*) FROM files WHERE sha256 = ?1")
                    .bind(&name)
                    .fetch_one(pool)
                    .await?;
                if refs == 0 {
                    let _ = fs::remove_file(&fp).await;
                    removed += 1;
                }
            }
        }
    }
    Ok(removed)
}
