//! echodrop — файлообменник. Ф1: SQLite-база + пул в state.

mod auth;
mod codes;
mod config;
mod db;
mod janitor;
mod routes;
mod sessions;
mod storage;

use routes::AppState;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI-режим: `echodrop user add|del|list` — управление юзерами без
    // запуска сервера (Ф3a). Всё остальное — обычный запуск сервера.
    let argv: Vec<String> = std::env::args().collect();
    if argv.len() >= 3 && argv[1] == "user" {
        return cli_user(&argv[2..]).await;
    }

    // Конфиг: дефолты -> echodrop.toml -> env ECHODROP_*. Ошибка = внятный текст.
    let cfg = config::Config::load()?;

    // Хранилище и БД: папка создаётся при первом старте, схема — тоже.
    std::fs::create_dir_all(&cfg.storage_path)?;
    let db_path = format!("{}/echodrop.db", cfg.storage_path.trim_end_matches('/'));
    let pool = db::create_pool(&db_path).await?;
    db::migrate(&pool).await?;
    // users-таблица нужна в open/closed (ЛК); создаём всегда — пустая таблица
    // в free режиме безвредна, зато чистый деплой в open не словит 500 на регистрации.
    db::migrate_users(&pool).await?;
    // events-таблица рождается ТОЛЬКО при tracking=true: при false данных
    // нет ни в БД, ни на диске (решение по приватности).
    if cfg.tracking {
        db::migrate_tracking(&pool).await?;
    }

    // Чистильщик протухших файлов — фон, раз в минуту.
    janitor::spawn(pool.clone(), cfg.storage_path.clone());

    // State — то, что доступно каждому хендлеру: конфиг + пул БД.
    // Секрет разблокировок: случайный на процесс. Рестарт = все пароли
    // придётся вводить заново — осознанно (см. auth.rs).
    let unlock_secret = codes::random(32);
    let state = AppState {
        config: cfg.clone(),
        db: pool,
        unlock_secret,
        limiter: std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
    };

    let limit = (cfg.max_file_size_mb as usize) * 1024 * 1024;
    let app = routes::router(limit).with_state(state);
    let listener = TcpListener::bind(&cfg.listen).await?;

    println!(
        "echodrop listening on {}, mode={}, db={}",
        cfg.listen, cfg.mode, db_path
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// CLI: управление пользователями. `echodrop user add LOGIN PASSWORD`,
/// `echodrop user del LOGIN`, `echodrop user list`. Работает с той же БД,
/// что и сервер (путь из конфига/ENV). Вызывается до старта сервера.
async fn cli_user(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::Config::load()?;
    std::fs::create_dir_all(&cfg.storage_path)?;
    let db_path = format!("{}/echodrop.db", cfg.storage_path.trim_end_matches('/'));
    let pool = db::create_pool(&db_path).await?;
    db::migrate(&pool).await?;
    db::migrate_users(&pool).await?;

    match args {
        [cmd, rest @ ..] if cmd == "add" => {
            let (login, password) = match rest {
                [l, p, ..] => (l.clone(), p.clone()),
                _ => {
                    eprintln!("использование: echodrop user add LOGIN PASSWORD");
                    std::process::exit(2);
                }
            };
            let hash = crate::auth::hash_password(&password)
                .map_err(|e| format!("bcrypt: {e}"))?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs() as i64;
            let res = sqlx::query(
                "INSERT INTO users (login, password_hash, created_at) VALUES (?1, ?2, ?3)",
            )
            .bind(&login)
            .bind(&hash)
            .bind(now)
            .execute(&pool)
            .await;
            match res {
                Ok(_) => println!("ok: пользователь {login} добавлен"),
                Err(sqlx::Error::Database(db_err)) if db_err.message().contains("UNIQUE") => {
                    eprintln!("ошибка: логин {login} уже занят");
                    std::process::exit(1);
                }
                Err(e) => return Err(e.into()),
            }
        }
        [cmd, rest @ ..] if cmd == "del" => {
            let login = match rest {
                [l, ..] => l.clone(),
                _ => {
                    eprintln!("использование: echodrop user del LOGIN");
                    std::process::exit(2);
                }
            };
            let n = sqlx::query("DELETE FROM users WHERE login = ?1")
                .bind(&login)
                .execute(&pool)
                .await?
                .rows_affected();
            if n == 0 {
                eprintln!("не найден: {login}");
            } else {
                println!("ok: пользователь {login} удалён ({n})");
            }
        }
        [cmd] if cmd == "list" => {
            let rows: Vec<(String, i64)> =
                sqlx::query_as("SELECT login, created_at FROM users ORDER BY login")
                    .fetch_all(&pool)
                    .await?;
            if rows.is_empty() {
                println!("(пусто — пользователей нет)");
            }
            for (login, ts) in rows {
                println!("{login}\t{ts}");
            }
        }
        _ => {
            eprintln!("использование: echodrop user add|del|list");
            std::process::exit(2);
        }
    }
    pool.close().await;
    Ok(())
}
