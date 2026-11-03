//! Хранилище blob-ов echodrop: файловая система под управлением БД.
//!
//! Контент-адресация: имя файла на диске = sha256 содержимого. Бонусы:
//! - дедупликация: два одинаковых аплоада лягут в один blob (в БД две строки);
//! - целостность: имя = контрольная сумма, проверяема в любой момент;
//! - шардирование: blob кладётся в подпапку из первых двух hex-символов
//!   (`ab/cdef...`), чтобы в одной папке не скапливались сотни тысяч файлов.

use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;

/// Результат сохранения: сумма и итоговый размер.
pub struct StoredBlob {
    pub sha256: String,
    pub size: u64,
}

/// Инкрементальный писатель blob: принимает чанки из любого источника
/// (multipart-поле или raw-тело), считает sha256 на лету, на диск пишет
/// сразу — целиком файл в памяти не держим.
///
/// Пишет во временный файл рядом с целевым (атомарность: недокачанный blob
/// не появится под финальным именем), затем переименовывает. Если целевой
/// blob уже существует (дедуп) — временный удаляется.
pub struct BlobWriter {
    tmp: PathBuf,
    root: PathBuf,
    file: tokio::fs::File,
    hasher: Sha256,
    size: u64,
}

impl BlobWriter {
    /// Начинает запись нового blob в хранилище.
    pub async fn create(storage_path: &str) -> std::io::Result<Self> {
        let root = Path::new(storage_path).to_path_buf();
        tokio::fs::create_dir_all(&root).await?;
        let tmp = root.join(format!(".tmp-{}-{}", std::process::id(), nanos()));
        let file = tokio::fs::File::create(&tmp).await?;
        Ok(Self {
            tmp,
            root,
            file,
            hasher: Sha256::new(),
            size: 0,
        })
    }

    /// Дописывает чанк. Пустые чанки игнорирует.
    pub async fn write_chunk(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.file.write_all(bytes).await?;
        self.hasher.update(bytes);
        self.size += bytes.len() as u64;
        Ok(())
    }

    /// Завершает: fsync, затем атомарный rename под финальное имя.
    /// При существующем blob (дедуп) временный файл молча убирается.
    pub async fn finish(self) -> std::io::Result<StoredBlob> {
        self.file.sync_all().await?;
        drop(self.file);
        let sha = hex(&self.hasher.finalize());
        let dest = blob_path(&self.root, &sha);
        if dest.exists() {
            let _ = tokio::fs::remove_file(&self.tmp).await;
        } else {
            if let Some(dir) = dest.parent() {
                tokio::fs::create_dir_all(dir).await?;
            }
            tokio::fs::rename(&self.tmp, &dest).await?;
        }
        Ok(StoredBlob {
            sha256: sha,
            size: self.size,
        })
    }

    /// Откат: недокачанный blob удаляется (вызывать при ошибке источника).
    pub async fn abort(self) {
        let _ = tokio::fs::remove_file(&self.tmp).await;
    }
}

/// Путь до blob по сумме: `storage/ab/abcdef...`.
pub fn blob_path(root: &Path, sha256: &str) -> PathBuf {
    root.join(&sha256[..2]).join(sha256)
}

/// Удаляет blob, если существует. Ошибки не возвращаем: мусор подберёт janitor.
pub async fn remove_blob(storage_path: &str, sha256: &str) {
    let p = blob_path(Path::new(storage_path), sha256);
    if let Err(e) = tokio::fs::remove_file(&p).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("echodrop: не смог удалить blob {sha256}: {e}");
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blob_writer_roundtrip_and_dedup() {
        let dir = std::env::temp_dir().join(format!("echodrop-storage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sp = dir.to_str().unwrap().to_string();

        let data: Vec<u8> = b"hello echodrop".repeat(1000);

        // Пишем двумя чанками
        let mut w = BlobWriter::create(&sp).await.unwrap();
        w.write_chunk(&data[..100]).await.unwrap();
        w.write_chunk(&data[100..]).await.unwrap();
        let a = w.finish().await.unwrap();

        // Тот же контент ещё раз — дедуп, вторая запись на диске не появляется
        let mut w2 = BlobWriter::create(&sp).await.unwrap();
        w2.write_chunk(&data).await.unwrap();
        let b = w2.finish().await.unwrap();

        assert_eq!(a.sha256, b.sha256, "одинаковый контент = одна сумма");
        assert_eq!(a.size, data.len() as u64);
        assert_eq!(b.size, data.len() as u64);

        // Читаем обратно
        let path = blob_path(Path::new(&sp), &a.sha256);
        let read = tokio::fs::read(&path).await.unwrap();
        assert_eq!(read, data);

        // Удаление
        remove_blob(&sp, &a.sha256).await;
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
