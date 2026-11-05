# echodrop

Минималистичный self-hosted файлообменник. Один Rust-бинарь, SQLite, ноль внешних зависимостей — Docker не обязателен.

**Статус:** v0.4.0 — ранняя разработка, но ядро работает.

## Возможности

- Дроп-зона: перетащил файл — получил короткую ссылку. Без аккаунта, если инстанс так настроен
- Три режима инстанса: `free` (дропзона без аккаунтов) / `open` (свободная регистрация + личный кабинет) / `closed` (регистрация закрыта, вход существующих)
- ЛК: список своих файлов, удаление
- TTL на файл: от часа до потолка инстанса, опционально «бессрочно»
- Пароль на файл (bcrypt)
- Хранение content-addressed (sha256): одинаковые файлы не занимают место дважды
- CLI-friendly: `curl -F file=@x.bin http://host/upload` работает
- i18n EN/RU, переключение темы dark/light на лету
- Конфигурация только через env — systemd-friendly, docker-friendly
- Опциональный трекинг upload/download (IP + fingerprint) для правовой реальности

## Быстрый старт (из релизного архива)

```bash
# скачать и распаковать архив релиза (echodrop-linux-amd64.tar.gz), затем:
cp echodrop.env.example echodrop.env   # отредактируй под себя
./install.sh                           # сервис + CLI в PATH
source ~/.bashrc                       # чтобы echodrop был виден сразу
```

install.sh делает три вещи: кладёт симлинк в `~/.local/bin`, подключает
`echodrop.env` в `~/.bashrc` (CLI работает с той же базой, что сервис),
поднимает systemd user-юнит `echodrop`. Прокинуть наружу — reverse-proxy (nginx), см. ниже.

Сборка из исходников (Rust 1.75+):

```bash
cargo build --release
cp echodrop.env.example echodrop.env   # отредактируй под себя
set -a; . ./echodrop.env; set +a
./target/release/echodrop
```

## Развертывание

### systemd

`/etc/systemd/system/echodrop.service`:

```ini
[Unit]
Description=echodrop file sharing
After=network.target

[Service]
User=echodrop
EnvironmentFile=/etc/echodrop/echodrop.env
ExecStart=/usr/local/bin/echodrop
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now echodrop
```

### Docker

Dockerfile в репозитории пока нет — но запуск без него прост:

```bash
cargo build --release
docker run -d --name echodrop -p 8080:8080 \
  --env-file echodrop.env \
  -v /srv/echodrop/data:/data \
  debian:stable-slim /target/release/echodrop  # смонтируй бинарь в контейнер
```

Проще: `cargo build --release` на хосте, бинарь + env-файл копируются в чистый образ (см. roadmap ниже).

### Обратный прокси (nginx)

```nginx
server {
    listen 443 ssl;
    server_name files.example.com;
    client_max_body_size 110m;   # чуть больше ECHODROP_MAX_FILE_SIZE_MB

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Конфигурация

Только переменные окружения — все опциональны, дефолты разумные. Полный список с пояснениями RU/EN: **[echodrop.env.example](echodrop.env.example)**.

Ключевое:

| Переменная | Дефолт | Что делает |
|---|---|---|
| `ECHODROP_MODE` | `free` | free / open / closed |
| `ECHODROP_LISTEN` | `0.0.0.0:8080` | адрес сервера |
| `ECHODROP_PORT` | — | перекрывает только порт из LISTEN |
| `ECHODROP_STORAGE_PATH` | `./data` | каталог файлов и SQLite |
| `ECHODROP_MAX_FILE_SIZE_MB` | `100` | потолок загрузки |
| `ECHODROP_DEFAULT_TTL_HOURS` | `168` | срок жизни по умолчанию |
| `ECHODROP_MAX_TTL_HOURS` | `720` | потолок TTL |
| `ECHODROP_ALLOW_INFINITE_TTL` | `false` | разрешить «бессрочно» |
| `ECHODROP_TRACKING` | `false` | трекинг upload/download |
| `ECHODROP_REGISTRATION_TOKEN` | — | код приглашения при регистрации (только open; пусто = свободная регистрация) |
| `ECHODROP_ALLOW_UNREG_UPLOAD` | `true` | false = грузить могут только залогиненные (open/closed; в free игнорируется) |
| `ECHODROP_STORAGE_LIMIT_GB` | `0` | потолок хранилища (0 = без лимита) |
| `ECHODROP_SITE_NAME` | `echodrop` | название сайта |
| `ECHODROP_BASE_URL` | `http://localhost:8080` | публичный URL для ссылок |

## Режимы и аккаунты

- **free** — классическая анонимная дропзона. Аккаунтов нет, страницы входа/регистрации скрыты.
- **open** — + аккаунты: свободная регистрация (или по invite-коду `ECHODROP_REGISTRATION_TOKEN`), вход, «мои файлы» прямо на главной.
- **closed** — дропзона для всех, аккаунты только через CLI (`echodrop user add`). Вход и «мои файлы» доступны созданным юзерам.

Вход и регистрация — модальные окна на главной (отдельных страниц нет). Список файлов залогиненного пользователя отображается на главной под зоной загрузки.

CLI для доверенных юзеров (закрытый режим):

```bash
echodrop user add LOGIN PASSWORD   # создать доверенного
echodrop user list                # список
echodrop user del LOGIN           # удалить
```

CLI работает с той же базой, что и сервис — при условии, что видит те же env-переменные.
`install.sh` подключает `echodrop.env` в `~/.bashrc`, поэтому после установки всё совпадает
автоматически. Если сервер запускался вручную с нестандартным `ECHODROP_STORAGE_PATH` —
укажите его и при запуске CLI одной командой: `ECHODROP_STORAGE_PATH=/path echodrop user add ...`
(префикс `VAR=value` перед командой задаёт переменную только для этого запуска).

## Roadmap

- [ ] Квоты на хранилище: лимит на аккаунт или IP (например 2 ГБ на юзера — чтобы никто не засрал весь диск инстанса)
- [ ] Индикатор заполненности хранилища в кабинете
- [ ] API-токены для CLI-клиентов
- [ ] Права на инстанс: админ-панель

## Разработка


## License

TBD
