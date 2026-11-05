#!/usr/bin/env bash
# echodrop installer: env -> systemd-сервис + CLI в PATH.
# Запускать из распакованного архива релиза: ./install.sh
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/echodrop"
ENVF="$DIR/echodrop.env"
[ -f "$BIN" ] || { echo "ошибка: рядом нет бинаря echodrop"; exit 1; }
[ -x "$BIN" ] || chmod +x "$BIN"
if [ ! -f "$ENVF" ]; then
  [ -f "$DIR/echodrop.env.example" ] && cp "$DIR/echodrop.env.example" "$ENVF" || { echo "ошибка: нет echodrop.env(.example)"; exit 1; }
  echo "-> echodrop.env создан из примера. ОТРЕДАКТИРУЙТЕ его и запустите install.sh снова."
  exit 1
fi

# 1) CLI в PATH (пользовательский ~/.local/bin — sudo не нужен)
DEST="$HOME/.local/bin"
mkdir -p "$DEST"
ln -sf "$BIN" "$DEST/echodrop"
echo "-> CLI: $DEST/echodrop"
if [ -f "$HOME/.bashrc" ] && ! grep -q 'echodrop.env' "$HOME/.bashrc"; then
  printf '\n# echodrop: env для CLI (та же база, что у сервиса)\nset -a; . "%s/echodrop.env"; set +a\n' "$DIR" >> "$HOME/.bashrc"
  echo "-> env добавлен в ~/.bashrc (новый терминал или: source ~/.bashrc)"
fi

# 2) systemd-сервис от текущего пользователя (systemd --user; sudo не нужен)
U="$HOME/.config/systemd/user/echodrop.service"
mkdir -p "$(dirname "$U")"
cat > "$U" << UNIT
[Unit]
Description=echodrop file sharing
After=network.target

[Service]
EnvironmentFile=$ENVF
WorkingDirectory=$DIR
ExecStart=$BIN
Restart=on-failure

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable --now echodrop
sleep 1
systemctl --user is-active echodrop && echo "=> сервис запущен" || { echo "=> сервис НЕ запустился, смотрите: journalctl --user -u echodrop -e"; exit 1; }

echo
echo "Готово. Дальше — прокинуть порт наружу (reverse-proxy/curl), см. README."
echo "CLI доступен: echodrop user list  (после source ~/.bashrc)"
