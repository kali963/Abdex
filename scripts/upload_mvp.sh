#!/usr/bin/env bash
# Загрузка существующего MVP AbdEX в репозиторий (ветка mvp-original). macOS / Linux.
#   1. Распакуйте RAR:   unrar x abdex.rar ~/abdex-mvp/   (или через любой архиватор)
#   2. Запустите:        bash scripts/upload_mvp.sh ~/abdex-mvp
set -euo pipefail

SOURCE="${1:?Укажите путь к распакованной папке MVP}"
REPO_URL="${REPO_URL:-https://github.com/kali963/Abdex.git}"
BRANCH="${BRANCH:-mvp-original}"
WORKDIR="${WORKDIR:-$HOME/abdex-upload}"

command -v git >/dev/null || { echo "Установите git"; exit 1; }
[ -d "$SOURCE" ] || { echo "Папка $SOURCE не найдена — сначала распакуйте RAR"; exit 1; }

echo "==> Подготовка репозитория в $WORKDIR"
if [ -d "$WORKDIR/.git" ]; then git -C "$WORKDIR" fetch origin; else git clone "$REPO_URL" "$WORKDIR"; fi
git -C "$WORKDIR" checkout -B "$BRANCH" origin/main

echo "==> Копирование проекта (без мусора и секретов)"
DEST="$WORKDIR/legacy/mvp"
rm -rf "$DEST"; mkdir -p "$DEST"
EXCLUDES=(.git .venv venv env __pycache__ node_modules .idea .vscode .pytest_cache .mypy_cache media uploads var logs
          static_root dist build '*.pyc' .env '.env.*' '*.pem' '*.key' '*.p12' '*.pfx' '*.crt' '*.sqlite3' '*.db'
          '*.rar' '*.zip' '*.7z' '*.log' '*.dump' '*.sql.gz' '*.bak')
if command -v rsync >/dev/null; then
  args=(); for e in "${EXCLUDES[@]}"; do args+=(--exclude "$e"); done
  rsync -a "${args[@]}" "$SOURCE"/ "$DEST"/
else
  tar_args=(); for e in "${EXCLUDES[@]}"; do tar_args+=(--exclude "$e"); done
  (cd "$SOURCE" && tar cf - "${tar_args[@]}" .) | (cd "$DEST" && tar xf -)
fi
[ -f "$SOURCE/.env.example" ] && cp "$SOURCE/.env.example" "$DEST/.env.example"

echo "==> Проверка размеров (GitHub не принимает файлы > 100 МБ)"
find "$DEST" -type f -size +95M -print -delete | sed 's/^/  исключен: /' || true
echo "Итого: $(find "$DEST" -type f | wc -l) файлов, $(du -sh "$DEST" | cut -f1)"

echo "==> Поиск возможных секретов"
if grep -rnEI --include='*.py' --include='*.json' --include='*.yml' --include='*.yaml' --include='*.ini' --include='*.toml' \
     "(password|secret_key|api[_-]?key)\s*=\s*['\"][^'\"]{6,}|postgres(ql)?://[^:]+:[^@]+@" "$DEST" | head -20; then
  read -r -p "Найдены возможные секреты. Все равно продолжить? (да/нет) " ans
  [[ "$ans" =~ ^(да|y|yes)$ ]] || { echo "Остановлено"; exit 1; }
fi

echo "==> Коммит и отправка"
git -C "$WORKDIR" add legacy/mvp
git -C "$WORKDIR" commit -m "Import existing AbdEX MVP into legacy/mvp" \
  -m "Imported from local archive; virtualenvs, caches, databases, uploads and secrets excluded."
git -C "$WORKDIR" push -u origin "$BRANCH"
echo "Готово! MVP в ветке '$BRANCH', папка legacy/mvp. Напишите Claude: «MVP загружен в ветку mvp-original»."
