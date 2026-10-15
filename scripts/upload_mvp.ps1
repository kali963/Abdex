<#
  Загрузка существующего MVP AbdEX в репозиторий (ветка mvp-original).

  Использование (PowerShell):
    1. Распакуйте RAR в любую папку, например C:\abdex-mvp
    2. Запустите:
         powershell -ExecutionPolicy Bypass -File .\upload_mvp.ps1 -Source "C:\abdex-mvp"

  Скрипт:
    - клонирует репозиторий во временную папку (или обновляет уже склонированный),
    - создает ветку mvp-original от main,
    - копирует проект в legacy/mvp, ИСКЛЮЧАЯ виртуальные окружения, кэши, node_modules,
      базы данных, загруженные пользователями файлы и секреты (.env, ключи, сертификаты),
    - проверяет файлы больше 95 МБ (GitHub не принимает файлы > 100 МБ),
    - делает коммит и отправляет ветку на GitHub.
#>
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [string]$RepoUrl = "https://github.com/kali963/Abdex.git",
    [string]$Branch = "mvp-original",
    [string]$WorkDir = (Join-Path $env:USERPROFILE "abdex-upload")
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Step($text) { Write-Host ""; Write-Host "==> $text" -ForegroundColor Cyan }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "Git не найден. Установите его: https://git-scm.com/download/win и запустите скрипт снова." -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $Source -PathType Container)) {
    Write-Host "Папка $Source не найдена. Сначала распакуйте RAR." -ForegroundColor Red
    exit 1
}
$Source = (Resolve-Path $Source).Path

Step "Подготовка репозитория в $WorkDir"
if (Test-Path (Join-Path $WorkDir ".git")) {
    git -C $WorkDir fetch origin
} else {
    git clone $RepoUrl $WorkDir
}
if ($LASTEXITCODE -ne 0) { throw "Не удалось получить репозиторий. Проверьте доступ к GitHub (логин в браузере откроется автоматически)." }
git -C $WorkDir checkout -B $Branch origin/main
if ($LASTEXITCODE -ne 0) { throw "Не удалось создать ветку $Branch" }

if (-not (git -C $WorkDir config user.email)) {
    $email = Read-Host "Ваш e-mail для коммита (как в GitHub)"
    $name = Read-Host "Ваше имя для коммита"
    git -C $WorkDir config user.email $email
    git -C $WorkDir config user.name $name
}

Step "Копирование проекта (без мусора и секретов)"
$dest = Join-Path $WorkDir "legacy\mvp"
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
New-Item -ItemType Directory -Force -Path $dest | Out-Null
$excludeDirs = @(".git", ".venv", "venv", "env", "__pycache__", "node_modules", ".idea", ".vscode", ".pytest_cache",
                 ".mypy_cache", "media", "uploads", "var", "logs", "static_root", "dist", "build")
$excludeFiles = @("*.pyc", ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt", "*.sqlite3", "*.db",
                  "*.rar", "*.zip", "*.7z", "*.log", "*.dump", "*.sql.gz", "*.bak")
robocopy $Source $dest /E /XD $excludeDirs /XF $excludeFiles /NFL /NDL /NJH /NJS /NP | Out-Null
if ($LASTEXITCODE -ge 8) { throw "Ошибка копирования (robocopy код $LASTEXITCODE)" }
$global:LASTEXITCODE = 0

$keep = Join-Path $Source ".env.example"
if (Test-Path $keep) { Copy-Item $keep (Join-Path $dest ".env.example") }

Step "Проверка размеров файлов"
$big = Get-ChildItem $dest -Recurse -File | Where-Object { $_.Length -gt 95MB }
if ($big) {
    Write-Host "Эти файлы больше 95 МБ — GitHub их не примет, они будут исключены:" -ForegroundColor Yellow
    $big | ForEach-Object { Write-Host ("  {0} ({1:N0} МБ)" -f $_.FullName.Substring($dest.Length), ($_.Length / 1MB)) }
    $big | Remove-Item -Force
}
$total = (Get-ChildItem $dest -Recurse -File | Measure-Object -Property Length -Sum).Sum
$count = (Get-ChildItem $dest -Recurse -File | Measure-Object).Count
Write-Host ("Итого к загрузке: {0} файлов, {1:N1} МБ" -f $count, ($total / 1MB))

Step "Поиск возможных секретов в коде"
$patterns = @("password\s*=\s*['""][^'""]{4,}", "SECRET_KEY\s*=\s*['""][^'""]{8,}", "api[_-]?key\s*=\s*['""][^'""]{8,}",
              "postgres(ql)?://[^:\s]+:[^@\s]+@")
$hits = Get-ChildItem $dest -Recurse -File -Include *.py, *.json, *.yml, *.yaml, *.ini, *.cfg, *.toml, *.js |
    Select-String -Pattern $patterns -AllMatches -ErrorAction SilentlyContinue
if ($hits) {
    Write-Host "Похоже, в коде есть пароли или ключи. Проверьте эти строки:" -ForegroundColor Yellow
    $hits | Select-Object -First 20 | ForEach-Object { Write-Host ("  {0}:{1}" -f $_.Path.Substring($dest.Length), $_.LineNumber) }
    $answer = Read-Host "Все равно продолжить загрузку? (да/нет)"
    if ($answer -notmatch "^(да|y|yes|д)$") { Write-Host "Остановлено. Уберите секреты и запустите снова."; exit 1 }
}

Step "Коммит и отправка на GitHub"
git -C $WorkDir add legacy/mvp
git -C $WorkDir commit -m "Import existing AbdEX MVP into legacy/mvp" -m "Imported from local archive; virtualenvs, caches, databases, uploads and secrets excluded."
if ($LASTEXITCODE -ne 0) { throw "Коммит не создан (возможно, нет изменений)" }
git -C $WorkDir push -u origin $Branch
if ($LASTEXITCODE -ne 0) { throw "Не удалось отправить. Повторите команду: git -C `"$WorkDir`" push -u origin $Branch" }

Write-Host ""
Write-Host "Готово! MVP загружен в ветку '$Branch' в папку legacy/mvp." -ForegroundColor Green
Write-Host "Напишите Claude: «MVP загружен в ветку mvp-original» — дальше он сверит его с новой платформой."
