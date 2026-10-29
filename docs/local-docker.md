# Запуск на своём компьютере в Docker (Kali / Debian / Ubuntu)

Для проверки сайта у себя: приложение, фоновый обработчик и PostgreSQL. SMS и письма никуда не уходят —
коды видны на странице `http://localhost:8000/dev/outbox`. Боевой сервер поднимается иначе: `docs/launch.md`.

```bash
# 1. Docker (один раз)
sudo apt update
sudo apt install -y docker.io docker-compose git
sudo systemctl enable --now docker
sudo usermod -aG docker $USER        # затем выйдите из системы и войдите снова (или пишите sudo перед docker)

# 2. Код
git clone https://github.com/kali963/Abdex.git
cd Abdex

# 3. Настройки
cp .env.example .env
python3 -c "import secrets;print('SECRET_KEY='+secrets.token_urlsafe(48))"   # строку — в .env
nano .env        # SECRET_KEY, INITIAL_ADMIN_* (админ) и INITIAL_USER_* (пользователь), пароли от 12 символов

# 4. Запуск (первый раз — 3–5 минут на сборку)
docker compose up -d --build        # если команда не найдена: docker-compose up -d --build
docker compose ps                   # app — healthy, db — healthy, worker — Up
```

Сайт: <http://localhost:8000>, админка: <http://localhost:8000/admin> (вход телефоном или e-mail
администратора из `.env`).

| Что | Команда |
|---|---|
| журнал приложения | `docker compose logs -f app` |
| остановить | `docker compose down` |
| обновить код и перезапустить | `git pull && docker compose up -d --build` |
| другой порт (8000 занят) | в `.env`: `APP_PORT=8080` и `PUBLIC_BASE_URL=http://localhost:8080`, затем `docker compose up -d` |
| начать с чистой базы | `docker compose down -v && docker compose up -d` |

Если аккаунт администратора не появился — в `docker compose logs app` будет причина (короткий пароль, неверный
БИН и т. п.); исправьте `.env`, затем `docker compose down -v && docker compose up -d`.

## Открыть сайт с телефона или другого компьютера в той же Wi-Fi сети

```bash
ip -4 addr show | grep inet        # адрес компьютера в сети, например 192.168.1.50 (строка с wlan0 или eth0)
```

1. В `.env`: `PUBLIC_BASE_URL=http://192.168.1.50:9999` (ваш адрес и порт), затем `docker compose up -d`.
2. На телефоне (в той же Wi-Fi сети) откройте `http://192.168.1.50:9999`.

Если не открывается:
* `docker compose ps` — в колонке PORTS должно быть `0.0.0.0:9999->8000`;
* включён брандмауэр — `ufw allow 9999/tcp` (или `iptables -I INPUT -p tcp --dport 9999 -j ACCEPT`);
* Kali в виртуальной машине (VirtualBox, VMware) — в настройках сети машины выберите «Сетевой мост» (Bridged)
  вместо NAT, перезапустите сеть и снова посмотрите адрес;
* роутер с «изоляцией клиентов» (гостевая сеть) не пускает устройства друг к другу — подключитесь к основной сети.

Адрес меняется при переподключении к Wi-Fi — тогда обновите `PUBLIC_BASE_URL`.

## Telegram-бот

1. В Telegram откройте @BotFather → `/newbot` → придумайте имя и логин бота (оканчивается на `bot`).
2. В `.env`: `TELEGRAM_BOT_TOKEN=<токен от BotFather>` и `TELEGRAM_BOT_USERNAME=<логин бота без @>`.
3. `docker compose up -d`. На сайте: «Профиль → Уведомления → Получить код привязки → Открыть в Telegram» →
   в боте «Старт». Фоновый обработчик сам забирает сообщения бота, публичный адрес не нужен.

## Вход по ЭЦП (NCALayer) и через eGov mobile

Docker-сборка уже запускает **NCANode** — сервис проверки подписей НУЦ РК (цепочка сертификата, срок, отзыв
через OCSP). Ему нужен интернет до `*.pki.gov.kz`; после запуска он минуту скачивает списки отзыва. eGov mobile
работает через **SIGEX** — публичный адрес компьютера не нужен, телефон и сайт могут быть в разных сетях.

1. Админка → **«Функции»** (флаги) → включите **«Вход через ЭЦП НУЦ РК»** и **«Вход через eGov mobile»**
   (для подписания документов сделки — ещё «Подписание ЭЦП НУЦ РК» и «Подписание документов … в eGov mobile»).
2. Войдите по паролю → **Профиль → Безопасность → «Вход по ЭЦП»** и привяжите ЭЦП один раз:
   * **💻 через NCALayer** — на этом компьютере должен быть запущен NCALayer (pki.gov.kz → «NCALayer» для
     Linux/Windows/macOS), выберите ключ **AUTH_RSA…** из файла `.p12` и введите его пароль;
   * **📱 через eGov mobile** — отсканируйте QR в приложении eGov mobile и подпишите (на самом телефоне —
     кнопка «Открыть в eGov mobile»).
3. Выйдите. На странице входа появятся кнопки **«Войти с ЭЦП»** и **«Войти через eGov mobile»**.

ИИН берётся из проверенного сертификата; одну ЭЦП можно привязать только к одному аккаунту. Если подпись
отклонена, причина — в журнале безопасности (админка → «Аудит», событие `auth.eds_rejected`).
