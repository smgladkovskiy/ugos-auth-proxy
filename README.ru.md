# UGOS Auth Proxy

[![Tests](https://github.com/smgladkovskiy/ugos-auth-proxy/actions/workflows/tests.yml/badge.svg)](https://github.com/smgladkovskiy/ugos-auth-proxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

PAM-based аутентификация для интеграции UGOS NAS с [authentik](https://goauthentik.io/) SSO.

> 🇬🇧 [English documentation](README.md)

## Назначение

Этот сервис позволяет authentik аутентифицировать пользователей UGOS NAS без хранения паролей и поддерживает автоматическое создание пользователей.
При каждом входе пароль проверяется через PAM (чтение `/etc/shadow`).

**Ключевые особенности:**
- Пароли **не кэшируются** — каждый вход проверяется в реальном времени
- Изменение пароля в UGOS сразу применяется для SSO
- **Auto-provisioning** — новые пользователи автоматически создаются в authentik при первом входе
- Простая и надёжная PAM-based аутентификация

## Архитектура

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│    Браузер      │────▶│     authentik        │────▶│ ugos-auth-proxy │
│                 │     │  (Expression Policy) │     │  (PAM + passwd) │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
                                                              │
                                                              ▼
                                                      ┌────────────────┐
                                                      │  /etc/shadow   │
                                                      │  /etc/passwd   │
                                                      │  /etc/group    │
                                                      │   (UGOS NAS)   │
                                                      └────────────────┘
```

**Процесс аутентификации:**
1. Пользователь вводит учётные данные в authentik
2. Expression Policy вызывает ugos-auth-proxy `/validate`
3. Если пользователя нет в authentik, policy вызывает `/user-info`
4. Policy создаёт пользователя в authentik с атрибутами из UGOS
5. Пользователь авторизован

## Быстрый старт

### 1. Docker (рекомендуется)

```bash
# Клонировать репозиторий
git clone https://github.com/smgladkovskiy/ugos-auth-proxy.git
cd ugos-auth-proxy

# Запустить контейнер
docker compose up -d

# Проверить статус
curl http://localhost:8180/health
```

### 2. Systemd (альтернатива)

```bash
# Копировать файлы
sudo cp main.py /opt/ugos-auth-proxy/
sudo cp ugos-auth-proxy.service /etc/systemd/system/

# Включить и запустить
sudo systemctl daemon-reload
sudo systemctl enable --now ugos-auth-proxy

# Проверить статус
sudo systemctl status ugos-auth-proxy
```

## API Endpoints

### POST /validate

Проверка учётных данных пользователя через PAM.

**Запрос:**
```json
{
  "username": "ugadmin",
  "password": "secret"
}
```

**Успешный ответ (200):**
```json
{
  "valid": true,
  "username": "ugadmin"
}
```

**Неуспешный ответ (200):**
```json
{
  "valid": false,
  "error": "Invalid credentials"
}
```

### GET /user-info

Получение информации о пользователе из `/etc/passwd` и `/etc/group`. Используется для auto-provisioning пользователей в authentik.

**Query параметры:**
- `username` (обязательный) — имя пользователя UGOS

**Успешный ответ (200):**
```json
{
  "exists": true,
  "username": "ugadmin",
  "uid": 1026,
  "gid": 100,
  "full_name": "Admin User",
  "email": "admin@example.com",
  "home": "/var/services/homes/ugadmin",
  "shell": "/bin/sh",
  "groups": ["administrators", "users", "http"]
}
```

**Пользователь не найден (200):**
```json
{
  "exists": false,
  "error": "User not found"
}
```

### GET /health

Health check для мониторинга и load balancer'ов.

```json
{
  "status": "healthy",
  "service": "ugos-auth-proxy",
  "version": "0.2.0"
}
```

### GET /ready

Readiness probe для Kubernetes.

```json
{
  "status": "ready"
}
```

## Интеграция с authentik

### 1. Создать группы

Создайте следующие группы в authentik (Directory -> Groups):

| Имя группы   | Описание                               |
|--------------|----------------------------------------|
| `UGOS Users` | Все auto-provisioned пользователи UGOS |
| `admins`     | Администраторы (маппинг из UGOS)       |
| `family`     | Члены семьи (маппинг из UGOS)          |

### 2. Создать Authentication Flow

Создайте flow `ugos-authentication` со следующими stages:

| Order | Stage                      | Тип                 | Конфигурация                     |
|-------|----------------------------|---------------------|----------------------------------|
| 10    | ugos-find-user-stage       | IdentificationStage | `pretend_user_exists=True`       |
| 20    | ugos-password-prompt-stage | PromptStage         | Только поле пароля               |
| 25    | ugos-password-deny-stage   | DenyStage           | Policy binding с `negate=True`   |
| 100   | ugos-user-login-stage      | UserLoginStage      | Настройки по умолчанию           |

> **Важно:** Установите `pretend_user_exists=True` на IdentificationStage для включения auto-provisioning новых пользователей.

### 3. Создать Expression Policy

Создайте policy `ugos-password-validation-policy` и привяжите к `ugos-password-deny-stage` с **negate=True**.

Эта policy обрабатывает и валидацию пароля, и auto-provisioning.

📄 **Скопируйте код policy из:** [`authentik-policy.py`](authentik-policy.py)

> **Конфигурация:** Отредактируйте переменные в начале policy:
> - `UGOS_AUTH_PROXY_URL` — адрес вашего ugos-auth-proxy
> - `DEFAULT_EMAIL_DOMAIN` — домен по умолчанию для email пользователей
> - `GROUP_MAP` — маппинг групп UGOS на authentik


### 4. Маппинг групп

Policy автоматически маппит UGOS группы на authentik группы:

| UGOS группа | authentik группа | Описание           |
|-------------|------------------|--------------------|
| `admin`     | `admins`         | Администраторы NAS |
| `family`    | `family`         | Члены семьи        |

Все auto-provisioned пользователи добавляются в группу `UGOS Users`.

### 5. Атрибуты пользователя

Auto-provisioned пользователи будут иметь следующие атрибуты:

```json
{
  "ugos_user": true,
  "ugos_uid": 1005,
  "ugos_gid": 10,
  "ugos_groups": ["admin", "users", "ughomeusers"],
  "ugos_home": "/home/ugadmin",
  "auto_provisioned": true
}
```

### 6. Установить дефолтный flow

В настройках Brand (System -> Brands) установите `ugos-authentication` как дефолтный authentication flow.

### 7. Доступ для локального администратора

Для аварийного входа локальным админом (например, `akadmin`) используйте:
```
https://your-authentik-url/if/flow/default-authentication-flow/
```

## Конфигурация

### Переменные окружения

| Переменная | По умолчанию | Описание     |
|------------|--------------|--------------|
| `PORT`     | `8080`       | Порт сервиса |

### Docker Compose

См. файл [docker-compose.yml](docker-compose.yml).

## Тестирование

```bash
# Успешная аутентификация
curl -X POST http://localhost:8180/validate \
  -H "Content-Type: application/json" \
  -d '{"username":"ugadmin","password":"correct_password"}'

# Неуспешная аутентификация
curl -X POST http://localhost:8180/validate \
  -H "Content-Type: application/json" \
  -d '{"username":"ugadmin","password":"wrong_password"}'

# Получить информацию о пользователе
curl "http://localhost:8180/user-info?username=ugadmin"

# Health check
curl http://localhost:8180/health
```

## Безопасность

⚠️ **Важные замечания:**

1. Контейнер требует доступ к `/etc/shadow`, `/etc/passwd`, `/etc/group` — запускается с монтированием read-only
2. Не выставляйте порт наружу — используйте только внутреннюю Docker сеть
3. Рекомендуется использовать HTTPS между authentik и proxy (через reverse proxy)
4. Endpoint `/user-info` не раскрывает пароли — только публичную информацию из passwd

## Почему PAM, а не UGOS API?

UGOS использует сложную схему аутентификации:

1. **Динамические RSA ключи** — для каждой сессии генерируется новая пара
2. **Шифрование пароля** — пароль шифруется RSA публичным ключом
3. **Многошаговый процесс** — несколько API вызовов для одного логина
4. **Замкнутый круг** — публичный ключ приходит только после логина

PAM-based аутентификация обходит эти сложности и работает напрямую с `/etc/shadow`,
который синхронизирован с паролями UGOS.

## Лицензия

MIT — см. файл [LICENSE](LICENSE).

## Автор

**Sergey Gladkovskiy** — [@smgladkovskiy](https://github.com/smgladkovskiy)
