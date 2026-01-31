# UGOS Auth Proxy

PAM-based аутентификация для интеграции UGOS NAS с [authentik](https://goauthentik.io/) SSO.

> 🇬🇧 [English documentation](README.md)

## Назначение

Этот сервис позволяет authentik аутентифицировать пользователей UGOS NAS без хранения паролей.
При каждом входе пароль проверяется через PAM (чтение `/etc/shadow`).

**Ключевые особенности:**
- Пароли **не кэшируются** — каждый вход проверяется в реальном времени
- Изменение пароля в UGOS сразу применяется для SSO
- Простая и надёжная PAM-based аутентификация

## Архитектура

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│    Браузер      │────▶│     authentik        │────▶│ ugos-auth-proxy │
│                 │     │  (Expression Policy) │     │   (PAM/shadow)  │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
                                                            │
                                                            ▼
                                                    ┌────────────────┐
                                                    │  /etc/shadow   │
                                                    │   (UGOS NAS)   │
                                                    └────────────────┘
```

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

### GET /health

Health check для мониторинга и load balancer'ов.

```json
{
  "status": "healthy",
  "service": "ugos-auth-proxy"
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

### 1. Создать Authentication Flow

Создайте flow `ugos-authentication` со следующими stages:

| Order | Stage                      | Тип                 |
|-------|----------------------------|---------------------|
| 10    | ugos-find-user-stage       | IdentificationStage |
| 20    | ugos-password-prompt-stage | PromptStage         |
| 25    | ugos-password-deny-stage   | DenyStage           |
| 100   | ugos-user-login-stage      | UserLoginStage      |

### 2. Создать Expression Policy

Создайте policy `ugos-password-validation-policy` и привяжите к `ugos-password-deny-stage` с **negate=True**:

```python
import requests

password = request.context.get("prompt_data", {}).get("password")
if not password:
    ak_message("Password is required")
    return False

user = request.context.get("pending_user")
if not user:
    ak_message("User not found")
    return False

# Проверить атрибут ugos_user
is_ugos_user = user.attributes.get("ugos_user", False)
if not is_ugos_user:
    # Локальный пользователь - проверка через authentik
    if user.check_password(password):
        return True
    else:
        ak_message("Invalid password")
        return False

# UGOS пользователь - проверка через UGOS Auth Proxy
try:
    response = requests.post(
        "http://192.168.0.40:8180/validate",  # Изменить на свой адрес
        json={"username": user.username, "password": password},
        timeout=5
    )
    result = response.json()
    
    if result.get("valid", False):
        return True
    else:
        ak_message("Invalid password")
        return False
except Exception as e:
    ak_message(f"Authentication service error: {str(e)}")
    return False
```

### 3. Настроить пользователей

Пользователи UGOS должны иметь атрибут в authentik:

```json
{
  "ugos_user": true
}
```

### 4. Установить дефолтный flow

В настройках Brand установите `ugos-authentication` как дефолтный authentication flow.

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

# Health check
curl http://localhost:8180/health
```

## Безопасность

⚠️ **Важные замечания:**

1. Контейнер требует доступ к `/etc/shadow` — запускается с монтированием read-only
2. Не выставляйте порт наружу — используйте только внутреннюю Docker сеть
3. Рекомендуется использовать HTTPS между authentik и proxy (через reverse proxy)

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
