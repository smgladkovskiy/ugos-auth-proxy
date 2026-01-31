# UGOS Auth Proxy

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

PAM-based authentication proxy for integrating UGOS NAS with [authentik](https://goauthentik.io/) SSO.

> 🇷🇺 [Документация на русском](README.ru.md)

## Overview

This service enables authentik to authenticate UGOS NAS users without storing passwords. Each login attempt is validated
in real-time via PAM (reading `/etc/shadow`).

**Key Features:**

- 🔒 **No password caching** — every login is validated in real-time
- ⚡ **Instant sync** — password changes in UGOS apply immediately to SSO
- 🛡️ **Simple & reliable** — PAM-based authentication

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│    Browser      │────▶│     authentik        │────▶│ ugos-auth-proxy │
│                 │     │  (Expression Policy) │     │   (PAM/shadow)  │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
                                                            │
                                                            ▼
                                                     ┌────────────────┐
                                                     │  /etc/shadow   │
                                                     │   (UGOS NAS)   │
                                                     └────────────────┘
```

## Quick Start

### Docker (Recommended)

```bash
# Clone the repository
git clone https://github.com/smgladkovskiy/ugos-auth-proxy.git
cd ugos-auth-proxy

# Start the container
docker compose up -d

# Verify it's running
curl http://localhost:8180/health
```

### Systemd (Alternative)

```bash
# Copy files
sudo mkdir -p /opt/ugos-auth-proxy
sudo cp main.py /opt/ugos-auth-proxy/
sudo cp ugos-auth-proxy.service /etc/systemd/system/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable --now ugos-auth-proxy

# Check status
sudo systemctl status ugos-auth-proxy
```

## API Reference

### POST /validate

Validates user credentials via PAM.

**Request:**

```json
{
  "username": "ugadmin",
  "password": "secret"
}
```

**Success Response (200):**

```json
{
  "valid": true,
  "username": "ugadmin"
}
```

**Failure Response (200):**

```json
{
  "valid": false,
  "error": "Invalid credentials"
}
```

### GET /health

Health check endpoint for monitoring and load balancers.

```json
{
  "status": "healthy",
  "service": "ugos-auth-proxy"
}
```

### GET /ready

Readiness probe for Kubernetes.

```json
{
  "status": "ready"
}
```

## authentik Integration

### 1. Create Authentication Flow

Create a flow named `ugos-authentication` with the following stages:

| Order | Stage                      | Type                |
|-------|----------------------------|---------------------|
| 10    | ugos-find-user-stage       | IdentificationStage |
| 20    | ugos-password-prompt-stage | PromptStage         |
| 25    | ugos-password-deny-stage   | DenyStage           |
| 100   | ugos-user-login-stage      | UserLoginStage      |

### 2. Create Expression Policy

Create a policy named `ugos-password-validation-policy` and bind it to `ugos-password-deny-stage` with **negate=True**:

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

# Check ugos_user attribute
is_ugos_user = user.attributes.get("ugos_user", False)
if not is_ugos_user:
    # Local user - verify via authentik
    if user.check_password(password):
        return True
    else:
        ak_message("Invalid password")
        return False

# UGOS user - verify via UGOS Auth Proxy
try:
    response = requests.post(
        "http://192.168.0.40:8180/validate",  # Change to your address
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

### 3. Configure Users

UGOS users must have the following attribute in authentik:

```json
{
  "ugos_user": true
}
```

### 4. Set Default Flow

In Brand settings, set `ugos-authentication` as the default authentication flow.

## Configuration

### Environment Variables

| Variable | Default | Description  |
|----------|---------|--------------|
| `PORT`   | `8080`  | Service port |

## Testing

```bash
# Successful authentication
curl -X POST http://localhost:8180/validate \
  -H "Content-Type: application/json" \
  -d '{"username":"ugadmin","password":"correct_password"}'

# Failed authentication
curl -X POST http://localhost:8180/validate \
  -H "Content-Type: application/json" \
  -d '{"username":"ugadmin","password":"wrong_password"}'

# Health check
curl http://localhost:8180/health
```

## Security Considerations

⚠️ **Important:**

1. The container requires access to `/etc/shadow` — mounted as read-only
2. **Do not expose** the port externally — use internal Docker network only
3. Consider using HTTPS between authentik and proxy (via reverse proxy)

## Why PAM Instead of UGOS API?

UGOS uses a complex authentication scheme:

1. **Dynamic RSA keys** — new key pair generated for each session
2. **Password encryption** — password is encrypted with RSA public key
3. **Multi-step process** — multiple API calls for a single login
4. **Circular dependency** — public key is only available after login

PAM-based authentication bypasses these complexities and works directly with `/etc/shadow`, which stays in sync with
UGOS passwords.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Sergey Gladkovskiy** - [@smgladkovskiy](https://github.com/smgladkovskiy)

---

If you find this project useful, please consider giving it a ⭐!
