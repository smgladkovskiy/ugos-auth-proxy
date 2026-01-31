# UGOS Auth Proxy

[![Tests](https://github.com/smgladkovskiy/ugos-auth-proxy/actions/workflows/tests.yml/badge.svg)](https://github.com/smgladkovskiy/ugos-auth-proxy/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

PAM-based authentication proxy for integrating UGOS NAS with [authentik](https://goauthentik.io/) SSO.

> 🇷🇺 [Документация на русском](README.ru.md)

## Overview

This service enables authentik to authenticate UGOS NAS users without storing passwords and supports automatic user provisioning. Each login attempt is validated in real-time via PAM (reading `/etc/shadow`).

**Key Features:**

- 🔒 **No password caching** — every login is validated in real-time
- ⚡ **Instant sync** — password changes in UGOS apply immediately to SSO
- 👤 **Auto-provisioning** — new users are automatically created in authentik on first login
- 🛡️ **Simple & reliable** — PAM-based authentication

## Architecture

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│    Browser      │────▶│     authentik        │────▶│ ugos-auth-proxy │
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

**Flow:**
1. User enters credentials in authentik
2. authentik's Expression Policy calls ugos-auth-proxy `/validate`
3. If user doesn't exist in authentik, policy calls `/user-info` to get user details
4. Policy creates user in authentik with UGOS attributes
5. User is logged in

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

### GET /user-info

Retrieves user information from `/etc/passwd` and `/etc/group`. Used for auto-provisioning users in authentik.

**Query Parameters:**
- `username` (required) — UGOS username

**Success Response (200):**

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

**User Not Found Response (200):**

```json
{
  "exists": false,
  "error": "User not found"
}
```

### GET /health

Health check endpoint for monitoring and load balancers.

```json
{
  "status": "healthy",
  "service": "ugos-auth-proxy",
  "version": "0.2.0"
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

### 1. Create Groups

Create the following groups in authentik (Directory -> Groups):

| Group Name   | Description                        |
|--------------|------------------------------------|
| `UGOS Users` | All auto-provisioned UGOS users    |
| `admins`     | Administrators (mapped from UGOS)  |
| `family`     | Family members (mapped from UGOS)  |

### 2. Create Authentication Flow

Create a flow named `ugos-authentication` with the following stages:

| Order | Stage                      | Type                | Configuration                     |
|-------|----------------------------|---------------------|-----------------------------------|
| 10    | ugos-find-user-stage       | IdentificationStage | `pretend_user_exists=True`        |
| 20    | ugos-password-prompt-stage | PromptStage         | Password field only               |
| 25    | ugos-password-deny-stage   | DenyStage           | Policy binding with `negate=True` |
| 100   | ugos-user-login-stage      | UserLoginStage      | Default settings                  |

> **Important:** Set `pretend_user_exists=True` on IdentificationStage to enable auto-provisioning for new users.

### 3. Create Expression Policy

Create a policy named `ugos-password-validation-policy` and bind it to `ugos-password-deny-stage` with **negate=True**.

This policy handles both password validation and auto-provisioning.

📄 **Copy the policy code from:** [`authentik-policy.py`](authentik-policy.py)

> **Configuration:** Edit the variables at the top of the policy:
> - `UGOS_AUTH_PROXY_URL` — your ugos-auth-proxy address
> - `DEFAULT_EMAIL_DOMAIN` — default email domain for users
> - `GROUP_MAP` — UGOS to authentik group mapping


### 4. Group Mapping

The policy automatically maps UGOS groups to authentik groups:

| UGOS Group | authentik Group | Description        |
|------------|-----------------|--------------------|
| `admin`    | `admins`        | NAS administrators |
| `family`   | `family`        | Family members     |

All auto-provisioned users are added to `UGOS Users` group.

### 5. User Attributes

Auto-provisioned users will have these attributes:

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

### 6. Set Default Flow

In Brand settings (System -> Brands), set `ugos-authentication` as the default authentication flow.

### 7. Local Admin Access

For emergency access with local admin (e.g., `akadmin`), use:
```
https://your-authentik-url/if/flow/default-authentication-flow/
```

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

# Get user info
curl "http://localhost:8180/user-info?username=ugadmin"

# Health check
curl http://localhost:8180/health
```

## Security Considerations

⚠️ **Important:**

1. The container requires access to `/etc/shadow`, `/etc/passwd`, `/etc/group` — mounted as read-only
2. **Do not expose** the port externally — use internal Docker network only
3. Consider using HTTPS between authentik and proxy (via reverse proxy)
4. The `/user-info` endpoint only exposes public user data (no passwords)

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
