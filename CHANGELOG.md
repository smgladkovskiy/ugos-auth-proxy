# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-31

### Added

- **GET /user-info endpoint** - Retrieves user information from `/etc/passwd` and `/etc/group` for auto-provisioning users in authentik
  - Returns: username, uid, gid, full_name, email, home, shell, groups
  - Email is extracted from GECOS field if available
- Support for `/etc/group` to retrieve user's group memberships
- Auto-provisioning documentation for authentik integration
- **Unit tests** - Comprehensive test suite with 43 tests covering all endpoints and functions
  - Tests for `/validate`, `/user-info`, `/health`, `/ready` endpoints
  - Tests for `authenticate_pam` and `get_user_info` functions
  - Mock-based tests compatible with macOS/Windows (no Linux-specific dependencies)
- **GitHub Actions** - CI workflow for running tests on Python 3.10, 3.11, 3.12 with ruff linting

### Changed

- Updated architecture to support user provisioning flow
- Docker compose now mounts `/etc/group` (read-only) in addition to `/etc/shadow` and `/etc/passwd`
- Updated documentation with complete authentik auto-provisioning setup guide including:
  - Expression Policy code for auto-provisioning
  - Group mapping configuration (UGOS -> authentik)
  - IdentificationStage configuration with `pretend_user_exists=True`
  - User attributes structure

## [0.1.0] - 2026-01-15

### Added

- Initial release
- **POST /validate endpoint** - Validates user credentials via PAM/shadow
- **GET /health endpoint** - Health check for monitoring
- **GET /ready endpoint** - Readiness probe for Kubernetes
- Docker support with docker-compose
- Systemd service file
- Comprehensive documentation (English and Russian)
