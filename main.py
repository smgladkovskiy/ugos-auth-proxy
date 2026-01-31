#!/usr/bin/env python3
"""
UGOS Auth Proxy - PAM-based authentication proxy for authentik SSO.

This service validates user credentials against UGOS system via PAM/shadow
and provides user information for auto-provisioning in authentik.

Used by authentik as a custom authentication backend through Expression Policy.

The proxy requires root access to read /etc/shadow for PAM authentication.

Endpoints:
  - POST /validate  - Validate user credentials via PAM
  - GET  /user-info - Get user information from /etc/passwd and /etc/group
  - GET  /health    - Health check
  - GET  /ready     - Readiness probe

Deployment options:
  - Docker container with /etc/shadow, /etc/passwd, /etc/group mounted (recommended)
  - Systemd service on the host

Default port: 8080 (configurable via PORT environment variable)

Author: Sergey Gladkovskiy <smgladkovskiy@gmail.com>
License: MIT
"""

from __future__ import annotations

import crypt
import grp
import json
import logging
import os
import pwd
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

__version__ = "0.2.0"
__author__ = "Sergey Gladkovskiy <smgladkovskiy@gmail.com>"

# Configuration
DEFAULT_PORT = 8080
DEFAULT_HOST = "0.0.0.0"

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ugos-auth-proxy")


def get_port() -> int:
    """Get port from environment variable with validation."""
    port_str = os.getenv("PORT", str(DEFAULT_PORT))
    try:
        port = int(port_str)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535, got {port}")
        return port
    except ValueError as e:
        logger.error("Invalid PORT value '%s': %s", port_str, e)
        sys.exit(1)


def authenticate_pam(username: str, password: str) -> bool:
    """
    Validate password against /etc/shadow using PAM.

    Args:
        username: The username to authenticate.
        password: The password to validate.

    Returns:
        True if authentication successful, False otherwise.
    """
    try:
        import spwd  # noqa: PLC0415 - Import here as it's Linux-specific
    except ImportError:
        logger.error("spwd module not available - not running on Linux?")
        return False

    try:
        shadow_entry = spwd.getspnam(username)
        stored_hash = shadow_entry.sp_pwdp

        # Handle locked/disabled accounts
        if stored_hash.startswith(("!", "*")):
            logger.warning("User '%s' account is locked or disabled", username)
            return False

        # Validate password
        computed_hash = crypt.crypt(password, stored_hash)
        return computed_hash == stored_hash

    except KeyError:
        logger.warning("User '%s' not found in shadow database", username)
        return False
    except PermissionError:
        logger.error("Permission denied reading /etc/shadow - root access required")
        return False
    except Exception as e:
        logger.exception("Unexpected error during PAM authentication: %s", e)
        return False


def get_user_info(username: str) -> dict[str, Any] | None:
    """
    Get user information from /etc/passwd and /etc/group.

    Args:
        username: The username to look up.

    Returns:
        Dictionary with user info or None if user not found.
    """
    try:
        pw_entry = pwd.getpwnam(username)
    except KeyError:
        logger.warning("User '%s' not found in passwd database", username)
        return None

    # Get user's groups
    user_groups = []
    try:
        # Primary group
        primary_group = grp.getgrgid(pw_entry.pw_gid)
        user_groups.append(primary_group.gr_name)
    except KeyError:
        pass

    # Secondary groups
    try:
        all_groups = grp.getgrall()
        for group in all_groups:
            if username in group.gr_mem and group.gr_name not in user_groups:
                user_groups.append(group.gr_name)
    except Exception as e:
        logger.warning("Error reading groups for user '%s': %s", username, e)

    # Parse GECOS field for full name and email
    # GECOS format: Full Name,Room,Work Phone,Home Phone,Other
    # Some systems use: Full Name,,,email
    gecos = pw_entry.pw_gecos
    full_name = username
    email = ""

    if gecos:
        gecos_parts = gecos.split(",")
        if gecos_parts[0]:
            full_name = gecos_parts[0]
        # Check for email in GECOS (some systems store it there)
        for part in gecos_parts[1:]:
            if "@" in part:
                email = part.strip()
                break

    return {
        "exists": True,
        "username": username,
        "uid": pw_entry.pw_uid,
        "gid": pw_entry.pw_gid,
        "full_name": full_name,
        "email": email,
        "home": pw_entry.pw_dir,
        "shell": pw_entry.pw_shell,
        "groups": user_groups,
    }


class AuthHandler(BaseHTTPRequestHandler):
    """HTTP request handler for authentication endpoints."""

    # Suppress default server header for security
    server_version = "ugos-auth-proxy"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """Override to use our logger instead of stderr."""
        logger.info("%s - %s", self.address_string(), format % args)

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        """Override to use our logger for errors."""
        logger.error("%s - %s", self.address_string(), format % args)

    def _send_json(self, data: dict[str, Any], status: int = 200) -> None:
        """
        Send a JSON response.

        Args:
            data: Dictionary to serialize as JSON.
            status: HTTP status code.
        """
        response_body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(response_body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(response_body)

    def do_HEAD(self) -> None:  # noqa: N802
        """Handle HEAD requests for health checks."""
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET requests."""
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/health":
            self._send_json(
                {
                    "status": "healthy",
                    "service": "ugos-auth-proxy",
                    "version": __version__,
                }
            )
        elif path == "/ready":
            self._send_json({"status": "ready"})
        elif path == "/user-info":
            self._handle_user_info(parsed_url.query)
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_user_info(self, query_string: str) -> None:
        """
        Handle GET /user-info request.

        Args:
            query_string: URL query string.
        """
        # Parse query parameters
        params = parse_qs(query_string)
        username_list = params.get("username", [])

        if not username_list or not username_list[0]:
            self._send_json(
                {"exists": False, "error": "Username parameter is required"},
                400,
            )
            return

        username = username_list[0].strip()

        if not username:
            self._send_json(
                {"exists": False, "error": "Username cannot be empty"},
                400,
            )
            return

        logger.info("Getting user info for '%s'", username)

        user_info = get_user_info(username)

        if user_info:
            logger.info("User info retrieved for '%s'", username)
            self._send_json(user_info)
        else:
            logger.info("User '%s' not found", username)
            self._send_json({"exists": False, "error": "User not found"})

    def do_POST(self) -> None:  # noqa: N802
        """Handle POST requests for credential validation."""
        if self.path != "/validate":
            self._send_json({"error": "Not found"}, 404)
            return

        # Validate Content-Type
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/json"):
            self._send_json(
                {"valid": False, "error": "Content-Type must be application/json"},
                415,
            )
            return

        # Read and parse request body
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length == 0:
                self._send_json(
                    {"valid": False, "error": "Request body is required"},
                    400,
                )
                return

            # Limit request size to prevent DoS
            max_body_size = 4096
            if content_length > max_body_size:
                self._send_json(
                    {"valid": False, "error": "Request body too large"},
                    413,
                )
                return

            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body)

        except json.JSONDecodeError as e:
            self._send_json(
                {"valid": False, "error": f"Invalid JSON: {e}"},
                400,
            )
            return
        except UnicodeDecodeError:
            self._send_json(
                {"valid": False, "error": "Invalid UTF-8 encoding"},
                400,
            )
            return

        # Extract and validate credentials
        username = data.get("username", "")
        password = data.get("password", "")

        if not isinstance(username, str) or not isinstance(password, str):
            self._send_json(
                {"valid": False, "error": "Username and password must be strings"},
                400,
            )
            return

        username = username.strip()
        if not username:
            self._send_json(
                {"valid": False, "error": "Username is required"},
                400,
            )
            return

        if not password:
            self._send_json(
                {"valid": False, "error": "Password is required"},
                400,
            )
            return

        # Authenticate
        logger.info("Validating credentials for user '%s'", username)

        if authenticate_pam(username, password):
            logger.info("User '%s' authenticated successfully", username)
            self._send_json({"valid": True, "username": username})
        else:
            logger.info("Authentication failed for user '%s'", username)
            self._send_json({"valid": False, "error": "Invalid credentials"})


def main() -> None:
    """Main entry point for the authentication proxy server."""
    port = get_port()
    server_address = (DEFAULT_HOST, port)

    try:
        server = HTTPServer(server_address, AuthHandler)
    except OSError as e:
        logger.error("Failed to start server on port %d: %s", port, e)
        sys.exit(1)

    logger.info(
        "UGOS Auth Proxy v%s starting on %s:%d",
        __version__,
        DEFAULT_HOST,
        port,
    )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    finally:
        server.shutdown()
        server.server_close()
        logger.info("Server stopped")


if __name__ == "__main__":
    main()
