#!/usr/bin/env python3
"""
Unit tests for UGOS Auth Proxy.

Run with: python -m pytest test_main.py -v
Or: python test_main.py
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from http.server import HTTPServer
from threading import Thread
from typing import Any
from unittest.mock import MagicMock, patch

# Mock crypt module for macOS/Windows compatibility (crypt removed in Python 3.13+)
mock_crypt = MagicMock()
mock_crypt.crypt = lambda password, salt: f"hashed_{password}_{salt}"
sys.modules["crypt"] = mock_crypt

# Import the module under test
import main


class TestGetPort(unittest.TestCase):
    """Tests for get_port function."""

    def test_default_port(self) -> None:
        """Test default port when PORT env is not set."""
        with patch.dict("os.environ", {}, clear=True):
            port = main.get_port()
            self.assertEqual(port, 8080)

    def test_custom_port(self) -> None:
        """Test custom port from environment variable."""
        with patch.dict("os.environ", {"PORT": "9000"}):
            port = main.get_port()
            self.assertEqual(port, 9000)

    def test_invalid_port_not_number(self) -> None:
        """Test invalid port (not a number) exits with error."""
        with patch.dict("os.environ", {"PORT": "invalid"}):
            with self.assertRaises(SystemExit):
                main.get_port()

    def test_invalid_port_out_of_range(self) -> None:
        """Test invalid port (out of range) exits with error."""
        with patch.dict("os.environ", {"PORT": "70000"}):
            with self.assertRaises(SystemExit):
                main.get_port()

    def test_port_zero(self) -> None:
        """Test port 0 is invalid."""
        with patch.dict("os.environ", {"PORT": "0"}):
            with self.assertRaises(SystemExit):
                main.get_port()


class TestAuthenticatePam(unittest.TestCase):
    """Tests for authenticate_pam function."""

    def test_spwd_not_available(self) -> None:
        """Test when spwd module is not available (non-Linux)."""
        with patch.dict(sys.modules, {"spwd": None}):
            # Force reimport to trigger ImportError
            original_spwd = sys.modules.get("spwd")
            sys.modules["spwd"] = None

            # Since authenticate_pam imports spwd inside, we need to mock it differently
            with patch("builtins.__import__", side_effect=ImportError("No module named 'spwd'")):
                result = main.authenticate_pam("testuser", "testpass")
                self.assertFalse(result)

    def test_user_not_found(self) -> None:
        """Test authentication fails when user not in shadow database."""
        mock_spwd = MagicMock()
        mock_spwd.getspnam.side_effect = KeyError("User not found")

        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            result = main.authenticate_pam("nonexistent", "password")
            self.assertFalse(result)

    def test_permission_denied(self) -> None:
        """Test authentication fails when no permission to read shadow."""
        mock_spwd = MagicMock()
        mock_spwd.getspnam.side_effect = PermissionError("Permission denied")

        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            result = main.authenticate_pam("testuser", "password")
            self.assertFalse(result)

    def test_locked_account(self) -> None:
        """Test authentication fails for locked account (starts with !)."""
        mock_entry = MagicMock()
        mock_entry.sp_pwdp = "!$6$locked$hash"

        mock_spwd = MagicMock()
        mock_spwd.getspnam.return_value = mock_entry

        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            result = main.authenticate_pam("lockeduser", "password")
            self.assertFalse(result)

    def test_disabled_account(self) -> None:
        """Test authentication fails for disabled account (starts with *)."""
        mock_entry = MagicMock()
        mock_entry.sp_pwdp = "*"

        mock_spwd = MagicMock()
        mock_spwd.getspnam.return_value = mock_entry

        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            result = main.authenticate_pam("disableduser", "password")
            self.assertFalse(result)

    def test_successful_authentication(self) -> None:
        """Test successful password authentication."""
        # Mock the hash computation to return matching hash
        stored_hash = "$6$testsalt$hashedvalue"

        mock_entry = MagicMock()
        mock_entry.sp_pwdp = stored_hash

        mock_spwd = MagicMock()
        mock_spwd.getspnam.return_value = mock_entry

        # Mock crypt to return same hash for correct password
        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            with patch("main.crypt.crypt", return_value=stored_hash):
                result = main.authenticate_pam("testuser", "testpassword")
                self.assertTrue(result)

    def test_failed_authentication_wrong_password(self) -> None:
        """Test authentication fails with wrong password."""
        stored_hash = "$6$testsalt$correcthash"

        mock_entry = MagicMock()
        mock_entry.sp_pwdp = stored_hash

        mock_spwd = MagicMock()
        mock_spwd.getspnam.return_value = mock_entry

        # Mock crypt to return different hash for wrong password
        with patch.dict(sys.modules, {"spwd": mock_spwd}):
            with patch("main.crypt.crypt", return_value="$6$testsalt$wronghash"):
                result = main.authenticate_pam("testuser", "wrongpassword")
                self.assertFalse(result)


class TestGetUserInfo(unittest.TestCase):
    """Tests for get_user_info function."""

    def test_user_not_found(self) -> None:
        """Test returns None when user not found."""
        with patch("main.pwd.getpwnam", side_effect=KeyError("User not found")):
            result = main.get_user_info("nonexistent")
            self.assertIsNone(result)

    def test_user_found_basic(self) -> None:
        """Test returns user info for existing user."""
        mock_pw_entry = MagicMock()
        mock_pw_entry.pw_uid = 1000
        mock_pw_entry.pw_gid = 100
        mock_pw_entry.pw_gecos = "Test User"
        mock_pw_entry.pw_dir = "/home/testuser"
        mock_pw_entry.pw_shell = "/bin/bash"

        mock_grp_entry = MagicMock()
        mock_grp_entry.gr_name = "users"

        with patch("main.pwd.getpwnam", return_value=mock_pw_entry):
            with patch("main.grp.getgrgid", return_value=mock_grp_entry):
                with patch("main.grp.getgrall", return_value=[]):
                    result = main.get_user_info("testuser")

        self.assertIsNotNone(result)
        self.assertTrue(result["exists"])
        self.assertEqual(result["username"], "testuser")
        self.assertEqual(result["uid"], 1000)
        self.assertEqual(result["gid"], 100)
        self.assertEqual(result["full_name"], "Test User")
        self.assertEqual(result["home"], "/home/testuser")
        self.assertEqual(result["shell"], "/bin/bash")
        self.assertIn("users", result["groups"])

    def test_user_with_email_in_gecos(self) -> None:
        """Test extracts email from GECOS field."""
        mock_pw_entry = MagicMock()
        mock_pw_entry.pw_uid = 1000
        mock_pw_entry.pw_gid = 100
        mock_pw_entry.pw_gecos = "Test User,,,test@example.com"
        mock_pw_entry.pw_dir = "/home/testuser"
        mock_pw_entry.pw_shell = "/bin/bash"

        mock_grp_entry = MagicMock()
        mock_grp_entry.gr_name = "users"

        with patch("main.pwd.getpwnam", return_value=mock_pw_entry):
            with patch("main.grp.getgrgid", return_value=mock_grp_entry):
                with patch("main.grp.getgrall", return_value=[]):
                    result = main.get_user_info("testuser")

        self.assertEqual(result["email"], "test@example.com")

    def test_user_with_multiple_groups(self) -> None:
        """Test returns multiple groups for user."""
        mock_pw_entry = MagicMock()
        mock_pw_entry.pw_uid = 1000
        mock_pw_entry.pw_gid = 100
        mock_pw_entry.pw_gecos = "Test User"
        mock_pw_entry.pw_dir = "/home/testuser"
        mock_pw_entry.pw_shell = "/bin/bash"

        mock_primary_group = MagicMock()
        mock_primary_group.gr_name = "users"

        mock_admin_group = MagicMock()
        mock_admin_group.gr_name = "administrators"
        mock_admin_group.gr_mem = ["testuser", "otheruser"]

        mock_docker_group = MagicMock()
        mock_docker_group.gr_name = "docker"
        mock_docker_group.gr_mem = ["testuser"]

        mock_other_group = MagicMock()
        mock_other_group.gr_name = "other"
        mock_other_group.gr_mem = ["otheruser"]

        with patch("main.pwd.getpwnam", return_value=mock_pw_entry):
            with patch("main.grp.getgrgid", return_value=mock_primary_group):
                with patch("main.grp.getgrall", return_value=[
                    mock_admin_group, mock_docker_group, mock_other_group
                ]):
                    result = main.get_user_info("testuser")

        self.assertIn("users", result["groups"])
        self.assertIn("administrators", result["groups"])
        self.assertIn("docker", result["groups"])
        self.assertNotIn("other", result["groups"])

    def test_user_with_empty_gecos(self) -> None:
        """Test handles empty GECOS field."""
        mock_pw_entry = MagicMock()
        mock_pw_entry.pw_uid = 1000
        mock_pw_entry.pw_gid = 100
        mock_pw_entry.pw_gecos = ""
        mock_pw_entry.pw_dir = "/home/testuser"
        mock_pw_entry.pw_shell = "/bin/bash"

        mock_grp_entry = MagicMock()
        mock_grp_entry.gr_name = "users"

        with patch("main.pwd.getpwnam", return_value=mock_pw_entry):
            with patch("main.grp.getgrgid", return_value=mock_grp_entry):
                with patch("main.grp.getgrall", return_value=[]):
                    result = main.get_user_info("testuser")

        # When GECOS is empty, full_name defaults to username
        self.assertEqual(result["full_name"], "testuser")
        self.assertEqual(result["email"], "")

    def test_primary_group_not_found(self) -> None:
        """Test handles missing primary group gracefully."""
        mock_pw_entry = MagicMock()
        mock_pw_entry.pw_uid = 1000
        mock_pw_entry.pw_gid = 99999  # Non-existent group
        mock_pw_entry.pw_gecos = "Test User"
        mock_pw_entry.pw_dir = "/home/testuser"
        mock_pw_entry.pw_shell = "/bin/bash"

        with patch("main.pwd.getpwnam", return_value=mock_pw_entry):
            with patch("main.grp.getgrgid", side_effect=KeyError("Group not found")):
                with patch("main.grp.getgrall", return_value=[]):
                    result = main.get_user_info("testuser")

        self.assertIsNotNone(result)
        self.assertEqual(result["groups"], [])


class MockHTTPRequest:
    """Mock HTTP request for testing handler."""

    def __init__(
        self,
        method: str = "GET",
        path: str = "/",
        headers: dict[str, str] | None = None,
        body: bytes = b"",
    ) -> None:
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body


class TestAuthHandler(unittest.TestCase):
    """Tests for AuthHandler HTTP endpoints."""

    @classmethod
    def setUpClass(cls) -> None:
        """Start test server in background thread."""
        cls.server = HTTPServer(("127.0.0.1", 0), main.AuthHandler)
        cls.port = cls.server.server_address[1]
        cls.server_thread = Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        """Shutdown test server."""
        cls.server.shutdown()
        cls.server.server_close()

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        content_type: str = "application/json",
    ) -> tuple[int, dict[str, Any]]:
        """Make HTTP request to test server."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {}
        body_bytes = b""

        if body is not None:
            body_bytes = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = content_type
            headers["Content-Length"] = str(len(body_bytes))

        conn.request(method, path, body_bytes, headers)
        response = conn.getresponse()
        status = response.status

        response_body = response.read().decode("utf-8")
        if response_body:
            data = json.loads(response_body)
        else:
            data = {}

        conn.close()
        return status, data

    # ===== Health endpoint tests =====

    def test_health_get(self) -> None:
        """Test GET /health returns healthy status."""
        status, data = self._request("GET", "/health")

        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "ugos-auth-proxy")
        self.assertEqual(data["version"], main.__version__)

    def test_health_head(self) -> None:
        """Test HEAD /health returns 200."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/health")
        response = conn.getresponse()

        self.assertEqual(response.status, 200)
        conn.close()

    # ===== Ready endpoint tests =====

    def test_ready_get(self) -> None:
        """Test GET /ready returns ready status."""
        status, data = self._request("GET", "/ready")

        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ready")

    # ===== User-info endpoint tests =====

    def test_user_info_missing_username(self) -> None:
        """Test GET /user-info without username returns error."""
        status, data = self._request("GET", "/user-info")

        self.assertEqual(status, 400)
        self.assertFalse(data["exists"])
        self.assertIn("required", data["error"].lower())

    def test_user_info_empty_username(self) -> None:
        """Test GET /user-info with empty username returns error."""
        status, data = self._request("GET", "/user-info?username=")

        self.assertEqual(status, 400)
        self.assertFalse(data["exists"])

    def test_user_info_whitespace_username(self) -> None:
        """Test GET /user-info with whitespace-only username returns error."""
        status, data = self._request("GET", "/user-info?username=%20%20")

        self.assertEqual(status, 400)
        self.assertFalse(data["exists"])

    def test_user_info_user_not_found(self) -> None:
        """Test GET /user-info for non-existent user."""
        with patch("main.get_user_info", return_value=None):
            status, data = self._request("GET", "/user-info?username=nonexistent")

        self.assertEqual(status, 200)
        self.assertFalse(data["exists"])
        self.assertIn("not found", data["error"].lower())

    def test_user_info_user_found(self) -> None:
        """Test GET /user-info for existing user."""
        mock_info = {
            "exists": True,
            "username": "testuser",
            "uid": 1000,
            "gid": 100,
            "full_name": "Test User",
            "email": "test@example.com",
            "home": "/home/testuser",
            "shell": "/bin/bash",
            "groups": ["users", "admin"],
        }

        with patch("main.get_user_info", return_value=mock_info):
            status, data = self._request("GET", "/user-info?username=testuser")

        self.assertEqual(status, 200)
        self.assertTrue(data["exists"])
        self.assertEqual(data["username"], "testuser")
        self.assertEqual(data["uid"], 1000)
        self.assertEqual(data["email"], "test@example.com")
        self.assertIn("admin", data["groups"])

    # ===== Validate endpoint tests =====

    def test_validate_wrong_method(self) -> None:
        """Test GET /validate returns 404."""
        status, data = self._request("GET", "/validate")

        self.assertEqual(status, 404)

    def test_validate_wrong_content_type(self) -> None:
        """Test POST /validate with wrong content-type returns error."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(
            "POST", "/validate",
            b"username=test&password=test",
            {"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "28"}
        )
        response = conn.getresponse()
        data = json.loads(response.read().decode("utf-8"))

        self.assertEqual(response.status, 415)
        self.assertFalse(data["valid"])
        conn.close()

    def test_validate_empty_body(self) -> None:
        """Test POST /validate with empty body returns error."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(
            "POST", "/validate",
            b"",
            {"Content-Type": "application/json", "Content-Length": "0"}
        )
        response = conn.getresponse()
        data = json.loads(response.read().decode("utf-8"))

        self.assertEqual(response.status, 400)
        self.assertFalse(data["valid"])
        conn.close()

    def test_validate_invalid_json(self) -> None:
        """Test POST /validate with invalid JSON returns error."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        body = b"not valid json"
        conn.request(
            "POST", "/validate",
            body,
            {"Content-Type": "application/json", "Content-Length": str(len(body))}
        )
        response = conn.getresponse()
        data = json.loads(response.read().decode("utf-8"))

        self.assertEqual(response.status, 400)
        self.assertFalse(data["valid"])
        self.assertIn("JSON", data["error"])
        conn.close()

    def test_validate_missing_username(self) -> None:
        """Test POST /validate without username returns error."""
        status, data = self._request("POST", "/validate", {"password": "test"})

        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])
        self.assertIn("Username", data["error"])

    def test_validate_missing_password(self) -> None:
        """Test POST /validate without password returns error."""
        status, data = self._request("POST", "/validate", {"username": "test"})

        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])
        self.assertIn("Password", data["error"])

    def test_validate_empty_username(self) -> None:
        """Test POST /validate with empty username returns error."""
        status, data = self._request("POST", "/validate", {"username": "  ", "password": "test"})

        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])

    def test_validate_empty_password(self) -> None:
        """Test POST /validate with empty password returns error."""
        status, data = self._request("POST", "/validate", {"username": "test", "password": ""})

        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])

    def test_validate_non_string_credentials(self) -> None:
        """Test POST /validate with non-string credentials returns error."""
        status, data = self._request("POST", "/validate", {"username": 123, "password": ["test"]})

        self.assertEqual(status, 400)
        self.assertFalse(data["valid"])
        self.assertIn("string", data["error"].lower())

    def test_validate_successful(self) -> None:
        """Test POST /validate with correct credentials."""
        with patch("main.authenticate_pam", return_value=True):
            status, data = self._request(
                "POST", "/validate",
                {"username": "testuser", "password": "correctpassword"}
            )

        self.assertEqual(status, 200)
        self.assertTrue(data["valid"])
        self.assertEqual(data["username"], "testuser")

    def test_validate_failed(self) -> None:
        """Test POST /validate with wrong password."""
        with patch("main.authenticate_pam", return_value=False):
            status, data = self._request(
                "POST", "/validate",
                {"username": "testuser", "password": "wrongpassword"}
            )

        self.assertEqual(status, 200)
        self.assertFalse(data["valid"])
        self.assertIn("Invalid", data["error"])

    def test_validate_body_too_large(self) -> None:
        """Test POST /validate with body exceeding max size."""
        import http.client

        # Create a large body (> 4096 bytes)
        large_body = json.dumps({
            "username": "test",
            "password": "x" * 5000
        }).encode("utf-8")

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request(
            "POST", "/validate",
            large_body,
            {"Content-Type": "application/json", "Content-Length": str(len(large_body))}
        )
        response = conn.getresponse()
        data = json.loads(response.read().decode("utf-8"))

        self.assertEqual(response.status, 413)
        self.assertFalse(data["valid"])
        self.assertIn("too large", data["error"].lower())
        conn.close()

    # ===== 404 tests =====

    def test_unknown_path_get(self) -> None:
        """Test GET unknown path returns 404."""
        status, data = self._request("GET", "/unknown")

        self.assertEqual(status, 404)
        self.assertIn("Not found", data["error"])

    def test_unknown_path_post(self) -> None:
        """Test POST unknown path returns 404."""
        status, data = self._request("POST", "/unknown", {"test": "data"})

        self.assertEqual(status, 404)

    def test_head_unknown_path(self) -> None:
        """Test HEAD unknown path returns 404."""
        import http.client

        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        conn.request("HEAD", "/unknown")
        response = conn.getresponse()

        self.assertEqual(response.status, 404)
        conn.close()


class TestVersion(unittest.TestCase):
    """Test version constant."""

    def test_version_format(self) -> None:
        """Test version follows semver format."""
        import re
        semver_pattern = r"^\d+\.\d+\.\d+$"
        self.assertRegex(main.__version__, semver_pattern)

    def test_version_value(self) -> None:
        """Test current version is 0.2.0."""
        self.assertEqual(main.__version__, "0.2.0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
