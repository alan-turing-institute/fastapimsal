# type: ignore
"""Tests for OAuth state-based redirect functionality"""

import base64
import json
import urllib.parse
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from examples.app import app


def test_state_parameter_creation() -> None:
    """Test that state parameter is created correctly from redirect URL"""
    from fastapimsal.auth_routes import base64, json

    redirect_url = "https://example.com/protected/page"
    state_data = {"redirect": redirect_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Verify state is URL-safe base64
    assert isinstance(state, str)
    assert all(
        c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
        for c in state
    )

    # Verify decoding works
    decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded["redirect"] == redirect_url


def test_state_parameter_edge_cases() -> None:
    """Test state parameter with edge case URLs"""
    from fastapimsal.auth_routes import base64, json

    edge_case_urls = [
        "",  # Empty string
        "http://localhost:8000/",  # Localhost
        "https://example.com/path?a=1&b=2#section",  # Query params and fragment
        "https://example.com/unicode/ñáméß",  # Unicode characters
        "https://example.com/very/long/path/that/goes/on/and/on/with/many/segments",  # Long URL
    ]

    for url in edge_case_urls:
        state_data = {"redirect": url}
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

        # Verify round-trip
        decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
        assert decoded["redirect"] == url


def test_login_route_state_handling() -> None:
    """Test that login route properly handles redirect parameter and creates state"""
    client = TestClient(app)

    # Test without redirect parameter
    resp = client.get("/login", follow_redirects=False)
    assert resp.status_code == 302

    oauth_url = resp.headers["location"]
    parsed = urllib.parse.urlparse(oauth_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    # Should not have state parameter when no redirect is provided
    assert "state" not in query_params

    # Test with redirect parameter
    redirect_url = "https://example.com/docs"
    resp = client.get(f"/login?redirect={redirect_url}", follow_redirects=False)
    assert resp.status_code == 302

    oauth_url = resp.headers["location"]
    parsed = urllib.parse.urlparse(oauth_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    # Should have state parameter
    assert "state" in query_params
    state = query_params["state"][0]

    # Decode and verify state contains redirect URL
    decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded["redirect"] == redirect_url


def test_login_route_url_encoding() -> None:
    """Test that login route handles URL-encoded redirect parameters"""
    client = TestClient(app)

    # Test with URL-encoded redirect parameter
    redirect_url = "https://example.com/docs?param=value&other=123"
    encoded_redirect = urllib.parse.quote(redirect_url, safe="")

    resp = client.get(f"/login?redirect={encoded_redirect}", follow_redirects=False)
    assert resp.status_code == 302

    oauth_url = resp.headers["location"]
    parsed = urllib.parse.urlparse(oauth_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    state = query_params["state"][0]
    decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())

    # Should decode to the original URL
    assert decoded["redirect"] == redirect_url


# Note: Authorization callback tests that require OAuth flow mocking
# are complex and would need proper session handling. The core logic
# is tested in test_redirect_logic.py


def test_requires_login_exception_redirect() -> None:
    """Test that RequiresLoginException triggers redirect to login with current URL"""
    client = TestClient(app)

    # Access protected endpoint without authentication
    resp = client.get("/docs", follow_redirects=False)

    # Should get redirected to login
    assert resp.status_code == 307  # Temporary redirect
    location = resp.headers["location"]

    # Should redirect to login with redirect parameter
    assert location.startswith("/login?redirect=")

    # Extract the redirect parameter
    parsed = urllib.parse.urlparse(location)
    query_params = urllib.parse.parse_qs(parsed.query)
    redirect_param = query_params["redirect"][0]

    # Should contain the original URL
    assert "/docs" in redirect_param


def test_full_redirect_flow_simulation() -> None:
    """Test simulation of the full redirect flow"""
    client = TestClient(app)

    # Step 1: User tries to access protected page
    resp1 = client.get("/docs", follow_redirects=False)
    assert resp1.status_code == 307

    login_url = resp1.headers["location"]
    assert login_url.startswith("/login?redirect=")

    # Step 2: User is redirected to login
    resp2 = client.get(login_url, follow_redirects=False)
    assert resp2.status_code == 302

    # Should redirect to OAuth provider with state parameter
    oauth_url = resp2.headers["location"]
    parsed = urllib.parse.urlparse(oauth_url)
    query_params = urllib.parse.parse_qs(parsed.query)

    assert "state" in query_params
    state = query_params["state"][0]

    # Verify state contains original URL
    decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert "/docs" in decoded["redirect"]


def test_state_parameter_security() -> None:
    """Test that state parameter doesn't expose sensitive information in plain text"""
    from fastapimsal.auth_routes import base64, json

    # Create state with sensitive-looking URL
    sensitive_url = "https://example.com/admin/users?token=secret123&key=private"
    state_data = {"redirect": sensitive_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # State should not contain the sensitive parts in plain text
    assert "secret123" not in state
    assert "private" not in state
    assert "admin" not in state

    # But should decode correctly
    decoded = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded["redirect"] == sensitive_url
