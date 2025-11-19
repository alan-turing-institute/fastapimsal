# type: ignore
"""Tests for OAuth state-based redirect functionality"""

import base64
import json
import urllib.parse
from unittest.mock import Mock, patch

import msal
from fastapi.testclient import TestClient

from examples.app import app


def test_login_route_state_handling() -> None:
    """Test that login route properly handles redirect parameter and creates state"""
    client = TestClient(app)

    # patch msal.ConfidentialClientApplication to avoid real OAuth calls
    with patch("fastapimsal.auth_routes.build_msal_app") as mock_build_msal_app:
        mock_instance = Mock(spec_set=msal.ConfidentialClientApplication)

        # mock_instance.initiate_auth_code_flow.return_value = {
        #     "auth_uri": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=fake_client_id",
        #     "flow": "fake_flow_data",
        # }
        mock_build_msal_app.return_value = mock_instance

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

    # Extract the redirect parameter
    parsed = urllib.parse.urlparse(location)
    query_params = urllib.parse.parse_qs(parsed.query)
    redirect_param = query_params["redirect"][0]

    # Should contain the original URL
    assert redirect_param.endswith("/docs"), f"Redirect param was {redirect_param}"


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
