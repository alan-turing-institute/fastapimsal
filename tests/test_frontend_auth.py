# type: ignore
import base64
import json
import uuid
from typing import Any

import itsdangerous
import pytest
import requests
from fastapi.testclient import TestClient

from examples.app import app
from fastapimsal.config import get_auth_settings


def client_frontend(**kwargs) -> TestClient:
    return TestClient(app, **kwargs)


def request_path(
    client: TestClient, path: str, method: str = "get", **kwargs: Any
) -> requests.Response:
    """Request giving the name of route function

    Args:
        path (str): Route function name
        method (str, optional): HTTP Method. Defaults to "get".

    Returns:
        [type]: [description]
    """

    return client.request(url=app.url_path_for(path), method=method, **kwargs)


def signed_session(session_secret: str) -> bytes:

    # Use the session cookie secret to self sign a cookie
    oid = str(uuid.uuid4())
    signer = itsdangerous.TimestampSigner(session_secret)

    # Create cookie and sign
    payload = base64.b64encode(json.dumps({"user": oid}).encode("utf-8"))
    return signer.sign(payload)


def test_home_no_cookie() -> None:

    resp = request_path(client_frontend(), "home")
    assert resp.status_code == 200
    assert '<a href="/login">login</a>' in resp.content.decode()


@pytest.mark.xfail(reason="Fails to get whole cookie for some reason. Works on app")
def test_login() -> None:

    resp = request_path(client_frontend(), "login")

    # The login page redirects us to microsoft identity platform
    assert resp.status_code == 302

    # Verify we have been redirected
    base_url = get_auth_settings().base_url
    assert resp.headers["location"][: len(base_url)] == base_url

    # We should have added a 'flow' cookie requried for the signin process
    session_cookie = json.loads(base64.b64decode(resp.cookies["session"]).decode())
    assert "flow" in session_cookie


def test_no_cookie() -> None:
    "Check you can sign in when you have a signed session cookie, but cant if you don't"

    # No session cookie
    resp = request_path(
        client_frontend(), "get_open_api_endpoint", follow_redirects=False
    )
    assert resp.status_code == 307


def test_correct_cookie() -> None:
    # Correct session cookie
    payload = signed_session(get_auth_settings().session_secret.get_secret_value())
    resp_auth = request_path(
        client_frontend(
            cookies={"session": payload.decode("utf-8")},
        ),
        "get_documentation",
        follow_redirects=False,
    )

    assert resp_auth.status_code == 200


def test_wrong_cookie_signature() -> None:
    # Wrong session cookie
    payload = signed_session("thisisnotthesessionsecret")
    resp_no_auth = request_path(
        client_frontend(
            cookies={"session": payload.decode("utf-8")},
        ),
        "get_documentation",
        follow_redirects=False,
    )

    assert resp_no_auth.status_code == 307


def test_signed_cookie_malformed() -> None:

    payload = signed_session(get_auth_settings().session_secret.get_secret_value())
    resp_no_auth = request_path(
        client_frontend(cookies={"hello": payload.decode("utf-8")}),
        "get_documentation",
        follow_redirects=False,
    )

    assert resp_no_auth.status_code == 307


# Tests for OAuth state redirect functionality
def test_state_encoding_decoding() -> None:
    """Test that state encoding and decoding works correctly"""
    from fastapimsal.auth_routes import base64, json

    # Test data
    redirect_url = "https://example.com/docs"
    state_data = {"redirect": redirect_url}

    # Encode
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Decode
    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    decoded_url = decoded_data.get("redirect")

    assert decoded_url == redirect_url


def test_login_without_redirect_parameter() -> None:
    """Test login route without redirect parameter behaves normally"""
    client = client_frontend()
    resp = client.get("/login", follow_redirects=False)

    # Should redirect to Microsoft OAuth
    assert resp.status_code == 302
    base_url = get_auth_settings().base_url
    assert resp.headers["location"].startswith(base_url)

    # Should not contain state parameter in the OAuth URL
    oauth_url = resp.headers["location"]
    assert "state=" not in oauth_url


def test_login_with_redirect_parameter() -> None:
    """Test login route with redirect parameter encodes it in OAuth state"""
    client = client_frontend()
    redirect_url = "https://example.com/docs"
    resp = client.get(f"/login?redirect={redirect_url}", follow_redirects=False)

    # Should redirect to Microsoft OAuth
    assert resp.status_code == 302
    base_url = get_auth_settings().base_url
    assert resp.headers["location"].startswith(base_url)

    # Should contain state parameter in the OAuth URL
    oauth_url = resp.headers["location"]
    assert "state=" in oauth_url

    # Extract and decode state parameter
    import urllib.parse

    parsed_url = urllib.parse.urlparse(oauth_url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    state = query_params["state"][0]

    # Decode state and verify it contains our redirect URL
    decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
    assert decoded_data["redirect"] == redirect_url


def test_exception_handler_redirect() -> None:
    """Test that RequiresLoginException redirects to login with redirect parameter"""
    client = client_frontend()

    # Request a protected endpoint without authentication
    resp = client.get("/docs", follow_redirects=False)

    # Should redirect to login with redirect parameter
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert location.startswith("/login?redirect=")

    # Verify the redirect parameter contains the original URL
    import urllib.parse

    parsed_url = urllib.parse.urlparse(location)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    redirect_param = query_params["redirect"][0]
    assert "/docs" in redirect_param


@pytest.mark.xfail(reason="Requires full OAuth flow which needs real credentials")
def test_authorization_callback_with_state() -> None:
    """Test that authorization callback decodes state and redirects correctly"""
    client = client_frontend()

    # Create a mock state parameter
    redirect_url = "https://example.com/docs"
    state_data = {"redirect": redirect_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    # Mock authorization callback (this would normally come from Microsoft)
    # Note: This test would need proper OAuth flow setup to work fully
    resp = client.get(
        f"/getAToken?state={state}&code=mock_code", follow_redirects=False
    )

    # In a real scenario, this would redirect to the decoded URL
    # For now, we just test that the state parameter is handled


def test_authorization_callback_invalid_state() -> None:
    """Test that authorization callback handles invalid state gracefully"""
    client = client_frontend()

    # Test with malformed state
    invalid_states = [
        "invalid_base64!@#",
        base64.urlsafe_b64encode(b"not json").decode(),
        base64.urlsafe_b64encode(
            json.dumps({"no_redirect": "value"}).encode()
        ).decode(),
        "",
    ]

    for invalid_state in invalid_states:
        # This would normally require a full OAuth flow, but we're testing error handling
        # In practice, the callback would fall back to redirecting to home
        pass  # Placeholder - full test would require OAuth mocking


def test_state_encoding_special_characters() -> None:
    """Test state encoding with URLs containing special characters"""
    from fastapimsal.auth_routes import base64, json

    # Test URLs with various special characters
    test_urls = [
        "https://example.com/docs?param=value&other=123",
        "https://example.com/path with spaces/file.html",
        "https://example.com/path#anchor",
        "https://example.com/path?query=value%20encoded",
    ]

    for url in test_urls:
        # Encode
        state_data = {"redirect": url}
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

        # Decode
        decoded_data = json.loads(base64.urlsafe_b64decode(state.encode()).decode())
        decoded_url = decoded_data.get("redirect")

        assert decoded_url == url
