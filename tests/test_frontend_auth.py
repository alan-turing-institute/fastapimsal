import base64
import json
import urllib
import uuid
from typing import Any
from unittest.mock import Mock, patch

import httpx2 as httpx
import itsdangerous
from fastapi.testclient import TestClient

from examples.app import app
from fastapimsal.config import get_auth_settings


def client_frontend(**kwargs: Any) -> TestClient:
    return TestClient(app, **kwargs)


def request_path(
    client: TestClient, path: str, method: str = "get", **kwargs: Any
) -> httpx.Response:
    """Request giving the name of route function

    Args:
        client (TestClient): Your test client
        path (str): Route function name
        method (str, optional): HTTP Method. Defaults to "get".

    Returns:
        [type]: [description]
    """

    return client.request(url=app.url_path_for(path), method=method, **kwargs)


def signed_session(session_secret: str) -> Any:

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


def test_login() -> None:

    client = client_frontend()
    with patch("fastapimsal.auth_routes.build_msal_app") as mock_build_msal_app:
        mock_app = Mock()
        mock_app.initiate_auth_code_flow = lambda scopes, redirect_uri, state=None: {
            "auth_uri": f"https://fakeurl/common/oauth2/v2.0/authorize?client_id=fake_client_id&redirect_uri={redirect_uri}"
            + (f"&state={state}" if state else ""),
        }

        mock_build_msal_app.return_value = mock_app
        resp = client.get("/login", follow_redirects=False)

        # The login page redirects us to microsoft identity platform
        assert resp.status_code == 302

        # Verify we have been redirected
        base_url = "https://fakeurl/common/oauth2/v2.0"
        assert resp.headers["location"].startswith(base_url)

        # We should have added a 'flow' cookie required for the signin process
        session_cookie = json.loads(base64.b64decode(resp.cookies["session"]).decode())
        assert "redirect_uri=" in session_cookie["flow"]["auth_uri"]
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
    the_state = query_params["state"][0]

    # Decode and verify state contains redirect URL
    decoded = json.loads(base64.urlsafe_b64decode(the_state.encode()).decode())
    assert decoded["redirect"] == redirect_url


def test_no_cookie() -> None:
    """Check you can only sign in when you have a signed session cookie"""

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


def test_exception_handler_redirect() -> None:
    """Test that RequiresLoginException redirects to login with redirect parameter"""
    client = client_frontend()

    # Request a protected endpoint without authentication
    resp = client.get("/docs", follow_redirects=False)

    # Should redirect to /login with redirect parameter
    assert resp.status_code == 307
    location = resp.headers["location"]
    assert "/login?redirect=" in location

    parsed_url = urllib.parse.urlparse(location)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    redirect_param = query_params["redirect"][0]

    # Should contain the original URL
    assert redirect_param.endswith("/docs"), f"Redirect param was {redirect_param}"


def test_authorization_callback_with_state() -> None:
    """Test that authorization callback decodes state and redirects correctly"""
    client = client_frontend()

    redirect_url = "https://example.com/docs"
    state_data = {"redirect": redirect_url}
    state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

    response = client.get(
        f"/getAToken?state={state}&code=mock_code", follow_redirects=False
    )
    assert response.status_code == 302
    assert response.headers["location"] == redirect_url

    response = client.get("/getAToken?code=mock_code", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == str(client.base_url) + app.url_path_for(
        "home"
    )
