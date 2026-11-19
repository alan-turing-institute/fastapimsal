# type: ignore
"""Tests for error results returned by MSAL in the /getAToken route"""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from examples.app import app


def get_a_token(result: dict):
    client = TestClient(app)
    with patch("fastapimsal.auth_routes.build_msal_app") as build_msal_app:
        build_msal_app.return_value.acquire_token_by_auth_code_flow.return_value = (
            result
        )
        return client.get(app.url_path_for("authorized"), follow_redirects=False)


@pytest.mark.parametrize("error", ["access_denied", "invalid_grant"])
def test_recoverable_error_redirects_home(error: str) -> None:

    resp = get_a_token({"error": error, "error_description": "description"})

    assert resp.status_code == 302
    assert resp.headers["location"].endswith(app.url_path_for("home"))


def test_invalid_client_raises() -> None:

    with pytest.raises(RuntimeError, match="AADSTS7000222"):
        get_a_token(
            {
                "error": "invalid_client",
                "error_description": "AADSTS7000222: The provided client secret keys are expired.",
            }
        )
