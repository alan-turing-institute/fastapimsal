# type: ignore
"""Tests for verifying access tokens in the backend"""

import asyncio
import base64
import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jwt.algorithms import RSAAlgorithm

from fastapimsal.backend.authentication import TokenVerifier
from fastapimsal.config import get_auth_settings

KID = "test-kid"


def make_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


SIGNING_KEY = make_private_key()
JWK = {**RSAAlgorithm.to_jwk(SIGNING_KEY.public_key(), as_dict=True), "kid": KID}


def make_claims(**overrides) -> dict:
    settings = get_auth_settings()
    now = int(time.time())
    claims = {
        "iss": settings.issuer,
        "aud": str(settings.client_id),
        "oid": "user-oid",
        "iat": now,
        "nbf": now,
        "exp": now + 3600,
    }
    claims.update(overrides)
    return claims


def make_token(key=SIGNING_KEY, algorithm: str = "RS256", **claim_overrides) -> str:
    return jwt.encode(
        make_claims(**claim_overrides),
        key,
        algorithm=algorithm,
        headers={"kid": KID},
    )


def make_hs256_token_signed_with_public_key() -> str:
    """Key confusion attack: HMAC-sign a token using the public key as the secret.
    Built by hand because PyJWT refuses to create one."""

    def b64(data: bytes) -> bytes:
        return base64.urlsafe_b64encode(data).rstrip(b"=")

    header = {"alg": "HS256", "typ": "JWT", "kid": KID}
    signing_input = (
        b64(json.dumps(header).encode())
        + b"."
        + b64(json.dumps(make_claims()).encode())
    )
    secret = SIGNING_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64(signature)).decode()


def verify(token: str, auto_error: bool = False):
    with patch.object(TokenVerifier, "get_key", AsyncMock(return_value=JWK)):
        return asyncio.run(
            TokenVerifier().verify_access_token(token, auto_error=auto_error)
        )


def test_valid_token() -> None:

    claims = verify(make_token())

    assert claims["oid"] == "user-oid"


def test_invalid_token_raises_401_when_auto_error() -> None:

    with pytest.raises(HTTPException) as excinfo:
        verify("not-a-token", auto_error=True)

    assert excinfo.value.status_code == 401


def test_wrong_issuer_raises_401() -> None:

    with pytest.raises(HTTPException) as excinfo:
        verify(make_token(iss="https://evil.example.com/v2.0"))

    assert excinfo.value.status_code == 401


@pytest.mark.parametrize(
    "token",
    [
        pytest.param("not-a-token", id="malformed"),
        pytest.param(make_token(aud="some-other-app"), id="wrong-audience"),
        pytest.param(make_token(exp=int(time.time()) - 60), id="expired"),
        pytest.param(make_token(nbf=int(time.time()) + 3600), id="not-yet-valid"),
        pytest.param(make_token(key=make_private_key()), id="wrong-signing-key"),
        pytest.param(make_token(key=None, algorithm="none"), id="alg-none"),
        pytest.param(
            make_hs256_token_signed_with_public_key(), id="hs256-with-public-key"
        ),
    ],
)
def test_invalid_token_returns_none(token: str) -> None:

    assert verify(token) is None
