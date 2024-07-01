"""Configurations"""

from functools import lru_cache
from typing import List
from uuid import UUID

from pydantic import HttpUrl, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthSettings(BaseSettings):
    """Settings class"""

    client_id: UUID
    client_secret: SecretStr
    tenant_id: UUID
    base_url: HttpUrl = "https://login.microsoftonline.com/"  # type: ignore
    session_secret: SecretStr
    session_expire_time_minutes: int
    https_only: bool = True
    scopes: List[str] = []

    # Settings for the settings class itself.
    model_config = SettingsConfigDict(env_file=".auth.env", env_file_encoding="utf-8")

    @property
    def authority(self) -> str:
        """Makes authorized URL"""
        return str(self.base_url) + str(self.tenant_id)

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def token_metadata_uri(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/.well-known/openid-configuration"


@lru_cache()
def get_auth_settings() -> AuthSettings:

    return AuthSettings()  # type: ignore
