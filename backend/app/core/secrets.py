

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("app.core.secrets")


@dataclass
class SecretValue:
    """Container for secret value with metadata."""
    value: str
    source: str
    version: str | None = None
    metadata: dict[str, Any] = None


class SecretsProvider(ABC):
    """Abstract base class for secrets providers."""
    
    @abstractmethod
    async def get_secret(self, path: str, key: str | None = None) -> SecretValue:
        """Retrieve a secret by path."""
    
    @abstractmethod
    async def get_secrets(self, path: str) -> dict[str, str]:
        """Retrieve all secrets at a path."""
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the secrets provider is available."""


class EnvSecretsProvider(SecretsProvider):
    """Environment variable secrets provider (development fallback)."""
    
    def __init__(self, prefix: str = "SECRET_") -> None:
        self.prefix = prefix
    
    async def get_secret(self, path: str, key: str | None = None) -> SecretValue:
        env_key = f"{self.prefix}{path.upper().replace('/', '_')}"
        if key:
            env_key = f"{env_key}_{key.upper()}"
        
        value = os.getenv(env_key)
        if value is None:
            raise KeyError(f"Secret not found in environment: {env_key}")
        
        return SecretValue(value=value, source="environment", metadata={})
    
    async def get_secrets(self, path: str) -> dict[str, str]:
        prefix = f"{self.prefix}{path.upper().replace('/', '_')}_"
        secrets = {}
        for k, v in os.environ.items():
            if k.startswith(prefix):
                secret_key = k[len(prefix):].lower()
                secrets[secret_key] = v
        return secrets
    
    async def health_check(self) -> bool:
        return True


class VaultSecretsProvider(SecretsProvider):
    """HashiCorp Vault secrets provider."""
    
    def __init__(
        self,
        vault_url: str,
        vault_token: str,
        mount_point: str = "secret",
    ) -> None:
        self.vault_url = vault_url.rstrip("/")
        self.vault_token = vault_token
        self.mount_point = mount_point
        self._client = None
    
    async def _get_client(self):
        if self._client is None:
            import hvac
            self._client = hvac.Client(
                url=self.vault_url,
                token=self.vault_token,
            )
        return self._client
    
    async def get_secret(self, path: str, key: str | None = None) -> SecretValue:
        client = await self._get_client()
        full_path = f"{self.mount_point}/data/{path.lstrip('/')}"
        
        try:
            response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=self.mount_point)
            data = response["data"]["data"]
            
            if key:
                if key not in data:
                    raise KeyError(f"Key '{key}' not found in secret '{path}'")
                value = data[key]
            else:
                # Return first key or JSON string
                value = next(iter(data.values())) if data else ""
            
            return SecretValue(
                value=value,
                source="vault",
                version=str(response["data"]["metadata"]["version"]),
                metadata=response["data"]["metadata"],
            )
        except Exception as e:
            logger.error("Failed to read secret from Vault: %s", e)
            raise
    
    async def get_secrets(self, path: str) -> dict[str, str]:
        client = await self._get_client()
        try:
            response = client.secrets.kv.v2.read_secret_version(path=path, mount_point=self.mount_point)
            return response["data"]["data"]
        except Exception as e:
            logger.error("Failed to read secrets from Vault: %s", e)
            raise
    
    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            return client.sys.is_sealed() is False
        except Exception:
            return False


class AWSSecretsManagerProvider(SecretsProvider):
    """AWS Secrets Manager secrets provider."""
    
    def __init__(
        self,
        region: str = "us-east-1",
        endpoint_url: str | None = None,
    ) -> None:
        self.region = region
        self.endpoint_url = endpoint_url
        self._client = None
    
    async def _get_client(self):
        if self._client is None:
            import boto3
            self._client = boto3.client(
                "secretsmanager",
                region_name=self.region,
                endpoint_url=self.endpoint_url,
            )
        return self._client
    
    async def get_secret(self, path: str, key: str | None = None) -> SecretValue:
        client = await self._get_client()
        
        try:
            response = client.get_secret_value(SecretId=path)
            secret_string = response.get("SecretString", "{}")
            import json
            data = json.loads(secret_string)
            
            if key:
                if key not in data:
                    raise KeyError(f"Key '{key}' not found in secret '{path}'")
                value = data[key]
            else:
                value = next(iter(data.values())) if data else ""
            
            return SecretValue(
                value=value,
                source="aws_secrets_manager",
                version=response.get("VersionId"),
                metadata={"arn": response.get("ARN"), "name": response.get("Name")},
            )
        except Exception as e:
            logger.error("Failed to read secret from AWS Secrets Manager: %s", e)
            raise
    
    async def get_secrets(self, path: str) -> dict[str, str]:
        client = await self._get_client()
        try:
            response = client.get_secret_value(SecretId=path)
            secret_string = response.get("SecretString", "{}")
            import json
            return json.loads(secret_string)
        except Exception as e:
            logger.error("Failed to read secrets from AWS Secrets Manager: %s", e)
            raise
    
    async def health_check(self) -> bool:
        try:
            client = await self._get_client()
            client.list_secrets(MaxResults=1)
            return True
        except Exception:
            return False


# Global secrets provider instance
_secrets_provider: SecretsProvider | None = None


def get_secrets_provider() -> SecretsProvider:
    """Get the configured secrets provider."""
    global _secrets_provider
    
    if _secrets_provider is not None:
        return _secrets_provider
    
    # Determine provider from environment
    provider_type = os.getenv("SECRETS_PROVIDER", "env").lower()
    
    if provider_type == "vault":
        vault_url = os.getenv("VAULT_URL", "http://localhost:8200")
        vault_token = os.getenv("VAULT_TOKEN")
        if not vault_token:
            raise ValueError("VAULT_TOKEN required for Vault secrets provider")
        mount_point = os.getenv("VAULT_MOUNT_POINT", "secret")
        _secrets_provider = VaultSecretsProvider(vault_url, vault_token, mount_point)
    
    elif provider_type == "aws":
        region = os.getenv("AWS_REGION", "us-east-1")
        endpoint_url = os.getenv("AWS_ENDPOINT_URL")
        _secrets_provider = AWSSecretsManagerProvider(region, endpoint_url)
    
    else:
        # Default to environment provider
        _secrets_provider = EnvSecretsProvider()
    
    return _secrets_provider


async def load_secret(path: str, key: str | None = None) -> str:
    """Convenience function to load a secret value."""
    provider = get_secrets_provider()
    secret = await provider.get_secret(path, key)
    return secret.value


async def load_secrets(path: str) -> dict[str, str]:
    """Convenience function to load all secrets at a path."""
    provider = get_secrets_provider()
    return await provider.get_secrets(path)