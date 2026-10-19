

import asyncio
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx
from fastapi import Depends
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    SecurityScopes,
)
from jose import JWTError, jwt
from jose.backends import RSAKey
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.exceptions import AuthenticationException, AuthorizationException

logger = logging.getLogger("app.core.security")

# HTTP Bearer scheme setup with automatic 401 challenge formatting
bearer_scheme = HTTPBearer(auto_error=False)

# Password hashing configuration using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWKS cache
_jwks_cache: dict[str, Any] = {"keys": {}, "fetched_at": 0.0}
_jwks_lock = asyncio.Lock()
JWKS_CACHE_TTL = 3600  # 1 hour


class TokenClaims(BaseModel):
    """Authoritative representation of verified JWT token claims."""

    sub: str = Field(..., description="Subject identifier (User/Agent UUID or system identifier)")
    preferred_username: str | None = Field(default=None, description="Human-readable identity name")
    roles: list[str] = Field(default_factory=list, description="Assigned operational security roles")
    scopes: list[str] = Field(default_factory=list, description="Granted permission scopes")
    exp: datetime = Field(..., description="Token expiration timestamp in UTC")
    iat: datetime = Field(..., description="Token issuance timestamp in UTC")
    jti: str | None = Field(default=None, description="JWT ID for token tracking")
    token_type: str = Field(default="access", description="Token type: access or refresh")

    @property
    def subject_uuid(self) -> UUID | None:
        """Attempts to parse sub as a UUID if applicable."""
        try:
            return UUID(self.sub)
        except (ValueError, TypeError):
            return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain-text password against a stored bcrypt hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generates a secure salted bcrypt hash for a plain-text password."""
    return pwd_context.hash(password)


async def _fetch_jwks(jwks_url: str) -> dict[str, Any]:
    """Fetch JWKS from the configured URL."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(jwks_url)
        response.raise_for_status()
        return response.json()


async def get_jwks() -> dict[str, Any]:
    """Get JWKS with caching."""
    global _jwks_cache
    
    jwks_url = settings.security.JWT_JWKS_URL
    if not jwks_url:
        raise ValueError("JWT_JWKS_URL must be configured for RS256 validation")
    
    async with _jwks_lock:
        now = time.time()
        if now - _jwks_cache["fetched_at"] < JWKS_CACHE_TTL and _jwks_cache["keys"]:
            return _jwks_cache["keys"]
        
        try:
            jwks_data = await _fetch_jwks(jwks_url)
            _jwks_cache["keys"] = jwks_data.get("keys", {})
            _jwks_cache["fetched_at"] = now
            logger.info("JWKS refreshed from %s (%d keys)", jwks_url, len(_jwks_cache["keys"]))
        except Exception as e:
            logger.error("Failed to fetch JWKS: %s", e)
            if not _jwks_cache["keys"]:
                raise AuthenticationException(
                    message="Unable to fetch JWKS for token validation",
                    context={"jwks_url": jwks_url, "error": str(e)},
                )
        
        return _jwks_cache["keys"]


def _get_rsa_key_from_jwks(token: str, jwks: dict[str, Any]) -> RSAKey:
    """Extract RSA key from JWKS matching the token's kid."""
    
    # Get kid from token header
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise AuthenticationException(
            message=f"Invalid token header: {e}",
            context={"token_error": str(e)},
        )
    
    kid = header.get("kid")
    if not kid:
        raise AuthenticationException(
            message="Token header missing 'kid' (key ID) required for JWKS validation",
        )
    
    # Find matching key in JWKS
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            return RSAKey(key, algorithm="RS256")
    
    raise AuthenticationException(
        message=f"No matching key found in JWKS for kid: {kid}",
        context={"kid": kid},
    )


def create_access_token(
    subject: str,
    roles: Sequence[str] | None = None,
    scopes: Sequence[str] | None = None,
    preferred_username: str | None = None,
    expires_delta: timedelta | None = None,
    token_type: str = "access",
) -> str:
    """
    Creates an RFC 7519 compliant JSON Web Token signed with RS256.
    Enforces UTC timestamps and dynamically embeds roles and scope permissions.
    
    For RS256, requires JWT_PRIVATE_KEY (PEM format) in settings or secrets.
    Falls back to HS256 with JWT_SECRET_KEY if RS256 not configured.
    """
    now = datetime.now(UTC)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        # Default to 15 minutes for access tokens
        default_minutes = 15 if token_type == "access" else settings.security.ACCESS_TOKEN_EXPIRE_MINUTES
        expire = now + timedelta(minutes=default_minutes)

    import uuid
    claims: dict[str, Any] = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "roles": list(roles) if roles else [],
        "scope": " ".join(scopes) if scopes else "",
        "jti": str(uuid.uuid4()),
        "token_type": token_type,
    }
    if preferred_username:
        claims["preferred_username"] = preferred_username

    # Determine signing algorithm and key
    algorithm = getattr(settings.security, "JWT_ALGORITHM", "RS256")
    
    if algorithm == "RS256":
        # Load private key from settings or secrets
        private_key = getattr(settings.security, "JWT_PRIVATE_KEY", None)
        if hasattr(private_key, "get_secret_value"):
            private_key = private_key.get_secret_value()
        if not private_key:
            raise ValueError("JWT_PRIVATE_KEY must be configured for RS256 signing")
        key = private_key
    else:
        # HS256 fallback
        secret_key = settings.security.JWT_SECRET_KEY.get_secret_value()
        key = secret_key

    encoded_jwt = jwt.encode(claims, key, algorithm=algorithm)
    return encoded_jwt


def create_refresh_token(
    subject: str,
    roles: Sequence[str] | None = None,
    scopes: Sequence[str] | None = None,
    preferred_username: str | None = None,
) -> str:
    """Create a long-lived refresh token (default 7 days)."""
    return create_access_token(
        subject=subject,
        roles=roles,
        scopes=scopes,
        preferred_username=preferred_username,
        expires_delta=timedelta(days=7),
        token_type="refresh",
    )


async def decode_and_verify_token(token: str) -> TokenClaims:
    """
    Decodes and validates JWT claims against the application's cryptographic configuration.
    Supports RS256 with JWKS and HS256 fallback.
    Raises AuthenticationException on signature invalidity, expiration, or format corruption.
    """
    algorithm = getattr(settings.security, "JWT_ALGORITHM", "RS256")
    
    try:
        if algorithm == "RS256":
            # Get JWKS and find matching key
            jwks = await get_jwks()
            rsa_key = _get_rsa_key_from_jwks(token, {"keys": jwks})
            
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=["RS256"],
                audience=getattr(settings.security, "JWT_AUDIENCE", None),
                issuer=getattr(settings.security, "JWT_ISSUER", None),
            )
        else:
            # HS256 fallback
            payload = jwt.decode(
                token,
                settings.security.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[algorithm],
            )
    except JWTError as err:
        raise AuthenticationException(
            message=f"Invalid or expired authorization token: {err}",
            context={"token_error": str(err)},
        ) from err

    raw_sub = payload.get("sub")
    raw_exp = payload.get("exp")
    raw_iat = payload.get("iat")

    if not raw_sub or not raw_exp or not raw_iat:
        raise AuthenticationException(
            message="Token payload is missing mandatory RFC 7519 standard claims.",
            context={"missing_claims": [k for k in ("sub", "exp", "iat") if not payload.get(k)]},
        )

    # Check token type
    token_type = payload.get("token_type", "access")
    
    # Scopes can be formatted either as space-delimited string or JSON list
    raw_scope = payload.get("scope", "")
    if isinstance(raw_scope, str):
        parsed_scopes = [s.strip() for s in raw_scope.split(" ") if s.strip()]
    elif isinstance(raw_scope, list):
        parsed_scopes = [str(s).strip() for s in raw_scope if str(s).strip()]
    else:
        parsed_scopes = []

    return TokenClaims(
        sub=str(raw_sub),
        preferred_username=payload.get("preferred_username"),
        roles=payload.get("roles", []),
        scopes=parsed_scopes,
        exp=datetime.fromtimestamp(float(raw_exp), tz=UTC),
        iat=datetime.fromtimestamp(float(raw_iat), tz=UTC),
        jti=payload.get("jti"),
        token_type=token_type,
    )


async def get_current_user_claims(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> TokenClaims:
    """
    FastAPI dependency that extracts and validates the Bearer token from incoming request headers.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationException(
            message="Missing Bearer authentication token in request Authorization header."
        )

    if credentials.scheme.lower() != "bearer":
        raise AuthenticationException(
            message="Unsupported authentication scheme. Bearer authentication is required."
        )

    return await decode_and_verify_token(credentials.credentials)


class SecurityScopeChecker:
    """
    Enforces that the authenticated identity possesses required permission scopes.
    Supports OpenAPI securityScopes auto-documentation in FastAPI.
    """

    def __init__(self, required_scopes: Sequence[str]) -> None:
        self.required_scopes = set(required_scopes)

    def __call__(
        self,
        security_scopes: SecurityScopes,
        claims: TokenClaims = Depends(get_current_user_claims),
    ) -> TokenClaims:
        # Evaluate both dynamically injected scopes and decorator-declared scopes
        all_required = self.required_scopes.union(set(security_scopes.scopes))
        if not all_required:
            return claims

        user_scopes = set(claims.scopes)
        missing_scopes = all_required - user_scopes

        if missing_scopes:
            raise AuthorizationException(
                required_scope=", ".join(sorted(missing_scopes)),
                context={
                    "user_scopes": list(user_scopes),
                    "missing_scopes": list(missing_scopes),
                },
            )

        return claims


class RoleChecker:
    """
    Enforces that the authenticated identity is assigned at least one of the permitted roles.
    """

    def __init__(self, allowed_roles: Sequence[str]) -> None:
        self.allowed_roles = set(allowed_roles)

    def __call__(self, claims: TokenClaims = Depends(get_current_user_claims)) -> TokenClaims:
        if not self.allowed_roles:
            return claims

        user_roles = set(claims.roles)
        if not user_roles.intersection(self.allowed_roles):
            raise AuthorizationException(
                context={
                    "user_roles": list(user_roles),
                    "allowed_roles": list(self.allowed_roles),
                }
            )

        return claims


# Reusable FastAPI dependency factory functions
def require_scopes(*scopes: str) -> SecurityScopeChecker:
    """Dependency factory enforcing one or more specific OAuth2/JWT permission scopes."""
    return SecurityScopeChecker(scopes)


def require_roles(*roles: str) -> RoleChecker:
    """Dependency factory enforcing one or more security operational roles."""
    return RoleChecker(roles)