"""
Core Security and Identity Verification Module.
Implements JWT token decoding/encoding, RFC 7519 claims validation, password hashing,
and fine-grained Role-Based Access Control (RBAC) dependency injection for FastAPI endpoints.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated, Any, Dict, List, Optional, Sequence
from uuid import UUID

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    SecurityScopes,
)
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.exceptions import AuthenticationException, AuthorizationException

# HTTP Bearer scheme setup with automatic 401 challenge formatting
bearer_scheme = HTTPBearer(auto_error=False)

# Password hashing configuration using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class TokenClaims(BaseModel):
    """Authoritative representation of verified JWT token claims."""

    sub: str = Field(..., description="Subject identifier (User/Agent UUID or system identifier)")
    preferred_username: Optional[str] = Field(default=None, description="Human-readable identity name")
    roles: List[str] = Field(default_factory=list, description="Assigned operational security roles")
    scopes: List[str] = Field(default_factory=list, description="Granted permission scopes")
    exp: datetime = Field(..., description="Token expiration timestamp in UTC")
    iat: datetime = Field(..., description="Token issuance timestamp in UTC")

    @property
    def subject_uuid(self) -> Optional[UUID]:
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


def create_access_token(
    subject: str,
    roles: Optional[Sequence[str]] = None,
    scopes: Optional[Sequence[str]] = None,
    preferred_username: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """
    Creates an RFC 7519 compliant JSON Web Token signed with the application secret key.
    Enforces UTC timestamps and dynamically embeds roles and scope permissions.
    """
    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.security.ACCESS_TOKEN_EXPIRE_MINUTES)

    claims: Dict[str, Any] = {
        "sub": subject,
        "iat": now.timestamp(),
        "exp": expire.timestamp(),
        "roles": list(roles) if roles else [],
        "scope": " ".join(scopes) if scopes else "",
    }
    if preferred_username:
        claims["preferred_username"] = preferred_username

    encoded_jwt = jwt.encode(
        claims,
        settings.security.JWT_SECRET_KEY.get_secret_value(),
        algorithm=settings.security.JWT_ALGORITHM,
    )
    return encoded_jwt


def decode_and_verify_token(token: str) -> TokenClaims:
    """
    Decodes and validates JWT claims against the application's cryptographic configuration.
    Raises AuthenticationException on signature invalidity, expiration, or format corruption.
    """
    try:
        payload = jwt.decode(
            token,
            settings.security.JWT_SECRET_KEY.get_secret_value(),
            algorithms=[settings.security.JWT_ALGORITHM],
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
        exp=datetime.fromtimestamp(float(raw_exp), tz=timezone.utc),
        iat=datetime.fromtimestamp(float(raw_iat), tz=timezone.utc),
    )


async def get_current_user_claims(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
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

    return decode_and_verify_token(credentials.credentials)


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