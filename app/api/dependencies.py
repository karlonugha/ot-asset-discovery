"""FastAPI dependencies for authentication and authorization.

Implements:
- Auth middleware that validates JWT on all protected endpoints
- Role-based access control: "viewer" (read-only) and "admin" (full access)
- Specific error messages: "missing token", "token expired", "invalid token"
- HTTP 403 for insufficient permissions

Requirements: 8.1, 8.3, 8.4, 8.5
"""

from typing import Literal

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.api.auth import AuthError, TokenData, decode_access_token

# HTTP Bearer scheme - auto_error=False so we can provide custom "missing token" message
security_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security_scheme),
) -> TokenData:
    """Validate JWT token and return current user data.

    This dependency validates the Authorization header on all protected endpoints.
    Returns specific error messages per Requirement 8.3:
    - "missing token" when no Authorization header is provided
    - "token expired" when the JWT has expired
    - "invalid token" when the JWT signature is invalid or malformed

    Args:
        credentials: The HTTP Bearer credentials from the Authorization header.

    Returns:
        TokenData containing the authenticated user's username and role.

    Raises:
        HTTPException: 401 with specific error message.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        token_data = decode_access_token(credentials.credentials)
        return token_data
    except AuthError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=e.detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_role(required_role: Literal["viewer", "admin"]):
    """Create a dependency that enforces a minimum role level.

    Role hierarchy:
    - "admin": full access (includes all viewer permissions)
    - "viewer": read-only access

    Args:
        required_role: The minimum role required to access the endpoint.

    Returns:
        A FastAPI dependency function that validates the user's role.
    """

    async def role_checker(
        current_user: TokenData = Depends(get_current_user),
    ) -> TokenData:
        """Check if the current user has the required role.

        Args:
            current_user: The authenticated user from JWT validation.

        Returns:
            TokenData if role is sufficient.

        Raises:
            HTTPException: 403 if user lacks required permissions.
        """
        # Admin has full access to everything
        if current_user.role == "admin":
            return current_user

        # Viewer can only access viewer-level endpoints
        if required_role == "admin" and current_user.role == "viewer":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: '{current_user.role}' role cannot perform this action. Required role: '{required_role}'.",
            )

        return current_user

    return role_checker


# Convenience dependencies for common access patterns
require_viewer = require_role("viewer")
require_admin = require_role("admin")
