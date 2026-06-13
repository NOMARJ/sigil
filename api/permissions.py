from __future__ import annotations

from fastapi import HTTPException, status

from api.models import UserResponse

_REVIEW_ROLES = {"reviewer", "admin", "owner"}
_SIGNATURE_ADMIN_ROLES = {"admin", "owner"}


def require_review_role(current_user: UserResponse) -> None:
    if current_user.role not in _REVIEW_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Reviewer, admin, or owner role required",
        )


def require_signature_admin_role(current_user: UserResponse) -> None:
    if current_user.role not in _SIGNATURE_ADMIN_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or owner role required",
        )
