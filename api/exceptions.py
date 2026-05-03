"""Sigil API — cross-cutting domain exceptions.

Re-exports service-owned exceptions and defines API-wide ones. Modules
that catch or raise these errors import from here so the dependency
direction is router → exceptions, not router → specific service.
"""

from __future__ import annotations

from api.services.credit_service import (
    CreditTransactionError,
    InsufficientCreditsError,
)


class UnauthorizedError(Exception):
    """Raised when an unauthenticated request hits a protected operation.

    Distinct from FastAPI's HTTPException(401) — this is a domain signal
    raised inside service code that callers translate to a 401 response.
    """


__all__ = [
    "CreditTransactionError",
    "InsufficientCreditsError",
    "UnauthorizedError",
]
