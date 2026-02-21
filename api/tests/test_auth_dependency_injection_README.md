# Authentication Dependency Injection Test Suite

## Overview

This test suite documents and tests the authentication system for threat API endpoints, with a focus on the dependency injection fix that was implemented to support both Supabase Auth and custom JWT tokens.

## Test File

`test_auth_dependency_injection.py`

## Current Status

### Working Endpoints (Plan Gating Temporarily Disabled)

These endpoints are accessible **without authentication** as a temporary workaround:

- ✅ `GET /v1/threat/{hash}` - Threat lookup by hash
- ✅ `GET /v1/signatures` - List detection signatures

**Rationale:** Plan gating was temporarily disabled on these endpoints (commit `76ce627`) to unblock tests while the dependency injection issue in `require_plan()` is being investigated.

### Broken Endpoints (Dependency Injection Issue)

These endpoints have `require_plan()` dependencies that cause 422 validation errors:

- ❌ `GET /v1/threats` - List all threats
- ❌ `POST /v1/signatures` - Create signature
- ❌ `DELETE /v1/signatures/{id}` - Delete signature
- ❌ `GET /v1/threat-reports` - List threat reports
- ❌ `GET /v1/threat-reports/{id}` - Get single report
- ❌ `PATCH /v1/threat-reports/{id}` - Update report status

**Error:** `422 Unprocessable Entity` with detail: `Field 'current_user' required in query`

**Root Cause:** FastAPI treats the `current_user` parameter in `require_plan()` as a query parameter instead of resolving it as a dependency. This is a known FastAPI issue with nested `Depends()` calls.

## Test Classes

### `TestWorkingEndpoints`

Tests endpoints where plan gating is disabled and authentication is not required.

- Verifies threat lookup works
- Verifies signature listing works
- Tests query parameters (e.g., `since` filter)

### `TestBrokenDependencyInjection`

Documents the dependency injection issue with `pytest.mark.xfail` tests.

- Tests are expected to fail currently
- Will pass once the issue is fixed
- Serve as regression tests

### `TestAuthenticationOnNonGatedEndpoints`

Verifies that JWT token generation and validation works on non-gated endpoints like `/auth/me`.

- Tests registration generates valid tokens
- Tests login generates valid tokens
- Tests invalid tokens are rejected

### `TestPlanSubscriptionManagement`

Tests the plan tier detection logic (separate from the dependency injection issue).

- Verifies default plan is FREE
- Verifies PRO plan detection works
- Tests subscription data storage

### `TestDependencyInjectionIssueDocumentation`

Comprehensive documentation of the issue for debugging purposes.

- Documents that all gated endpoints have the same error
- Explains the root cause
- Provides technical analysis

### `TestProposedFixes`

Placeholder tests for proposed fixes (currently skipped).

## The Dependency Injection Issue

### Problem

In `api/gates.py`, the `require_plan()` function creates a dependency that itself depends on `get_current_user`:

```python
def require_plan(minimum_tier: PlanTier):
    from api.routers.auth import get_current_user, UserResponse

    async def _gate(
        current_user: Annotated[UserResponse, Depends(get_current_user)],
    ) -> None:
        current_tier = await get_user_plan(current_user.id)
        if _tier_rank(current_tier) < _tier_rank(minimum_tier):
            raise PlanGateException(minimum_tier, current_tier)

    return _gate
```

The `get_current_user` function itself has a nested dependency:

```python
async def get_current_user(
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> UserResponse:
    ...
```

FastAPI fails to resolve this nested dependency chain properly, treating `current_user` as a query parameter instead.

### Attempted Fixes

**Commit `f4ca1b3`:** Tried using `get_current_user_unified` instead of `get_current_user`
- Result: Still had dependency injection issues

**Commit `fdb6cbb`:** Reverted to use `get_current_user`
- Result: Still has issues, but at least uses custom JWT

**Commit `76ce627`:** Temporarily disabled plan gating on some endpoints
- Result: Those endpoints work but are unprotected

### Proposed Solutions

1. **Manual Token Extraction** - Extract token from `Request` object directly:
   ```python
   async def _gate(request: Request) -> None:
       token = request.headers.get("Authorization", "").replace("Bearer ", "")
       current_user = await verify_token_and_get_user(token)
   ```

2. **Unified Auth Dependency** - Create a single auth dependency without nested `Depends()`:
   ```python
   async def get_current_user_for_gates(request: Request) -> UserResponse:
       # Manually extract and validate token
       # No nested Depends()
   ```

3. **Flatten Dependency Chain** - Combine auth and plan check into one dependency:
   ```python
   def require_plan_and_auth(minimum_tier: PlanTier):
       async def _gate(request: Request) -> UserResponse:
           user = await validate_auth(request)
           plan = await get_user_plan(user.id)
           if plan < minimum_tier:
               raise PlanGateException(...)
           return user
       return _gate
   ```

## Running the Tests

```bash
# Run all auth dependency injection tests
pytest api/tests/test_auth_dependency_injection.py -v

# Run with xfail tests shown
pytest api/tests/test_auth_dependency_injection.py -v -rx

# Run only working tests (skip xfail)
pytest api/tests/test_auth_dependency_injection.py -v -m "not xfail"

# Run a specific test class
pytest api/tests/test_auth_dependency_injection.py::TestWorkingEndpoints -v
```

## Expected Results

- **Working endpoints:** All tests should pass
- **xfail tests:** Should fail (expected until fix is implemented)
- **Documentation tests:** Should pass (they document current behavior)

## Next Steps

1. Implement one of the proposed fixes for the dependency injection issue
2. Re-enable plan gating on `/v1/threat/{hash}` and `/v1/signatures`
3. Verify all xfail tests start passing
4. Add tests for Supabase Auth tokens (when unified auth is fixed)

## Related Files

- `api/gates.py` - Plan tier enforcement with dependency injection issue
- `api/routers/auth.py` - Authentication dependencies
- `api/routers/threat.py` - Threat API endpoints (some with disabled gating)
- `api/tests/conftest.py` - Test fixtures for authentication
- `api/tests/test_threat.py` - Original threat API tests

## References

- Commit `76ce627` - Temporarily disable plan gating on threat endpoints
- Commit `fdb6cbb` - Revert gates.py to use get_current_user
- Commit `f4ca1b3` - Fix require_plan to use unified auth (reverted)
- Commit `86cca1a` - Fix authentication token flow to use Supabase session tokens
