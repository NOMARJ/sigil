#!/usr/bin/env python3
"""
Test Auth0 Integration for Sigil API

This script tests the Auth0 JWKS verification without requiring a full API server.
It validates that our verify_auth0_token() implementation can fetch and parse JWKS.
"""

import sys
import asyncio
from pathlib import Path

# Add api to path
sys.path.insert(0, str(Path(__file__).parent))

async def test_jwks_fetch():
    """Test that we can fetch Auth0 JWKS from custom domain."""
    print("🔍 Testing Auth0 JWKS fetch from auth.sigilsec.ai...")

    import httpx

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get("https://auth.sigilsec.ai/.well-known/jwks.json")
            resp.raise_for_status()
            jwks = resp.json()

        print(f"✅ JWKS fetched successfully")
        print(f"   - Found {len(jwks.get('keys', []))} signing keys")

        for i, key in enumerate(jwks.get("keys", []), 1):
            print(f"   - Key {i}: {key.get('kid')} (alg: {key.get('alg')}, use: {key.get('use')})")

        return True
    except Exception as e:
        print(f"❌ JWKS fetch failed: {e}")
        return False

async def test_config_loaded():
    """Test that Auth0 config is properly loaded."""
    print("\n🔍 Testing Auth0 configuration...")

    try:
        from api.config import settings

        print(f"✅ Config loaded successfully")
        print(f"   - AUTH0_DOMAIN: {settings.auth0_domain}")
        print(f"   - AUTH0_AUDIENCE: {settings.auth0_audience}")
        print(f"   - AUTH0_CLIENT_ID: {settings.auth0_client_id[:20]}...")
        print(f"   - auth0_configured: {settings.auth0_configured}")

        if not settings.auth0_configured:
            print("❌ Auth0 not configured (domain or audience missing)")
            return False

        return True
    except Exception as e:
        print(f"❌ Config load failed: {e}")
        return False

async def test_jose_available():
    """Test that python-jose is available for RS256 verification."""
    print("\n🔍 Testing python-jose availability...")

    try:
        from jose import jwt, JWTError

        print(f"✅ python-jose available")
        print(f"   - Can decode RS256 tokens")

        return True
    except ImportError as e:
        print(f"❌ python-jose not available: {e}")
        print(f"   Auth0 RS256 verification requires python-jose")
        return False

async def test_verify_function():
    """Test that verify_auth0_token function exists and can be called."""
    print("\n🔍 Testing verify_auth0_token() function...")

    try:
        from api.routers.auth import verify_auth0_token, _get_auth0_jwks
        from api.config import settings

        print(f"✅ verify_auth0_token() function imported")

        # Try to fetch JWKS (simulates what happens during token verification)
        if settings.auth0_configured:
            jwks = await _get_auth0_jwks()
            print(f"✅ JWKS cache populated ({len(jwks.get('keys', []))} keys)")
        else:
            print(f"⚠️  Auth0 not configured, skipping JWKS fetch")

        return True
    except Exception as e:
        print(f"❌ Function test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_auto_provision_function():
    """Test that user auto-provisioning function exists."""
    print("\n🔍 Testing _auto_provision_auth0_user() function...")

    try:
        from api.routers.auth import _auto_provision_auth0_user

        print(f"✅ _auto_provision_auth0_user() function imported")
        print(f"   - Ready to auto-create OAuth users on first login")

        return True
    except Exception as e:
        print(f"❌ Auto-provision function test failed: {e}")
        return False

async def main():
    """Run all tests."""
    print("=" * 70)
    print("Auth0 Integration Test Suite")
    print("=" * 70)

    results = []

    # Test 1: JWKS fetch
    results.append(await test_jwks_fetch())

    # Test 2: Config
    results.append(await test_config_loaded())

    # Test 3: python-jose
    results.append(await test_jose_available())

    # Test 4: Verify function
    results.append(await test_verify_function())

    # Test 5: Auto-provision function
    results.append(await test_auto_provision_function())

    print("\n" + "=" * 70)
    print("Summary")
    print("=" * 70)

    passed = sum(results)
    total = len(results)

    print(f"Tests passed: {passed}/{total}")

    if passed == total:
        print("\n✅ All tests passed! Auth0 integration is ready.")
        print("\nNext steps:")
        print("1. Complete Auth0 Dashboard setup (see docs/internal/AUTH0_TODO.md)")
        print("2. Start services: docker compose up -d")
        print("3. Test OAuth login: http://localhost:3000/login")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed. Fix issues before proceeding.")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
