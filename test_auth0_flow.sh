#!/bin/bash
# Test Auth0 OAuth Flow Configuration

set -e

echo "======================================================================"
echo "Auth0 OAuth Flow Test"
echo "======================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Custom domain JWKS
echo "🔍 Test 1: Custom domain JWKS endpoint..."
if curl -sf https://auth.sigilsec.ai/.well-known/jwks.json > /dev/null; then
    echo -e "${GREEN}✅ auth.sigilsec.ai JWKS endpoint accessible${NC}"
else
    echo -e "${RED}❌ auth.sigilsec.ai JWKS endpoint failed${NC}"
    exit 1
fi

# Test 2: OpenID configuration
echo ""
echo "🔍 Test 2: OpenID configuration endpoint..."
if curl -sf https://auth.sigilsec.ai/.well-known/openid-configuration > /dev/null; then
    echo -e "${GREEN}✅ OpenID configuration accessible${NC}"

    # Extract key info
    ISSUER=$(curl -s https://auth.sigilsec.ai/.well-known/openid-configuration | python3 -c "import sys,json; print(json.load(sys.stdin).get('issuer',''))")
    echo "   Issuer: $ISSUER"
else
    echo -e "${RED}❌ OpenID configuration failed${NC}"
    exit 1
fi

# Test 3: Check if API exists (should return 404 but with Auth0 branding)
echo ""
echo "🔍 Test 3: Auth0 custom domain responding..."
STATUS=$(curl -s -o /dev/null -w "%{http_code}" https://auth.sigilsec.ai/)
if [ "$STATUS" = "404" ] || [ "$STATUS" = "200" ]; then
    echo -e "${GREEN}✅ Custom domain responding (HTTP $STATUS)${NC}"
else
    echo -e "${RED}❌ Unexpected status: $STATUS${NC}"
fi

# Test 4: Verify environment variables are set
echo ""
echo "🔍 Test 4: Environment variables..."
cd "$(dirname "$0")"

if [ -f "dashboard/.env.local" ]; then
    if grep -q "auth.sigilsec.ai" dashboard/.env.local; then
        echo -e "${GREEN}✅ Dashboard .env.local configured with custom domain${NC}"
    else
        echo -e "${RED}❌ Dashboard .env.local missing custom domain${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ dashboard/.env.local not found${NC}"
    exit 1
fi

if [ -f "api/.env" ]; then
    if grep -q "auth.sigilsec.ai" api/.env; then
        echo -e "${GREEN}✅ API .env configured with custom domain${NC}"
    else
        echo -e "${RED}❌ API .env missing custom domain${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ api/.env not found${NC}"
    exit 1
fi

# Test 5: Check Auth0 Dashboard setup (by testing authorize endpoint)
echo ""
echo "🔍 Test 5: Auth0 application configured..."
CLIENT_ID="WzNmPGqml7IKSAcSCwz8lhwyv383CKfq"
AUTH_URL="https://auth.sigilsec.ai/authorize?client_id=$CLIENT_ID&response_type=code&redirect_uri=http://localhost:3000/api/auth/callback&scope=openid%20profile%20email"

# This will return 302 redirect if configured, or error if not
STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$AUTH_URL")
if [ "$STATUS" = "302" ] || [ "$STATUS" = "200" ]; then
    echo -e "${GREEN}✅ Auth0 application responding (HTTP $STATUS)${NC}"
    echo "   OAuth flow can be initiated"
else
    echo -e "${YELLOW}⚠️  Unexpected status: $STATUS${NC}"
    echo "   May indicate Auth0 application not fully configured"
    echo "   This is OK if you haven't completed Dashboard setup yet"
fi

# Summary
echo ""
echo "======================================================================"
echo "Summary"
echo "======================================================================"
echo ""
echo -e "${GREEN}✅ Custom domain verified: auth.sigilsec.ai${NC}"
echo -e "${GREEN}✅ JWKS endpoint working${NC}"
echo -e "${GREEN}✅ Environment files configured${NC}"
echo ""
echo "Next steps:"
echo "1. Complete Auth0 Dashboard configuration (docs/internal/AUTH0_TODO.md)"
echo "2. Update GitHub OAuth app callback to: https://auth.sigilsec.ai/login/callback"
echo "3. Update Google OAuth redirect to: https://auth.sigilsec.ai/login/callback"
echo "4. Start services: docker compose up -d"
echo "5. Test login: open http://localhost:3000/login"
echo ""
echo "To test API directly (requires running API server):"
echo "  cd api && uvicorn api.main:app --reload"
echo "  # In another terminal:"
echo "  curl http://localhost:8000/health"
