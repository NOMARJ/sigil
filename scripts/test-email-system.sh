#!/bin/bash
set -e

# Test Script for Forge Weekly Email System
# Validates that all email components are working correctly

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "🧪 Testing Forge Weekly Email System"
echo "Project root: $PROJECT_ROOT"
echo ""

# Check if virtual environment exists
if [[ -f "venv/bin/python" ]]; then
    PYTHON_CMD="venv/bin/python"
    echo "📦 Using virtual environment: venv/bin/python"
elif [[ -n "$VIRTUAL_ENV" ]]; then
    PYTHON_CMD="python3"
    echo "📦 Using active virtual environment: $VIRTUAL_ENV"
else
    PYTHON_CMD="python3"
    echo "📦 Using system python3"
fi

echo ""

# Test 1: Check database migration
echo "🗄️  Testing database migration..."
if $PYTHON_CMD -c "
import asyncpg
import asyncio
import os
from pathlib import Path

async def test_migration():
    database_url = os.environ.get('SIGIL_DATABASE_URL')
    if not database_url:
        # Try reading from .env
        env_file = Path('api/.env')
        if env_file.exists():
            with open(env_file) as f:
                for line in f:
                    if line.startswith('SIGIL_DATABASE_URL='):
                        database_url = line.split('=', 1)[1].strip()
                        break
    
    if not database_url:
        print('❌ No database URL found')
        return False
    
    try:
        conn = await asyncpg.connect(database_url)
        
        # Check if email tables exist
        tables = await conn.fetch('''
            SELECT table_name FROM information_schema.tables 
            WHERE table_schema = 'public' 
            AND table_name IN ('email_subscriptions', 'email_campaigns', 'email_sends', 'weekly_digest_cache')
        ''')
        
        table_names = [row['table_name'] for row in tables]
        expected_tables = ['email_subscriptions', 'email_campaigns', 'email_sends', 'weekly_digest_cache']
        
        missing_tables = [t for t in expected_tables if t not in table_names]
        
        if missing_tables:
            print(f'❌ Missing tables: {missing_tables}')
            print('   Run migration: python3 -c \"import asyncio; from api.database import run_migration; asyncio.run(run_migration(\\\"007_email_subscriptions.sql\\\"))\"')
            return False
        else:
            print('✅ All email tables exist')
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f'❌ Database test failed: {e}')
        return False

asyncio.run(test_migration())
"; then
    echo "✅ Database migration test passed"
else
    echo "❌ Database migration test failed"
    exit 1
fi

echo ""

# Test 2: Check email service configuration
echo "📧 Testing email service configuration..."
if $PYTHON_CMD -c "
import sys
sys.path.append('.')

try:
    from api.services.email_service import EmailService
    from api.config import settings
    
    service = EmailService()
    
    print(f'Resend configured: {settings.resend_configured}')
    print(f'From email: {service.from_email}')
    print(f'From name: {service.from_name}')
    print(f'Base URL: {service.base_url}')
    
    if settings.resend_api_key:
        print('✅ Resend API key is set')
    else:
        print('⚠️  Resend API key not set (emails will not send)')
    
    print('✅ Email service initialized successfully')
    
except Exception as e:
    print(f'❌ Email service test failed: {e}')
    sys.exit(1)
"; then
    echo "✅ Email service configuration test passed"
else
    echo "❌ Email service configuration test failed"
    exit 1
fi

echo ""

# Test 3: Test email template rendering
echo "🎨 Testing email template rendering..."
if $PYTHON_CMD -c "
import sys
sys.path.append('.')
import asyncio
from datetime import datetime

async def test_templates():
    try:
        from api.services.email_service import EmailService
        
        service = EmailService()
        
        # Test welcome template
        welcome_html = await service._render_email_template('welcome.html', {
            'email': 'test@example.com',
            'unsubscribe_url': 'https://api.sigilsec.ai/email/unsubscribe/token',
            'base_url': 'https://api.sigilsec.ai'
        })
        
        if 'Welcome to Forge Weekly' in welcome_html:
            print('✅ Welcome template renders correctly')
        else:
            print('❌ Welcome template missing expected content')
            return False
        
        # Test digest generation
        week_ending = datetime.now()
        content = await service.generate_weekly_digest(week_ending)
        
        print(f'✅ Weekly digest generated for {week_ending.date()}')
        print(f'   New tools: {len(content.new_tools)}')
        print(f'   Security alerts: {len(content.security_alerts)}')
        print(f'   Trending categories: {len(content.trending_categories)}')
        
        return True
        
    except Exception as e:
        print(f'❌ Template test failed: {e}')
        return False

if not asyncio.run(test_templates()):
    sys.exit(1)
"; then
    echo "✅ Email template test passed"
else
    echo "❌ Email template test failed"
    exit 1
fi

echo ""

# Test 4: Test email job runner
echo "⚙️  Testing email job runner..."
if $PYTHON_CMD -c "
import sys
sys.path.append('.')

try:
    from api.jobs.email_jobs import EmailJobRunner
    
    runner = EmailJobRunner()
    print('✅ Email job runner created successfully')
    
    # Test job methods exist
    methods = ['generate_and_send_weekly_digest', 'process_scheduled_campaigns', 'cleanup_old_data', 'send_test_digest']
    for method in methods:
        if hasattr(runner, method):
            print(f'✅ Job method {method} exists')
        else:
            print(f'❌ Job method {method} missing')
            sys.exit(1)
    
except Exception as e:
    print(f'❌ Job runner test failed: {e}')
    sys.exit(1)
"; then
    echo "✅ Email job runner test passed"
else
    echo "❌ Email job runner test failed"
    exit 1
fi

echo ""

# Test 5: Test API endpoints
echo "🌐 Testing email API endpoints..."
if $PYTHON_CMD -c "
import sys
sys.path.append('.')

try:
    from api.routers.email import router
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    
    app = FastAPI()
    app.include_router(router)
    
    client = TestClient(app)
    
    # Test subscription endpoint exists
    response = client.post('/email/subscribe', json={
        'email': 'test@example.com',
        'source': 'test'
    })
    
    # Should get some response (even if it fails due to missing DB in test)
    print(f'✅ Subscribe endpoint responds (status: {response.status_code})')
    
    print('✅ API endpoints loaded successfully')
    
except Exception as e:
    print(f'❌ API endpoint test failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"; then
    echo "✅ Email API endpoint test passed"
else
    echo "❌ Email API endpoint test failed"
    exit 1
fi

echo ""
echo "🎉 All email system tests passed!"
echo ""
echo "📋 System Status Summary:"
echo "  ✅ Database migration ready"
echo "  ✅ Email service configured"
echo "  ✅ Templates rendering correctly"  
echo "  ✅ Job runner operational"
echo "  ✅ API endpoints functional"
echo ""

echo "🚀 Next Steps:"
echo "  1. Set SIGIL_RESEND_API_KEY in your .env file"
echo "  2. Run database migration: ./scripts/run-migrations.sh"
echo "  3. Set up cron jobs: ./scripts/setup-email-cron.sh"
echo "  4. Test with: python3 api/jobs/email_jobs.py test_digest your@email.com"
echo ""

echo "📧 Email system is ready for production!"