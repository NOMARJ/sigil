# Forge Weekly Email Newsletter System

## Overview

The Forge Weekly email newsletter system provides automated weekly security intelligence digests for the AI developer community. It features a complete subscription management system, responsive email templates, and automated content curation.

## Architecture

### Components

1. **Email Service** (`api/services/email_service.py`)
   - Subscription management with GDPR compliance
   - Resend integration for reliable delivery
   - Template rendering with Jinja2
   - Campaign creation and tracking

2. **Database Schema** (`api/migrations/007_email_subscriptions.sql`)
   - `email_subscriptions` - Subscriber management with preferences
   - `email_campaigns` - Campaign tracking and analytics
   - `email_sends` - Individual email delivery tracking
   - `weekly_digest_cache` - Generated content caching
   - `unsubscribe_log` - Audit trail for unsubscribes

3. **API Endpoints** (`api/routers/email.py`)
   - `/email/subscribe` - Newsletter subscription
   - `/email/unsubscribe/{token}` - Unsubscribe page and processing
   - `/email/preferences` - Update subscription preferences
   - `/email/digest/preview` - Preview digest content
   - `/email/campaign` - Create and send campaigns (admin)
   - `/email/stats` - Analytics and metrics (admin)

4. **Email Templates** (`api/templates/email/`)
   - `base.html` - Responsive base template with Sigil branding
   - `weekly_digest.html` - Weekly digest template
   - `welcome.html` - Welcome email for new subscribers

5. **Background Jobs** (`api/jobs/email_jobs.py`)
   - Weekly digest generation and sending
   - Scheduled campaign processing
   - Data cleanup and maintenance

6. **Automation Scripts** (`scripts/`)
   - `setup-email-cron.sh` - Configure cron jobs
   - `test-email-system.sh` - Validate system functionality

## Features

### Subscription Management
- **GDPR Compliant**: Secure unsubscribe tokens, preference management
- **Granular Preferences**: Security alerts, tool discoveries, weekly digest, product updates
- **Double Opt-in**: Confirmation emails for new subscribers
- **Source Tracking**: Track subscription sources (forge, api, dashboard)

### Email Delivery
- **Resend Integration**: Professional email delivery with tracking
- **Responsive Templates**: Mobile-optimized HTML emails
- **Personalization**: Dynamic content based on user preferences
- **Analytics**: Open rates, click tracking, bounce handling

### Content Curation
- **Automated Discovery**: New tools and security alerts from the past week
- **Trust Score Analysis**: Notable trust score changes and trending categories
- **Community Highlights**: Featured content and discussions
- **Metrics Dashboard**: Weekly activity statistics

## Configuration

### Environment Variables

Add these to your `.env` file:

```bash
# Required for email sending
SIGIL_RESEND_API_KEY=re_your_resend_api_key_here

# Email sender configuration
SIGIL_FROM_EMAIL=noreply@sigilsec.ai
SIGIL_FROM_NAME="Sigil Security"

# Base URL for email links
SIGIL_BASE_URL=https://api.sigilsec.ai
```

### Resend Setup

1. Create a Resend account at [resend.com](https://resend.com)
2. Add and verify your sending domain
3. Generate an API key
4. Configure webhook endpoints for event tracking (optional)

## Installation & Setup

### 1. Database Migration

Run the email tables migration:

```bash
# Apply the migration
python3 -c "
import asyncio
from api.database import run_migration
asyncio.run(run_migration('007_email_subscriptions.sql'))
"
```

### 2. Test System Components

```bash
# Run comprehensive tests
./scripts/test-email-system.sh
```

### 3. Configure Automation

```bash
# Set up cron jobs for automation
./scripts/setup-email-cron.sh
```

### 4. Test Email Sending

```bash
# Send test digest to your email
python3 api/jobs/email_jobs.py test_digest your@email.com

# Generate weekly digest (test mode)
python3 api/jobs/email_jobs.py weekly_digest --test
```

## Usage

### API Integration

#### Subscribe User
```python
import requests

response = requests.post('https://api.sigilsec.ai/email/subscribe', json={
    'email': 'user@example.com',
    'preferences': {
        'security_alerts': True,
        'tool_discoveries': True,
        'weekly_digest': True,
        'product_updates': False
    },
    'source': 'forge'
})
```

#### Create Campaign (Admin)
```python
from datetime import datetime
from api.models import EmailCampaignRequest, WeeklyDigestContent

# Generate content
content = await email_service.generate_weekly_digest(datetime.now())

# Create campaign
campaign = EmailCampaignRequest(
    subject="Forge Weekly - New Tools & Security Alerts",
    content=content,
    send_at=datetime.now(),
    test_mode=False
)

response = await email_service.create_email_campaign(campaign)
```

### Frontend Integration

#### Subscription Form
```typescript
// Subscribe to newsletter
const subscribeToNewsletter = async (email: string) => {
  const response = await fetch('/api/email/subscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      source: 'forge',
      preferences: {
        security_alerts: true,
        tool_discoveries: true,
        weekly_digest: true,
        product_updates: true
      }
    })
  });
  
  return response.json();
};
```

#### Unsubscribe Handling
```typescript
// Handle unsubscribe
const unsubscribe = async (token: string, reason?: string) => {
  const response = await fetch('/api/email/unsubscribe', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, reason })
  });
  
  return response.json();
};
```

## Automation Schedule

### Cron Jobs
- **Weekly Digest**: Every Sunday at 9:00 AM
- **Campaign Processing**: Every hour (for scheduled campaigns)  
- **Data Cleanup**: Every Monday at 2:00 AM (removes old tracking data)

### Manual Commands
```bash
# Generate and send weekly digest
python3 api/jobs/email_jobs.py weekly_digest

# Process scheduled campaigns
python3 api/jobs/email_jobs.py process_campaigns

# Clean up old data (90 days)
python3 api/jobs/email_jobs.py cleanup --days=90

# Send test digest
python3 api/jobs/email_jobs.py test_digest user@example.com
```

## Email Content

### Weekly Digest Structure
1. **Header**: Weekly metrics and activity summary
2. **Security Alerts**: Critical threats and vulnerabilities  
3. **New Tool Discoveries**: Recently analyzed tools with trust scores
4. **Trending Categories**: Most active tool categories
5. **Trust Score Changes**: Notable security score updates
6. **Community Highlights**: Featured discussions and contributions
7. **Call to Action**: Security best practices and platform features

### Content Sources
- **New Tools**: From forge_tools table (last 7 days)
- **Security Alerts**: From feed_items with type 'security_alert'
- **Trust Changes**: Tools with significant trust score deltas
- **Metrics**: Aggregated scan counts, discoveries, subscriber stats
- **Community**: Placeholder for future community features

## Analytics & Monitoring

### Email Metrics
- **Subscriber Growth**: Daily/weekly subscription rates
- **Engagement**: Open rates, click-through rates  
- **Deliverability**: Bounce rates, spam complaints
- **Content Performance**: Most clicked sections and links

### Admin Dashboard
Access via `/email/stats` endpoint (admin authentication required):
- Active subscriber count and retention rate
- Campaign performance statistics
- Recent campaign list with metrics
- Unsubscribe reasons and trends

### Resend Webhooks
Configure webhooks for real-time tracking:
```
POST /api/email/webhook/resend
```

Tracks: email.sent, email.opened, email.clicked, email.bounced, email.complaint events

## Security & Compliance

### GDPR Compliance
- **Explicit Consent**: Clear subscription confirmation
- **Right to Erasure**: Secure unsubscribe with token validation
- **Data Minimization**: Only collect necessary subscription data
- **Audit Trail**: Complete unsubscribe logging

### Security Features  
- **Token-based Unsubscribe**: Cryptographically secure tokens (32 bytes)
- **Rate Limiting**: Email subscription rate limits (5 requests/hour)
- **Input Validation**: Email format validation and sanitization
- **Content Security**: XSS protection in email templates

### Privacy Protection
- **No Tracking Pixels**: Optional open tracking via Resend
- **Secure Storage**: Encrypted database storage
- **Minimal Retention**: Automatic cleanup of old tracking data
- **Transparent Privacy**: Clear privacy policy and data usage

## Troubleshooting

### Common Issues

#### Emails Not Sending
```bash
# Check Resend configuration
python3 -c "from api.config import settings; print(f'Resend configured: {settings.resend_configured}')"

# Test API connectivity
curl -X POST https://api.resend.com/emails \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"from":"noreply@sigilsec.ai","to":["test@example.com"],"subject":"Test","html":"<p>Test email</p>"}'
```

#### Template Rendering Errors
```bash
# Check template directory
ls -la api/templates/email/

# Test template rendering
python3 -c "
from api.services.email_service import EmailService
import asyncio
service = EmailService()
html = asyncio.run(service._render_email_template('welcome.html', {'email': 'test@example.com', 'unsubscribe_url': '#', 'base_url': 'https://api.sigilsec.ai'}))
print('Template rendered successfully' if html else 'Template rendering failed')
"
```

#### Database Issues
```bash
# Check email tables
python3 -c "
import asyncio
import asyncpg
import os

async def check_tables():
    conn = await asyncpg.connect(os.environ['SIGIL_DATABASE_URL'])
    tables = await conn.fetch('SELECT table_name FROM information_schema.tables WHERE table_schema = \\'public\\' AND table_name LIKE \\'email_%\\'')
    print('Email tables:', [row['table_name'] for row in tables])
    await conn.close()

asyncio.run(check_tables())
"
```

#### Cron Job Issues
```bash
# Check cron jobs
crontab -l | grep -A 5 "Forge Weekly"

# Test cron environment
env -i /bin/bash --login -c 'cd /path/to/sigil && python3 api/jobs/email_jobs.py weekly_digest --test'

# Check cron logs
grep CRON /var/log/syslog | tail -20
```

### Performance Optimization

#### Batch Processing
- Resend API supports batch sending for multiple recipients
- Jobs process emails in batches of 100 to avoid rate limits
- Background task processing prevents API timeouts

#### Caching
- Weekly digest content is cached to avoid regeneration
- Template compilation is cached in memory
- Redis caching for rate limiting and session data

#### Database Optimization
- Indexes on email, token, and timestamp columns
- Automatic cleanup of old tracking data
- Optimized queries for subscriber counts and metrics

## Future Enhancements

### Planned Features
1. **A/B Testing**: Subject line and content testing
2. **Personalization**: User-specific content based on interests
3. **Segmentation**: Targeted campaigns based on user behavior
4. **Social Integration**: Share buttons and social proof
5. **Advanced Analytics**: Cohort analysis and engagement scoring

### Integration Opportunities
1. **Community Platform**: User-generated content in digests
2. **GitHub Integration**: Repository security alerts
3. **Marketplace Integration**: Tool recommendation engine
4. **AI Assistant**: LLM-powered content curation

---

## Support

For technical support or feature requests:
- Check the [troubleshooting guide](#troubleshooting)
- Review system logs and error messages
- Test individual components with provided scripts
- Contact the development team with specific error details