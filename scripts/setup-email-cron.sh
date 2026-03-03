#!/bin/bash
set -e

# Setup Email Automation Cron Jobs
# This script configures cron jobs for automated email sending

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_PATH="${PROJECT_ROOT}/venv/bin/python"

# Check if we're in a virtual environment or use system python
if [[ -z "$VIRTUAL_ENV" ]]; then
    if [[ -f "$PYTHON_PATH" ]]; then
        PYTHON_CMD="$PYTHON_PATH"
    else
        PYTHON_CMD="python3"
    fi
else
    PYTHON_CMD="python3"
fi

echo "🔧 Setting up Forge Weekly email automation..."
echo "Project root: $PROJECT_ROOT"
echo "Python command: $PYTHON_CMD"

# Create cron jobs
CRON_JOBS=$(cat << EOF
# Forge Weekly Email Automation
# Send weekly digest every Sunday at 9 AM
0 9 * * 0 cd $PROJECT_ROOT && $PYTHON_CMD api/jobs/email_jobs.py weekly_digest

# Process scheduled campaigns every hour
0 * * * * cd $PROJECT_ROOT && $PYTHON_CMD api/jobs/email_jobs.py process_campaigns

# Clean up old email data weekly on Monday at 2 AM
0 2 * * 1 cd $PROJECT_ROOT && $PYTHON_CMD api/jobs/email_jobs.py cleanup --days=90

EOF
)

# Backup existing crontab
echo "📋 Backing up existing crontab..."
crontab -l > "$PROJECT_ROOT/crontab.backup" 2>/dev/null || echo "No existing crontab found"

# Add new cron jobs
echo "⏰ Adding email automation cron jobs..."
(crontab -l 2>/dev/null || echo "") | grep -v "Forge Weekly Email Automation" | grep -v "weekly_digest" | grep -v "process_campaigns" > temp_cron
echo "$CRON_JOBS" >> temp_cron
crontab temp_cron
rm temp_cron

echo "✅ Email automation cron jobs installed successfully!"
echo ""
echo "📋 Current cron jobs:"
crontab -l | grep -A 10 "Forge Weekly"

echo ""
echo "🧪 To test the setup:"
echo "  1. Test email generation:"
echo "     $PYTHON_CMD api/jobs/email_jobs.py test_digest test@example.com"
echo ""
echo "  2. Generate weekly digest (test mode):"
echo "     $PYTHON_CMD api/jobs/email_jobs.py weekly_digest --test"
echo ""
echo "  3. Process scheduled campaigns:"
echo "     $PYTHON_CMD api/jobs/email_jobs.py process_campaigns"
echo ""

echo "📧 Email automation is now configured to:"
echo "  • Send Forge Weekly every Sunday at 9 AM"
echo "  • Process scheduled campaigns every hour"
echo "  • Clean up old data every Monday at 2 AM"
echo ""

echo "⚙️ Environment requirements:"
echo "  • SENDGRID_API_KEY: Your SendGrid API key"
echo "  • FROM_EMAIL: Sender email address (default: noreply@sigilsec.ai)"
echo "  • BASE_URL: Base URL for links (default: https://api.sigilsec.ai)"
echo ""

# Create environment template if it doesn't exist
ENV_FILE="$PROJECT_ROOT/.env.email"
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" << 'EOF'
# Email Service Configuration for Forge Weekly
# Copy these variables to your main .env file

# Resend API Key (required for email sending)
SIGIL_RESEND_API_KEY=re_your_resend_api_key_here

# Sender email configuration
FROM_EMAIL=noreply@sigilsec.ai
FROM_NAME="Sigil Security"

# Base URL for email links
BASE_URL=https://api.sigilsec.ai

# Database connection (should already be configured)
# DATABASE_URL=your_database_url

EOF
    echo "📄 Created email environment template at $ENV_FILE"
    echo "   Please update with your Resend API key and other settings."
fi

echo ""
echo "🎯 Next steps:"
echo "  1. Configure Resend API key in your .env file"
echo "  2. Test email functionality with the commands above"
echo "  3. Monitor cron job execution in system logs"
echo "  4. Email subscribers will receive their first digest next Sunday"