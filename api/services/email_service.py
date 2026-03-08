"""
Sigil Email Service

Handles email subscriptions, newsletter generation, and delivery for Forge Weekly.
Integrates with SendGrid for reliable email delivery with tracking and analytics.
"""

import asyncio
import json
import logging
import secrets
from datetime import datetime, timedelta

import aiohttp
from jinja2 import Environment, FileSystemLoader

from api.database import db
from api.models import (
    EmailCampaignRequest,
    EmailCampaignResponse,
    EmailSubscriptionRequest,
    EmailSubscriptionResponse,
    UnsubscribeRequest,
    UnsubscribeResponse,
    WeeklyDigestContent,
)
from api.config import settings

logger = logging.getLogger(__name__)


class EmailService:
    """Manages email subscriptions and campaign delivery."""

    def __init__(self):
        self.settings = settings
        self.resend_api_key = self.settings.resend_api_key
        self.from_email = self.settings.from_email
        self.from_name = self.settings.from_name
        self.base_url = self.settings.base_url

        # Initialize Jinja2 for email templates
        template_dir = "api/templates/email"
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir), autoescape=True
        )

    async def subscribe_email(
        self, request: EmailSubscriptionRequest
    ) -> EmailSubscriptionResponse:
        """Subscribe an email to Forge Weekly newsletter."""
        # Use db directly (it's already connected)
        # Generate unsubscribe token
        unsubscribe_token = secrets.token_urlsafe(32)

        # Check if email already exists
        existing = await db.fetchrow(
            "SELECT id, is_active FROM email_subscriptions WHERE email = $1",
            request.email,
        )

        if existing:
            if existing["is_active"]:
                return EmailSubscriptionResponse(
                    success=True,
                    message="Email already subscribed to Forge Weekly",
                    email=request.email,
                    preferences=request.preferences,
                    unsubscribe_token="",  # Don't expose existing token
                )
            else:
                # Reactivate subscription
                await db.execute(
                    """
                    UPDATE email_subscriptions 
                    SET is_active = true, preferences = $1, updated_at = NOW()
                    WHERE email = $2
                """,
                    json.dumps(request.preferences),
                    request.email,
                )
        else:
            # Insert new subscription
            await db.execute(
                """
                INSERT INTO email_subscriptions (email, preferences, unsubscribe_token, source)
                VALUES ($1, $2, $3, $4)
            """,
                request.email,
                json.dumps(request.preferences),
                unsubscribe_token,
                request.source,
            )

            # Send welcome email
        await self._send_welcome_email(request.email, unsubscribe_token)

        return EmailSubscriptionResponse(
            success=True,
            message="Successfully subscribed to Forge Weekly",
            email=request.email,
            preferences=request.preferences,
            unsubscribe_token=unsubscribe_token,
        )

    async def unsubscribe_email(
        self, request: UnsubscribeRequest
    ) -> UnsubscribeResponse:
        """Unsubscribe an email using the unsubscribe token."""
        # Use db directly (it's already connected)
        # Find subscription by token
        subscription = await db.fetchrow(
            "SELECT email FROM email_subscriptions WHERE unsubscribe_token = $1",
            request.token,
        )

        if not subscription:
            return UnsubscribeResponse(
                success=False, message="Invalid unsubscribe token"
            )

            # Deactivate subscription
        await db.execute(
            "UPDATE email_subscriptions SET is_active = false WHERE unsubscribe_token = $1",
            request.token,
        )

        # Log unsubscribe
        await db.execute(
            """
            INSERT INTO unsubscribe_log (email, unsubscribe_token, reason)
            VALUES ($1, $2, $3)
        """,
            subscription["email"],
            request.token,
            request.reason,
        )

        return UnsubscribeResponse(
            success=True, message="Successfully unsubscribed from all emails"
        )

    async def generate_weekly_digest(
        self, week_ending: datetime
    ) -> WeeklyDigestContent:
        """Generate weekly digest content by aggregating data from the past week."""
        # Use db directly (it's already connected)
        week_start = week_ending - timedelta(days=7)

        # Get new tool discoveries
        new_tools_rows = await db.fetch(
            """
            SELECT name, description, category, trust_score, discovered_at
            FROM forge_tools 
            WHERE discovered_at >= $1 AND discovered_at < $2
            ORDER BY trust_score DESC, discovered_at DESC
            LIMIT 10
        """,
            week_start,
            week_ending,
        )

        new_tools = [dict(row) for row in new_tools_rows]

        # Get security alerts from feeds
        security_alerts_rows = await db.fetch(
            """
            SELECT title, description, severity, published_at
            FROM feed_items 
            WHERE feed_type = 'security_alert' 
            AND published_at >= $1 AND published_at < $2
            ORDER BY published_at DESC
            LIMIT 10
        """,
            week_start,
            week_ending,
        )

        security_alerts = [dict(row) for row in security_alerts_rows]

        # Get trending categories
        trending_rows = await db.fetch(
            """
            SELECT category, COUNT(*) as tool_count, 
                   AVG(trust_score) as avg_trust_score
            FROM forge_tools 
            WHERE discovered_at >= $1 AND discovered_at < $2
            GROUP BY category
            ORDER BY tool_count DESC, avg_trust_score DESC
            LIMIT 5
        """,
            week_start,
            week_ending,
        )

        trending_categories = [dict(row) for row in trending_rows]

        # Get notable trust score changes
        trust_changes_rows = await db.fetch(
            """
            SELECT name, trust_score, previous_trust_score, 
                   (trust_score - previous_trust_score) as change
            FROM forge_tools 
            WHERE trust_score_updated_at >= $1 AND trust_score_updated_at < $2
            AND ABS(trust_score - previous_trust_score) >= 10
            ORDER BY ABS(trust_score - previous_trust_score) DESC
            LIMIT 5
        """,
            week_start,
            week_ending,
        )

        trust_score_changes = [dict(row) for row in trust_changes_rows]

        # Get weekly metrics
        metrics_row = await db.fetchrow(
            """
            SELECT 
                COUNT(DISTINCT CASE WHEN ps.created_at >= $1 THEN ps.id END) as scans_this_week,
                COUNT(DISTINCT CASE WHEN ft.discovered_at >= $1 THEN ft.id END) as tools_discovered,
                COUNT(DISTINCT CASE WHEN fi.published_at >= $1 THEN fi.id END) as security_alerts,
                COUNT(DISTINCT es.email) as active_subscribers
            FROM public_scans ps
            CROSS JOIN forge_tools ft
            CROSS JOIN feed_items fi
            CROSS JOIN email_subscriptions es
            WHERE es.is_active = true
        """,
            week_start,
        )

        metrics = dict(metrics_row) if metrics_row else {}

        # Community highlights (placeholder - would integrate with actual community features)
        community_highlights = [
            {
                "title": "Community Spotlight",
                "content": "Featured community contributions and discussions",
            },
            {
                "title": "Tool of the Week",
                "content": "Community-voted tool recommendation",
            },
        ]

        return WeeklyDigestContent(
            week_ending=week_ending,
            new_tools=new_tools,
            security_alerts=security_alerts,
            trending_categories=trending_categories,
            trust_score_changes=trust_score_changes,
            community_highlights=community_highlights,
            metrics=metrics,
        )

    async def create_email_campaign(
        self, request: EmailCampaignRequest
    ) -> EmailCampaignResponse:
        """Create and optionally send an email campaign."""
        # Use db directly (it's already connected)
        campaign_id = secrets.token_urlsafe(16)

        # Get subscriber count
        subscriber_count = await db.fetchval("""
            SELECT COUNT(*) FROM email_subscriptions 
            WHERE is_active = true 
            AND preferences->>'weekly_digest' = 'true'
        """)

        # Set send time
        send_time = request.send_at or datetime.utcnow()

        # Insert campaign
        await db.execute(
            """
            INSERT INTO email_campaigns (
                campaign_id, subject, content_json, recipient_count, 
                scheduled_for, status
            ) VALUES ($1, $2, $3, $4, $5, $6)
        """,
            campaign_id,
            request.subject,
            json.dumps(request.content.dict()),
            subscriber_count,
            send_time,
            "test" if request.test_mode else "scheduled",
        )

        # If not test mode and send time is now or past, send immediately
        if not request.test_mode and send_time <= datetime.utcnow():
            await self._send_campaign(campaign_id)

        return EmailCampaignResponse(
            campaign_id=campaign_id,
            scheduled_for=send_time,
            recipient_count=subscriber_count if not request.test_mode else 1,
            status="sent" if send_time <= datetime.utcnow() else "scheduled",
        )

    async def _send_campaign(self, campaign_id: str) -> None:
        """Send an email campaign to all subscribers."""
        # Use db directly (it's already connected)
        # Get campaign details
        campaign = await db.fetchrow(
            "SELECT * FROM email_campaigns WHERE campaign_id = $1", campaign_id
        )

        if not campaign or campaign["status"] != "scheduled":
            logger.error(f"Campaign {campaign_id} not found or not scheduled")
            return

            # Get active subscribers
        subscribers = await db.fetch("""
            SELECT email, unsubscribe_token 
            FROM email_subscriptions 
            WHERE is_active = true 
            AND preferences->>'weekly_digest' = 'true'
        """)

        if not subscribers:
            logger.warning(f"No active subscribers for campaign {campaign_id}")
            return

            # Parse content
        content = WeeklyDigestContent(**json.loads(campaign["content_json"]))

        # Generate HTML email
        html_content = await self._render_email_template(
            "weekly_digest.html",
            {
                "subject": campaign["subject"],
                "content": content,
                "base_url": self.base_url,
            },
        )

        # Send emails in batches
        batch_size = 100
        sent_count = 0

        for i in range(0, len(subscribers), batch_size):
            batch = subscribers[i : i + batch_size]

            tasks = []
            for subscriber in batch:
                unsubscribe_url = f"{self.base_url}/email/unsubscribe/{subscriber['unsubscribe_token']}"

                # Personalize email with unsubscribe link
                personalized_html = html_content.replace(
                    "{{unsubscribe_url}}", unsubscribe_url
                ).replace("{{email}}", subscriber["email"])

                task = self._send_email_via_resend(
                    to_email=subscriber["email"],
                    subject=campaign["subject"],
                    html_content=personalized_html,
                    campaign_id=campaign_id,
                )
                tasks.append(task)

                # Send batch
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Track sends
            for j, result in enumerate(results):
                subscriber = batch[j]
                if not isinstance(result, Exception):
                    await db.execute(
                        """
                        INSERT INTO email_sends (campaign_id, email, status)
                        VALUES ($1, $2, $3)
                    """,
                        campaign_id,
                        subscriber["email"],
                        "sent",
                    )
                    sent_count += 1
                else:
                    logger.error(f"Failed to send to {subscriber['email']}: {result}")
                    await db.execute(
                        """
                        INSERT INTO email_sends (campaign_id, email, status)
                        VALUES ($1, $2, $3)
                    """,
                        campaign_id,
                        subscriber["email"],
                        "failed",
                    )

                # Small delay between batches to avoid rate limits
            await asyncio.sleep(1)

            # Update campaign status
        await db.execute(
            """
            UPDATE email_campaigns 
            SET status = 'sent', sent_at = NOW(), sent_count = $1
            WHERE campaign_id = $2
        """,
            sent_count,
            campaign_id,
        )

        logger.info(f"Campaign {campaign_id} sent to {sent_count} subscribers")

    async def _send_email_via_resend(
        self, to_email: str, subject: str, html_content: str, campaign_id: str = None
    ) -> bool:
        """Send an email via Resend API."""
        if not self.resend_api_key:
            logger.warning("Resend API key not configured, skipping email send")
            return False

        headers = {
            "Authorization": f"Bearer {self.resend_api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "from": f"{self.from_name} <{self.from_email}>",
            "to": [to_email],
            "subject": subject,
            "html": html_content,
        }

        if campaign_id:
            payload["tags"] = [{"name": "campaign_id", "value": campaign_id}]

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://api.resend.com/emails",
                    headers=headers,
                    json=payload,
                    timeout=30,
                ) as response:
                    if response.status in [200, 201]:
                        response_data = await response.json()
                        logger.info(
                            f"Email sent successfully via Resend: {response_data.get('id')}"
                        )
                        return True
                    else:
                        error_text = await response.text()
                        logger.error(f"Resend error {response.status}: {error_text}")
                        return False

        except Exception as e:
            logger.error(f"Error sending email via Resend: {e}")
            return False

    async def _send_welcome_email(self, email: str, unsubscribe_token: str) -> None:
        """Send welcome email to new subscriber."""
        subject = "Welcome to Forge Weekly - Your AI Security Intelligence"

        unsubscribe_url = f"{self.base_url}/email/unsubscribe/{unsubscribe_token}"

        html_content = await self._render_email_template(
            "welcome.html",
            {
                "email": email,
                "unsubscribe_url": unsubscribe_url,
                "base_url": self.base_url,
            },
        )

        await self._send_email_via_resend(email, subject, html_content)

    async def _render_email_template(self, template_name: str, context: dict) -> str:
        """Render Jinja2 email template with context."""
        try:
            template = self.jinja_env.get_template(template_name)
            return template.render(**context)
        except Exception as e:
            logger.error(f"Error rendering template {template_name}: {e}")
            # Fallback to basic HTML
            return f"""
        <html>
            <body>
                <h1>Forge Weekly Update</h1>
                <p>Your weekly AI security intelligence digest.</p>
                <p><a href="{context.get("unsubscribe_url", "#")}">Unsubscribe</a></p>
            </body>
        </html>
        """

    async def process_scheduled_campaigns(self) -> None:
        """Process and send scheduled campaigns (called by cron job)."""
        # Use db directly (it's already connected)
        # Find campaigns ready to send
        campaigns = await db.fetch("""
            SELECT campaign_id FROM email_campaigns 
            WHERE status = 'scheduled' 
            AND scheduled_for <= NOW()
            ORDER BY scheduled_for ASC
        """)

        for campaign in campaigns:
            try:
                await self._send_campaign(campaign["campaign_id"])
            except Exception as e:
                logger.error(f"Error sending campaign {campaign['campaign_id']}: {e}")
                # Mark campaign as failed
                await db.execute(
                    """
                    UPDATE email_campaigns 
                    SET status = 'failed' 
                    WHERE campaign_id = $1
                """,
                    campaign["campaign_id"],
                )


# Global email service instance
email_service = EmailService()
