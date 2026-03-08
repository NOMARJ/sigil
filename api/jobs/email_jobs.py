"""
Email Background Jobs

Handles scheduled email campaigns, digest generation, and automation.
Designed to be run by a cron job or task scheduler.
"""

import asyncio
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add the parent directory to the path so we can import from api
sys.path.append(str(Path(__file__).parent.parent))

from api.services.email_service import email_service
from models import EmailCampaignRequest
from database import get_database_client

logger = logging.getLogger(__name__)


class EmailJobRunner:
    """Handles automated email job execution."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    async def generate_and_send_weekly_digest(self, test_mode: bool = False) -> None:
        """Generate and send the weekly digest email."""
        try:
            # Calculate last Sunday as week ending date
            today = datetime.now().date()
            days_since_sunday = (today.weekday() + 1) % 7
            if days_since_sunday == 0:  # Today is Sunday
                week_ending = datetime.combine(today, datetime.min.time())
            else:
                last_sunday = today - timedelta(days=days_since_sunday)
                week_ending = datetime.combine(last_sunday, datetime.min.time())

            self.logger.info(
                f"Generating weekly digest for week ending {week_ending.date()}"
            )

            # Check if we already sent a digest for this week
            async with get_database_client() as db:
                existing = await db.fetchval(
                    """
                    SELECT campaign_id FROM email_campaigns 
                    WHERE content_json->>'week_ending' = $1 
                    AND status IN ('sent', 'scheduled')
                """,
                    week_ending.isoformat(),
                )

                if existing and not test_mode:
                    self.logger.info(
                        f"Weekly digest already sent for {week_ending.date()}"
                    )
                    return

            # Generate digest content
            content = await email_service.generate_weekly_digest(week_ending)

            # Create subject line with dynamic content
            subject_parts = ["Forge Weekly"]

            if content.new_tools:
                subject_parts.append(f"🔍 {len(content.new_tools)} New Tools")

            if content.security_alerts:
                alert_count = len(content.security_alerts)
                if alert_count > 0:
                    subject_parts.append(
                        f"🚨 {alert_count} Security Alert{'s' if alert_count > 1 else ''}"
                    )

            if len(subject_parts) == 1:  # No dynamic content
                subject_parts.append(f"Week of {content.week_ending.strftime('%b %d')}")

            subject = " • ".join(subject_parts)

            # Create campaign request
            campaign_request = EmailCampaignRequest(
                subject=subject,
                content=content,
                send_at=datetime.now()
                if test_mode
                else None,  # Send immediately in test mode
                test_mode=test_mode,
            )

            # Send campaign
            response = await email_service.create_email_campaign(campaign_request)

            self.logger.info(f"Weekly digest campaign created: {response.campaign_id}")
            self.logger.info(f"Scheduled for: {response.scheduled_for}")
            self.logger.info(f"Recipients: {response.recipient_count}")

            # Cache the content for future reference
            async with get_database_client() as db:
                await db.execute(
                    """
                    INSERT INTO weekly_digest_cache (week_ending, content_json, is_current)
                    VALUES ($1, $2, true)
                    ON CONFLICT (week_ending) DO UPDATE SET
                    content_json = EXCLUDED.content_json,
                    generated_at = NOW(),
                    is_current = EXCLUDED.is_current
                """,
                    week_ending.date(),
                    content.json(),
                )

                # Mark previous digests as not current
                await db.execute(
                    """
                    UPDATE weekly_digest_cache 
                    SET is_current = false 
                    WHERE week_ending != $1
                """,
                    week_ending.date(),
                )

        except Exception as e:
            self.logger.error(f"Error generating weekly digest: {e}")
            raise

    async def process_scheduled_campaigns(self) -> None:
        """Process any scheduled email campaigns that are ready to send."""
        try:
            await email_service.process_scheduled_campaigns()
            self.logger.info("Processed scheduled campaigns")
        except Exception as e:
            self.logger.error(f"Error processing scheduled campaigns: {e}")
            raise

    async def cleanup_old_data(self, days_to_keep: int = 90) -> None:
        """Clean up old email tracking data."""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)

            async with get_database_client() as db:
                # Clean up old email sends
                deleted_sends = await db.fetchval(
                    """
                    DELETE FROM email_sends 
                    WHERE sent_at < $1
                    RETURNING count(*)
                """,
                    cutoff_date,
                )

                # Clean up old campaigns (but keep recent analytics)
                deleted_campaigns = await db.fetchval(
                    """
                    DELETE FROM email_campaigns 
                    WHERE created_at < $1 AND status = 'sent'
                    RETURNING count(*)
                """,
                    cutoff_date,
                )

                # Clean up old digest cache
                deleted_cache = await db.fetchval(
                    """
                    DELETE FROM weekly_digest_cache 
                    WHERE generated_at < $1 AND is_current = false
                    RETURNING count(*)
                """,
                    cutoff_date,
                )

                self.logger.info("Cleanup completed:")
                self.logger.info(f"  - Deleted {deleted_sends or 0} old email sends")
                self.logger.info(f"  - Deleted {deleted_campaigns or 0} old campaigns")
                self.logger.info(
                    f"  - Deleted {deleted_cache or 0} old digest cache entries"
                )

        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            raise

    async def send_test_digest(self, test_email: str) -> None:
        """Send a test digest to a specific email address."""
        try:
            # Generate content for current week
            week_ending = datetime.now()
            content = await email_service.generate_weekly_digest(week_ending)

            # Override subscription check for test
            async with get_database_client() as db:
                # Temporarily add test email if it doesn't exist
                await db.execute(
                    """
                    INSERT INTO email_subscriptions (email, source, is_active)
                    VALUES ($1, 'test', true)
                    ON CONFLICT (email) DO NOTHING
                """,
                    test_email,
                )

            # Create test campaign
            campaign_request = EmailCampaignRequest(
                subject=f"[TEST] Forge Weekly - {week_ending.strftime('%B %d, %Y')}",
                content=content,
                send_at=datetime.now(),
                test_mode=True,
            )

            response = await email_service.create_email_campaign(campaign_request)

            self.logger.info(f"Test digest sent to {test_email}")
            self.logger.info(f"Campaign ID: {response.campaign_id}")

        except Exception as e:
            self.logger.error(f"Error sending test digest: {e}")
            raise


async def main():
    """Main entry point for email jobs."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    runner = EmailJobRunner()

    if len(sys.argv) < 2:
        print("Usage: python email_jobs.py <command> [args]")
        print("Commands:")
        print("  weekly_digest [--test]       Generate and send weekly digest")
        print("  process_campaigns           Process scheduled campaigns")
        print("  cleanup [--days=90]         Clean up old email data")
        print("  test_digest <email>         Send test digest to email")
        sys.exit(1)

    command = sys.argv[1]

    try:
        if command == "weekly_digest":
            test_mode = "--test" in sys.argv
            await runner.generate_and_send_weekly_digest(test_mode=test_mode)

        elif command == "process_campaigns":
            await runner.process_scheduled_campaigns()

        elif command == "cleanup":
            days_to_keep = 90
            for arg in sys.argv[2:]:
                if arg.startswith("--days="):
                    days_to_keep = int(arg.split("=")[1])
            await runner.cleanup_old_data(days_to_keep)

        elif command == "test_digest":
            if len(sys.argv) < 3:
                print("Error: test_digest requires an email address")
                sys.exit(1)
            test_email = sys.argv[2]
            await runner.send_test_digest(test_email)

        else:
            print(f"Unknown command: {command}")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Job failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
