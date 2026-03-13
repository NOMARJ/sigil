"""
Notification Service for Billing and Subscription Events
Handles email notifications for payment failures, subscription changes, etc.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from api.config import settings

logger = logging.getLogger(__name__)


class NotificationService:
    """Service for sending billing-related email notifications."""

    async def send_payment_failure_notification(
        self,
        user_email: str,
        user_name: str | None,
        attempt_count: int,
        amount: int,
        next_retry: Optional[datetime] = None,
    ) -> bool:
        """
        Send payment failure notification to user.

        Args:
            user_email: User's email address
            user_name: User's display name
            attempt_count: Number of failed attempts
            amount: Amount in cents
            next_retry: Next retry date if applicable

        Returns:
            True if email sent successfully, False otherwise
        """
        try:
            if not settings.smtp_configured and not settings.resend_configured:
                logger.warning(
                    "No email provider configured, skipping payment failure notification"
                )
                return False

            subject = "Payment Failed - Action Required for Your Sigil Pro Subscription"

            # Create email content
            amount_dollars = amount / 100
            name_part = f"Hi {user_name}," if user_name else "Hello,"

            if attempt_count <= 3:
                # Early failure notifications
                content = f"""
{name_part}

We were unable to process your payment of ${amount_dollars:.2f} for your Sigil Pro subscription.

This was attempt {attempt_count} of 3. Your Pro features remain active while we retry.

What happens next:
- We'll automatically retry your payment
- Your Pro features remain available during this period
- If all retries fail, you'll be downgraded to the free plan

To update your payment method:
1. Visit https://app.sigilsec.ai/settings/billing
2. Click "Manage Billing" to update your payment details

If you have any questions, reply to this email and we'll help you resolve this quickly.

Best regards,
The Sigil Team
"""
            else:
                # Final failure - downgrade notification
                content = f"""
{name_part}

Unfortunately, we were unable to process your payment of ${amount_dollars:.2f} after 3 attempts.

Your account has been downgraded to the free plan. Your Pro features are no longer available.

To restore your Pro subscription:
1. Visit https://app.sigilsec.ai/settings/billing
2. Update your payment method
3. Reactivate your Pro subscription

Your scan history and data remain safe and accessible.

Best regards,
The Sigil Team
"""

            return await self._send_email(user_email, subject, content)

        except Exception as e:
            logger.exception(f"Failed to send payment failure notification: {e}")
            return False

    async def send_payment_success_notification(
        self,
        user_email: str,
        user_name: str | None,
        amount: int,
        subscription_plan: str,
    ) -> bool:
        """Send payment success notification."""
        try:
            if not settings.smtp_configured and not settings.resend_configured:
                logger.warning(
                    "No email provider configured, skipping payment success notification"
                )
                return False

            subject = f"Payment Successful - Your Sigil {subscription_plan.title()} Subscription is Active"

            amount_dollars = amount / 100
            name_part = f"Hi {user_name}," if user_name else "Hello,"

            content = f"""
{name_part}

Great news! We've successfully processed your payment of ${amount_dollars:.2f}.

Your Sigil {subscription_plan.title()} subscription is now active and all features are available.

Your Pro features include:
- 5,000 monthly AI credits for security analysis
- AI-powered finding investigation
- False positive verification
- Interactive security chat
- Advanced threat detection

Get started: https://app.sigilsec.ai/

Best regards,
The Sigil Team
"""

            return await self._send_email(user_email, subject, content)

        except Exception as e:
            logger.exception(f"Failed to send payment success notification: {e}")
            return False

    async def send_subscription_cancelled_notification(
        self,
        user_email: str,
        user_name: str | None,
        cancellation_reason: str = "user_cancelled",
    ) -> bool:
        """Send subscription cancellation notification."""
        try:
            if not settings.smtp_configured and not settings.resend_configured:
                logger.warning(
                    "No email provider configured, skipping cancellation notification"
                )
                return False

            subject = "Your Sigil Pro Subscription Has Been Cancelled"

            name_part = f"Hi {user_name}," if user_name else "Hello,"

            content = f"""
{name_part}

Your Sigil Pro subscription has been cancelled and your account has been downgraded to the free plan.

What this means:
- Your Pro features are no longer available
- Your scan history and data remain accessible
- You can continue using Sigil with free plan limits

To reactivate your Pro subscription:
Visit https://app.sigilsec.ai/pricing to subscribe again.

We're sorry to see you go! If you have feedback on how we could improve, reply to this email.

Best regards,
The Sigil Team
"""

            return await self._send_email(user_email, subject, content)

        except Exception as e:
            logger.exception(f"Failed to send cancellation notification: {e}")
            return False

    async def send_trial_ending_notification(
        self, user_email: str, user_name: str | None, trial_end_date: datetime
    ) -> bool:
        """Send trial ending notification."""
        try:
            if not settings.smtp_configured and not settings.resend_configured:
                logger.warning(
                    "No email provider configured, skipping trial ending notification"
                )
                return False

            subject = "Your Sigil Pro Trial Ends Soon"

            name_part = f"Hi {user_name}," if user_name else "Hello,"
            trial_end_str = trial_end_date.strftime("%B %d, %Y")

            content = f"""
{name_part}

Your Sigil Pro trial ends on {trial_end_str}.

To continue enjoying Pro features like AI-powered security analysis:
1. Visit https://app.sigilsec.ai/pricing
2. Choose your plan
3. Complete your subscription

Don't lose access to:
- AI-powered finding investigation
- 5,000 monthly AI credits
- Advanced threat detection
- Interactive security chat

Subscribe now: https://app.sigilsec.ai/pricing

Best regards,
The Sigil Team
"""

            return await self._send_email(user_email, subject, content)

        except Exception as e:
            logger.exception(f"Failed to send trial ending notification: {e}")
            return False

    async def _send_email(self, to_email: str, subject: str, content: str) -> bool:
        """
        Send email using configured email provider.

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            if settings.resend_configured:
                return await self._send_via_resend(to_email, subject, content)
            elif settings.smtp_configured:
                return await self._send_via_smtp(to_email, subject, content)
            else:
                logger.warning("No email provider configured")
                return False

        except Exception as e:
            logger.exception(f"Failed to send email: {e}")
            return False

    async def _send_via_resend(self, to_email: str, subject: str, content: str) -> bool:
        """Send email via Resend API."""
        try:
            import resend

            resend.api_key = settings.resend_api_key

            params = {
                "from": f"{settings.from_name} <{settings.from_email}>",
                "to": [to_email],
                "subject": subject,
                "text": content,
            }

            result = resend.Emails.send(params)

            if result and result.get("id"):
                logger.info(f"Email sent via Resend: {result['id']} to {to_email}")
                return True
            else:
                logger.error(f"Failed to send email via Resend: {result}")
                return False

        except ImportError:
            logger.error("Resend package not installed")
            return False
        except Exception as e:
            logger.exception(f"Resend email failed: {e}")
            return False

    async def _send_via_smtp(self, to_email: str, subject: str, content: str) -> bool:
        """Send email via SMTP."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            msg = MIMEMultipart()
            msg["From"] = settings.smtp_from_email
            msg["To"] = to_email
            msg["Subject"] = subject

            msg.attach(MIMEText(content, "plain"))

            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
                server.starttls()
                server.login(settings.smtp_user, settings.smtp_password)
                server.send_message(msg)

            logger.info(f"Email sent via SMTP to {to_email}")
            return True

        except Exception as e:
            logger.exception(f"SMTP email failed: {e}")
            return False


# Global service instance
notification_service = NotificationService()
