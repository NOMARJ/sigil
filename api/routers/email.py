"""
Email Newsletter API Router

Handles Forge Weekly email subscriptions, unsubscribes, and campaign management.
Includes GDPR-compliant subscription management and analytics tracking.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query
from fastapi.responses import HTMLResponse

from api.dependencies import get_current_user, rate_limit
from api.models import (
    EmailSubscriptionRequest,
    EmailSubscriptionResponse,
    EmailPreferencesUpdate,
    EmailCampaignRequest,
    EmailCampaignResponse,
    UnsubscribeRequest,
    UnsubscribeResponse,
    WeeklyDigestContent,
    ErrorResponse
)
from api.services.email_service import email_service
from api.database import get_database_client

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/email", tags=["Email Newsletter"])


@router.post(
    "/subscribe",
    response_model=EmailSubscriptionResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Invalid email format"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"}
    }
)
async def subscribe_to_newsletter(
    request: EmailSubscriptionRequest,
    rate_limiter: None = Depends(rate_limit("email_subscribe", max_requests=5, window_seconds=3600))
) -> EmailSubscriptionResponse:
    """
    Subscribe to Forge Weekly newsletter.
    
    Subscribes an email address to receive weekly AI security intelligence digests.
    Includes tool discoveries, security alerts, and ecosystem updates.
    """
    try:
        return await email_service.subscribe_email(request)
    except Exception as e:
        logger.error(f"Error subscribing email {request.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process subscription"
        )


@router.get(
    "/unsubscribe/{token}",
    response_class=HTMLResponse,
    responses={
        404: {"description": "Invalid unsubscribe token"}
    }
)
async def unsubscribe_page(token: str) -> HTMLResponse:
    """
    Show unsubscribe confirmation page.
    
    Displays a user-friendly unsubscribe form with optional feedback.
    """
    # Validate token exists
    async with get_database_client() as db:
        subscription = await db.fetchrow(
            "SELECT email FROM email_subscriptions WHERE unsubscribe_token = $1",
            token
        )
    
    if not subscription:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invalid unsubscribe token"
        )
    
    # Return HTML unsubscribe form
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Unsubscribe - Forge Weekly</title>
        <style>
            body {{ 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 600px;
                margin: 0 auto;
                padding: 40px 20px;
                color: #333;
                line-height: 1.6;
            }}
            .logo {{ color: #6366f1; font-size: 24px; font-weight: bold; margin-bottom: 30px; }}
            .card {{ 
                background: #f8fafc;
                border: 1px solid #e2e8f0;
                border-radius: 8px;
                padding: 30px;
                margin-bottom: 20px;
            }}
            .btn {{ 
                background: #ef4444;
                color: white;
                padding: 12px 24px;
                border: none;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
                margin-right: 10px;
            }}
            .btn-secondary {{ 
                background: #6b7280;
                color: white;
            }}
            .form-group {{ margin-bottom: 20px; }}
            textarea {{ 
                width: 100%;
                padding: 12px;
                border: 1px solid #d1d5db;
                border-radius: 6px;
                resize: vertical;
                min-height: 100px;
            }}
            .success {{ 
                background: #dcfce7;
                border: 1px solid #bbf7d0;
                color: #166534;
                padding: 15px;
                border-radius: 6px;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="logo">🔒 Sigil Security</div>
        
        <div class="card">
            <h1>Unsubscribe from Forge Weekly</h1>
            <p>We're sorry to see you go! You're about to unsubscribe from Forge Weekly:</p>
            <p><strong>Email:</strong> {subscription['email']}</p>
            
            <form id="unsubscribeForm" onsubmit="return handleUnsubscribe()">
                <div class="form-group">
                    <label for="reason">Help us improve (optional):</label>
                    <textarea 
                        id="reason" 
                        name="reason"
                        placeholder="Tell us why you're unsubscribing..."
                    ></textarea>
                </div>
                
                <button type="submit" class="btn">Unsubscribe</button>
                <button type="button" class="btn btn-secondary" onclick="window.close()">
                    Keep Subscription
                </button>
            </form>
        </div>
        
        <div id="success" class="success" style="display: none;">
            <h3>✓ Successfully Unsubscribed</h3>
            <p>You have been removed from all email communications. Thank you for your feedback.</p>
        </div>
        
        <script>
            async function handleUnsubscribe() {{
                const reason = document.getElementById('reason').value;
                
                try {{
                    const response = await fetch('/api/email/unsubscribe', {{
                        method: 'POST',
                        headers: {{ 'Content-Type': 'application/json' }},
                        body: JSON.stringify({{ 
                            token: '{token}',
                            reason: reason 
                        }})
                    }});
                    
                    if (response.ok) {{
                        document.getElementById('unsubscribeForm').style.display = 'none';
                        document.getElementById('success').style.display = 'block';
                    }} else {{
                        alert('Error unsubscribing. Please try again.');
                    }}
                }} catch (error) {{
                    alert('Network error. Please try again.');
                }}
                
                return false;
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)


@router.post(
    "/unsubscribe",
    response_model=UnsubscribeResponse,
    responses={
        404: {"model": ErrorResponse, "description": "Invalid unsubscribe token"}
    }
)
async def unsubscribe_from_newsletter(
    request: UnsubscribeRequest
) -> UnsubscribeResponse:
    """
    Process unsubscribe request.
    
    Removes email from all newsletter communications and logs the unsubscribe reason.
    """
    try:
        return await email_service.unsubscribe_email(request)
    except Exception as e:
        logger.error(f"Error unsubscribing token {request.token}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process unsubscribe"
        )


@router.put(
    "/preferences",
    response_model=EmailSubscriptionResponse,
    dependencies=[Depends(get_current_user)]
)
async def update_email_preferences(
    request: EmailPreferencesUpdate,
    current_user: dict = Depends(get_current_user)
) -> EmailSubscriptionResponse:
    """
    Update email subscription preferences.
    
    Allows authenticated users to modify their newsletter preferences without unsubscribing.
    """
    user_email = current_user.get("email")
    if not user_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User email not found"
        )
    
    async with get_database_client() as db:
        # Update preferences
        result = await db.execute("""
            UPDATE email_subscriptions 
            SET preferences = $1, updated_at = NOW()
            WHERE email = $2 AND is_active = true
            RETURNING unsubscribe_token
        """, request.preferences, user_email)
        
        if result == "UPDATE 0":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Email subscription not found"
            )
        
        return EmailSubscriptionResponse(
            success=True,
            message="Email preferences updated successfully",
            email=user_email,
            preferences=request.preferences,
            unsubscribe_token=""  # Don't expose token
        )


@router.get(
    "/digest/preview",
    response_model=WeeklyDigestContent,
    dependencies=[Depends(get_current_user)]
)
async def preview_weekly_digest(
    week_ending: Optional[datetime] = Query(None, description="Week ending date (defaults to last Sunday)")
) -> WeeklyDigestContent:
    """
    Preview weekly digest content.
    
    Generates and returns the content for the weekly newsletter without sending it.
    Useful for testing and content review.
    """
    if not week_ending:
        # Default to last Sunday
        today = datetime.now().date()
        days_since_sunday = today.weekday() + 1
        if days_since_sunday == 7:
            days_since_sunday = 0
        week_ending = datetime.combine(
            today - timedelta(days=days_since_sunday), 
            datetime.min.time()
        )
    
    try:
        return await email_service.generate_weekly_digest(week_ending)
    except Exception as e:
        logger.error(f"Error generating digest preview: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate digest preview"
        )


@router.post(
    "/campaign",
    response_model=EmailCampaignResponse,
    dependencies=[Depends(get_current_user)]
)
async def create_email_campaign(
    request: EmailCampaignRequest,
    current_user: dict = Depends(get_current_user)
) -> EmailCampaignResponse:
    """
    Create and send email campaign.
    
    Creates a new email campaign with the provided content. Requires authentication.
    Can be scheduled for future delivery or sent immediately.
    """
    # Check if user has admin permissions (implement based on your auth system)
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permissions required"
        )
    
    try:
        return await email_service.create_email_campaign(request)
    except Exception as e:
        logger.error(f"Error creating email campaign: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create email campaign"
        )


@router.get(
    "/stats",
    dependencies=[Depends(get_current_user)]
)
async def get_email_stats(
    current_user: dict = Depends(get_current_user)
) -> dict:
    """
    Get email newsletter statistics.
    
    Returns subscriber counts, campaign performance, and engagement metrics.
    Requires authentication.
    """
    if not current_user.get("is_admin", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permissions required"
        )
    
    async with get_database_client() as db:
        stats = await db.fetchrow("""
            SELECT 
                COUNT(CASE WHEN is_active = true THEN 1 END) as active_subscribers,
                COUNT(CASE WHEN is_active = false THEN 1 END) as unsubscribed,
                COUNT(*) as total_subscriptions,
                AVG(CASE WHEN is_active = true THEN 1.0 ELSE 0.0 END) * 100 as retention_rate
            FROM email_subscriptions
        """)
        
        campaign_stats = await db.fetchrow("""
            SELECT 
                COUNT(*) as total_campaigns,
                COUNT(CASE WHEN status = 'sent' THEN 1 END) as sent_campaigns,
                SUM(sent_count) as total_emails_sent,
                SUM(opened_count) as total_opens,
                SUM(clicked_count) as total_clicks
            FROM email_campaigns
        """)
        
        recent_campaigns = await db.fetch("""
            SELECT campaign_id, subject, recipient_count, sent_count, 
                   opened_count, clicked_count, status, sent_at
            FROM email_campaigns
            ORDER BY created_at DESC
            LIMIT 10
        """)
        
        return {
            "subscribers": dict(stats) if stats else {},
            "campaigns": dict(campaign_stats) if campaign_stats else {},
            "recent_campaigns": [dict(row) for row in recent_campaigns]
        }


@router.post(
    "/webhook/sendgrid",
    include_in_schema=False
)
async def sendgrid_webhook(events: list[dict]) -> dict:
    """
    Handle SendGrid webhook events.
    
    Processes email delivery, open, click, and bounce events from SendGrid.
    Updates tracking data in the database.
    """
    async with get_database_client() as db:
        for event in events:
            event_type = event.get('event')
            email = event.get('email')
            campaign_id = event.get('campaign_id')
            timestamp = event.get('timestamp')
            
            if not all([event_type, email]):
                continue
            
            try:
                if event_type == 'open':
                    await db.execute("""
                        UPDATE email_sends 
                        SET opened_at = to_timestamp($1)
                        WHERE email = $2 AND campaign_id = $3 AND opened_at IS NULL
                    """, timestamp, email, campaign_id)
                    
                    # Update campaign stats
                    await db.execute("""
                        UPDATE email_campaigns 
                        SET opened_count = opened_count + 1
                        WHERE campaign_id = $1
                    """, campaign_id)
                
                elif event_type == 'click':
                    await db.execute("""
                        UPDATE email_sends 
                        SET clicked_at = to_timestamp($1)
                        WHERE email = $2 AND campaign_id = $3 AND clicked_at IS NULL
                    """, timestamp, email, campaign_id)
                    
                    # Update campaign stats
                    await db.execute("""
                        UPDATE email_campaigns 
                        SET clicked_count = clicked_count + 1
                        WHERE campaign_id = $1
                    """, campaign_id)
                
                elif event_type in ['bounce', 'dropped', 'spamreport']:
                    await db.execute("""
                        UPDATE email_sends 
                        SET bounced_at = to_timestamp($1), status = 'bounced'
                        WHERE email = $2 AND campaign_id = $3
                    """, timestamp, email, campaign_id)
                    
                    # Update campaign stats
                    await db.execute("""
                        UPDATE email_campaigns 
                        SET bounced_count = bounced_count + 1
                        WHERE campaign_id = $1
                    """, campaign_id)
                
                elif event_type == 'unsubscribe':
                    # Mark email as unsubscribed
                    await db.execute("""
                        UPDATE email_subscriptions 
                        SET is_active = false
                        WHERE email = $1
                    """, email)
                    
                    await db.execute("""
                        UPDATE email_sends 
                        SET unsubscribed_at = to_timestamp($1)
                        WHERE email = $2 AND campaign_id = $3
                    """, timestamp, email, campaign_id)
            
            except Exception as e:
                logger.error(f"Error processing SendGrid webhook event: {e}")
                continue
    
    return {"received": True}