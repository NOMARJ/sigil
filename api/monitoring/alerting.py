"""
Sigil API — Alerting and Notification System

Comprehensive alerting rules, escalation procedures, and notification
handling for production monitoring. Integrates with various notification
channels including email, Slack, and PagerDuty.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from typing import Any, Dict, List, Optional, Union

import httpx
from pydantic import BaseModel

from api.config import settings

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Alert Models
# ---------------------------------------------------------------------------

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    """Alert status values."""
    FIRING = "firing"
    RESOLVED = "resolved"
    ACKNOWLEDGED = "acknowledged"
    SILENCED = "silenced"


class AlertCategory(str, Enum):
    """Alert categories."""
    INFRASTRUCTURE = "infrastructure"
    APPLICATION = "application"
    SECURITY = "security"
    BUSINESS = "business"
    PERFORMANCE = "performance"


class Alert(BaseModel):
    """Alert model."""
    id: str
    name: str
    description: str
    severity: AlertSeverity
    category: AlertCategory
    status: AlertStatus
    timestamp: datetime
    value: Optional[float] = None
    threshold: Optional[float] = None
    tags: Dict[str, str] = {}
    metadata: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Notification Channels
# ---------------------------------------------------------------------------

class NotificationChannel(ABC):
    """Abstract base class for notification channels."""
    
    @abstractmethod
    async def send(self, alert: Alert) -> bool:
        """Send alert notification. Returns True if successful."""
        pass


class EmailChannel(NotificationChannel):
    """Email notification channel via SMTP."""
    
    def __init__(self, recipients: List[str]):
        self.recipients = recipients
    
    async def send(self, alert: Alert) -> bool:
        """Send email alert notification."""
        if not settings.smtp_configured:
            logger.warning("SMTP not configured, cannot send email alert")
            return False
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = settings.smtp_from_email
            msg['To'] = ', '.join(self.recipients)
            msg['Subject'] = f"[{alert.severity.upper()}] Sigil Alert: {alert.name}"
            
            # Email body
            body = self._format_email_body(alert)
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
                server.starttls()
                server.login(settings.smtp_user, settings.smtp_password)
                text = msg.as_string()
                server.sendmail(settings.smtp_from_email, self.recipients, text)
            
            logger.info(f"Email alert sent for {alert.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _format_email_body(self, alert: Alert) -> str:
        """Format alert as HTML email body."""
        severity_color = {
            AlertSeverity.CRITICAL: "#dc3545",
            AlertSeverity.HIGH: "#fd7e14", 
            AlertSeverity.MEDIUM: "#ffc107",
            AlertSeverity.LOW: "#28a745",
            AlertSeverity.INFO: "#17a2b8"
        }
        
        color = severity_color.get(alert.severity, "#6c757d")
        
        return f"""
        <html>
        <body>
            <h2 style="color: {color};">Sigil API Alert: {alert.name}</h2>
            <table border="1" cellpadding="5" cellspacing="0">
                <tr><td><strong>Severity</strong></td><td style="color: {color};">{alert.severity.upper()}</td></tr>
                <tr><td><strong>Category</strong></td><td>{alert.category}</td></tr>
                <tr><td><strong>Status</strong></td><td>{alert.status}</td></tr>
                <tr><td><strong>Time</strong></td><td>{alert.timestamp.isoformat()}</td></tr>
                <tr><td><strong>Description</strong></td><td>{alert.description}</td></tr>
                {f'<tr><td><strong>Value</strong></td><td>{alert.value}</td></tr>' if alert.value is not None else ''}
                {f'<tr><td><strong>Threshold</strong></td><td>{alert.threshold}</td></tr>' if alert.threshold is not None else ''}
            </table>
            
            {self._format_tags_table(alert.tags) if alert.tags else ''}
            {self._format_metadata_table(alert.metadata) if alert.metadata else ''}
            
            <p><small>Generated by Sigil API Monitoring System</small></p>
        </body>
        </html>
        """
    
    def _format_tags_table(self, tags: Dict[str, str]) -> str:
        """Format tags as HTML table."""
        rows = ''.join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in tags.items()])
        return f"""
        <h3>Tags</h3>
        <table border="1" cellpadding="5" cellspacing="0">
            {rows}
        </table>
        """
    
    def _format_metadata_table(self, metadata: Dict[str, Any]) -> str:
        """Format metadata as HTML table."""
        rows = ''.join([f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in metadata.items()])
        return f"""
        <h3>Metadata</h3>
        <table border="1" cellpadding="5" cellspacing="0">
            {rows}
        </table>
        """


class SlackChannel(NotificationChannel):
    """Slack notification channel via webhook."""
    
    def __init__(self, webhook_url: str, channel: str = "#alerts"):
        self.webhook_url = webhook_url
        self.channel = channel
    
    async def send(self, alert: Alert) -> bool:
        """Send Slack alert notification."""
        try:
            # Format Slack message
            message = self._format_slack_message(alert)
            
            # Send to Slack
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json=message,
                    timeout=10.0
                )
                response.raise_for_status()
            
            logger.info(f"Slack alert sent for {alert.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def _format_slack_message(self, alert: Alert) -> Dict[str, Any]:
        """Format alert as Slack message."""
        severity_colors = {
            AlertSeverity.CRITICAL: "danger",
            AlertSeverity.HIGH: "warning",
            AlertSeverity.MEDIUM: "warning", 
            AlertSeverity.LOW: "good",
            AlertSeverity.INFO: "#439FE0"
        }
        
        color = severity_colors.get(alert.severity, "warning")
        
        fields = [
            {"title": "Severity", "value": alert.severity.upper(), "short": True},
            {"title": "Category", "value": alert.category, "short": True},
            {"title": "Status", "value": alert.status, "short": True},
            {"title": "Time", "value": alert.timestamp.isoformat(), "short": True}
        ]
        
        if alert.value is not None:
            fields.append({"title": "Value", "value": str(alert.value), "short": True})
        
        if alert.threshold is not None:
            fields.append({"title": "Threshold", "value": str(alert.threshold), "short": True})
        
        return {
            "channel": self.channel,
            "username": "Sigil Monitoring",
            "icon_emoji": ":warning:",
            "attachments": [
                {
                    "color": color,
                    "title": f"🚨 {alert.name}",
                    "text": alert.description,
                    "fields": fields,
                    "footer": "Sigil API Monitoring",
                    "ts": int(alert.timestamp.timestamp())
                }
            ]
        }


class PagerDutyChannel(NotificationChannel):
    """PagerDuty notification channel."""
    
    def __init__(self, integration_key: str):
        self.integration_key = integration_key
    
    async def send(self, alert: Alert) -> bool:
        """Send PagerDuty alert notification."""
        try:
            # Format PagerDuty event
            event = self._format_pagerduty_event(alert)
            
            # Send to PagerDuty
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    "https://events.pagerduty.com/v2/enqueue",
                    json=event,
                    timeout=10.0
                )
                response.raise_for_status()
            
            logger.info(f"PagerDuty alert sent for {alert.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send PagerDuty alert: {e}")
            return False
    
    def _format_pagerduty_event(self, alert: Alert) -> Dict[str, Any]:
        """Format alert as PagerDuty event."""
        # Map severity to PagerDuty severity
        severity_mapping = {
            AlertSeverity.CRITICAL: "critical",
            AlertSeverity.HIGH: "error",
            AlertSeverity.MEDIUM: "warning",
            AlertSeverity.LOW: "info",
            AlertSeverity.INFO: "info"
        }
        
        return {
            "routing_key": self.integration_key,
            "event_action": "trigger" if alert.status == AlertStatus.FIRING else "resolve",
            "dedup_key": f"sigil-{alert.id}",
            "payload": {
                "summary": f"Sigil API Alert: {alert.name}",
                "source": "sigil-api",
                "severity": severity_mapping.get(alert.severity, "error"),
                "component": alert.category,
                "group": "sigil-api",
                "class": alert.name,
                "custom_details": {
                    "description": alert.description,
                    "value": alert.value,
                    "threshold": alert.threshold,
                    "tags": alert.tags,
                    "metadata": alert.metadata
                }
            }
        }


# ---------------------------------------------------------------------------
# Alert Rules
# ---------------------------------------------------------------------------

class AlertRule:
    """Alert rule definition."""
    
    def __init__(
        self,
        name: str,
        description: str,
        category: AlertCategory,
        severity: AlertSeverity,
        condition_func: callable,
        threshold: Optional[float] = None,
        cooldown_minutes: int = 15,
        tags: Optional[Dict[str, str]] = None
    ):
        self.name = name
        self.description = description
        self.category = category
        self.severity = severity
        self.condition_func = condition_func
        self.threshold = threshold
        self.cooldown_minutes = cooldown_minutes
        self.tags = tags or {}
        self.last_fired: Optional[datetime] = None
    
    async def evaluate(self) -> Optional[Alert]:
        """Evaluate the alert rule condition."""
        try:
            # Check cooldown period
            if self.last_fired:
                cooldown_end = self.last_fired + timedelta(minutes=self.cooldown_minutes)
                if datetime.now(timezone.utc) < cooldown_end:
                    return None
            
            # Evaluate condition
            result = await self.condition_func()
            
            if result and (isinstance(result, bool) or (isinstance(result, (int, float)) and result > 0)):
                self.last_fired = datetime.now(timezone.utc)
                
                # Create alert
                alert = Alert(
                    id=f"{self.name}-{int(self.last_fired.timestamp())}",
                    name=self.name,
                    description=self.description,
                    severity=self.severity,
                    category=self.category,
                    status=AlertStatus.FIRING,
                    timestamp=self.last_fired,
                    value=result if isinstance(result, (int, float)) else None,
                    threshold=self.threshold,
                    tags=self.tags
                )
                
                return alert
            
            return None
            
        except Exception as e:
            logger.error(f"Error evaluating alert rule {self.name}: {e}")
            return None


# ---------------------------------------------------------------------------
# Alert Manager
# ---------------------------------------------------------------------------

class AlertManager:
    """Manages alert rules, notifications, and escalation."""
    
    def __init__(self):
        self.rules: List[AlertRule] = []
        self.channels: Dict[str, List[NotificationChannel]] = {}
        self.active_alerts: Dict[str, Alert] = {}
        self._register_default_rules()
        self._register_default_channels()
    
    def register_rule(self, rule: AlertRule):
        """Register an alert rule."""
        self.rules.append(rule)
    
    def register_channel(self, severity: AlertSeverity, channel: NotificationChannel):
        """Register a notification channel for a severity level."""
        if severity not in self.channels:
            self.channels[severity] = []
        self.channels[severity].append(channel)
    
    def _register_default_rules(self):
        """Register default alert rules."""
        
        # High error rate alert
        self.register_rule(AlertRule(
            name="High Error Rate",
            description="HTTP error rate exceeds 5%",
            category=AlertCategory.APPLICATION,
            severity=AlertSeverity.HIGH,
            condition_func=self._check_error_rate,
            threshold=5.0,
            cooldown_minutes=5
        ))
        
        # High response time alert
        self.register_rule(AlertRule(
            name="High Response Time", 
            description="P95 response time exceeds 2 seconds",
            category=AlertCategory.PERFORMANCE,
            severity=AlertSeverity.MEDIUM,
            condition_func=self._check_response_time,
            threshold=2.0,
            cooldown_minutes=10
        ))
        
        # Database connectivity alert
        self.register_rule(AlertRule(
            name="Database Connectivity",
            description="Database connection failed",
            category=AlertCategory.INFRASTRUCTURE,
            severity=AlertSeverity.CRITICAL,
            condition_func=self._check_database_connectivity,
            cooldown_minutes=2
        ))
        
        # Security alert spike
        self.register_rule(AlertRule(
            name="Security Alert Spike",
            description="Unusually high number of security alerts",
            category=AlertCategory.SECURITY,
            severity=AlertSeverity.HIGH,
            condition_func=self._check_security_alerts,
            threshold=10.0,
            cooldown_minutes=30
        ))
        
        # Memory usage alert
        self.register_rule(AlertRule(
            name="High Memory Usage",
            description="Memory usage exceeds 80%",
            category=AlertCategory.INFRASTRUCTURE,
            severity=AlertSeverity.MEDIUM,
            condition_func=self._check_memory_usage,
            threshold=80.0,
            cooldown_minutes=15
        ))
    
    def _register_default_channels(self):
        """Register default notification channels."""
        # Email for all alerts (if configured)
        if settings.smtp_configured:
            email_channel = EmailChannel(["ops@sigilsec.ai"])
            for severity in AlertSeverity:
                self.register_channel(severity, email_channel)
    
    async def _check_error_rate(self) -> float:
        """Check current error rate from metrics."""
        try:
            from api.monitoring import http_requests_total
            
            # Get total requests and errors from last 5 minutes
            # This is a simplified check - in production you'd query metrics properly
            total_metric = http_requests_total._value._values
            total = sum(v for v in total_metric.values())
            
            errors = sum(v for labels, v in total_metric.items() 
                        if any(code.startswith(('4', '5')) for code in labels if code.isdigit()))
            
            if total > 0:
                error_rate = (errors / total) * 100
                return error_rate if error_rate > 5.0 else 0
            
            return 0
            
        except Exception as e:
            logger.error(f"Error checking error rate: {e}")
            return 0
    
    async def _check_response_time(self) -> float:
        """Check P95 response time."""
        # Placeholder - would integrate with actual metrics
        return 0
    
    async def _check_database_connectivity(self) -> bool:
        """Check database connectivity."""
        from api.database import db
        return not db.connected
    
    async def _check_security_alerts(self) -> float:
        """Check for security alert spikes."""
        # Placeholder - would check security metrics
        return 0
    
    async def _check_memory_usage(self) -> float:
        """Check memory usage percentage."""
        # Placeholder - would check system memory
        return 0
    
    async def evaluate_all_rules(self):
        """Evaluate all alert rules and send notifications."""
        for rule in self.rules:
            try:
                alert = await rule.evaluate()
                if alert:
                    await self._handle_alert(alert)
            except Exception as e:
                logger.error(f"Error evaluating rule {rule.name}: {e}")
    
    async def _handle_alert(self, alert: Alert):
        """Handle a fired alert by sending notifications."""
        logger.warning(f"Alert fired: {alert.name} - {alert.description}")
        
        # Store active alert
        self.active_alerts[alert.id] = alert
        
        # Send notifications to appropriate channels
        channels = self.channels.get(alert.severity, [])
        
        notification_tasks = []
        for channel in channels:
            notification_tasks.append(channel.send(alert))
        
        # Send all notifications concurrently
        if notification_tasks:
            results = await asyncio.gather(*notification_tasks, return_exceptions=True)
            
            successful = sum(1 for r in results if r is True)
            failed = len(results) - successful
            
            logger.info(f"Alert notifications sent: {successful} successful, {failed} failed")


# ---------------------------------------------------------------------------
# Global Alert Manager Instance
# ---------------------------------------------------------------------------

alert_manager = AlertManager()


# ---------------------------------------------------------------------------
# Background Alert Evaluation Task
# ---------------------------------------------------------------------------

async def run_alert_evaluation_loop():
    """Background task to continuously evaluate alert rules."""
    logger.info("Starting alert evaluation loop")
    
    while True:
        try:
            await alert_manager.evaluate_all_rules()
            await asyncio.sleep(60)  # Evaluate every minute
        except Exception as e:
            logger.error(f"Error in alert evaluation loop: {e}")
            await asyncio.sleep(60)  # Continue after error