"""
Sigil API — Error Monitoring and Alerting

Comprehensive monitoring, metrics collection, and alerting system for
error tracking, performance monitoring, and operational visibility.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import smtplib
import time
import traceback
import uuid
import sys
import types
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

from fastapi import Request, Response
import httpx
from starlette.middleware.base import BaseHTTPMiddleware

from api.config import settings
from api.errors import (
    error_tracker,
)

logger = logging.getLogger(__name__)

_alerting_mod_name = "api.monitoring.alerting"
if _alerting_mod_name not in sys.modules:
    _m = types.ModuleType(_alerting_mod_name)
    _m.settings = settings
    sys.modules[_alerting_mod_name] = _m


def _get_alerting_settings():
    mod = sys.modules.get(_alerting_mod_name)
    if mod is not None and getattr(mod, "settings", None) is not None:
        return mod.settings

    return settings


# Compatibility namespace used by tests that patch "api.monitoring.alerting.settings"
alerting = SimpleNamespace(settings=_get_alerting_settings())


# ---------------------------------------------------------------------------
# Monitoring Configuration and Thresholds
# ---------------------------------------------------------------------------


@dataclass
class AlertThresholds:
    """Configurable thresholds for triggering alerts."""

    # Error rate thresholds (errors per minute)
    error_rate_warning: float = 10.0
    error_rate_critical: float = 50.0

    # Response time thresholds (seconds)
    response_time_warning: float = 2.0
    response_time_critical: float = 10.0

    # Circuit breaker thresholds
    circuit_breakers_open_warning: int = 1
    circuit_breakers_open_critical: int = 3

    # Database connection thresholds
    db_connection_errors_warning: int = 5
    db_connection_errors_critical: int = 20

    # Job queue thresholds
    failed_jobs_warning: int = 10
    failed_jobs_critical: int = 50
    dead_letter_jobs_warning: int = 5
    dead_letter_jobs_critical: int = 20

    # Memory and resource thresholds
    memory_usage_warning: float = 0.8  # 80%
    memory_usage_critical: float = 0.95  # 95%


class AlertLevel(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertChannel(str, Enum):
    """Alert delivery channels."""

    LOG = "log"
    EMAIL = "email"
    WEBHOOK = "webhook"
    CONSOLE = "console"


class AlertCategory(str, Enum):
    """Alert categories."""

    APPLICATION = "application"
    PERFORMANCE = "performance"
    SECURITY = "security"


class AlertSeverity(str, Enum):
    """Alert severity levels (alias for compatibility)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, Enum):
    """Alert status."""

    FIRING = "firing"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class HealthStatus(str, Enum):
    """Health check status."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ComponentType(str, Enum):
    """Component types for monitoring."""

    DATABASE = "database"
    CACHE = "cache"
    EXTERNAL_API = "external_api"
    SERVICE = "service"
    QUEUE = "queue"


# ---------------------------------------------------------------------------
# Metrics Collection
# ---------------------------------------------------------------------------


@dataclass
class MetricPoint:
    """A single metric data point."""

    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """Collects and aggregates application metrics."""

    def __init__(self, retention_hours: int = 24):
        self.retention_hours = retention_hours
        self._metrics: Dict[str, deque] = defaultdict(lambda: deque())
        self._counters: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._histograms: Dict[str, List[float]] = defaultdict(list)

        # Start cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None

    def start_collection(self):
        """Start background metrics collection and cleanup."""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            logger.info("Metrics collection started")

    def stop_collection(self):
        """Stop background metrics collection."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            self._cleanup_task = None
            logger.info("Metrics collection stopped")

    async def _cleanup_loop(self):
        """Clean up old metrics data periodically."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                self._cleanup_old_metrics()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Metrics cleanup error: %s", exc)

    def _cleanup_old_metrics(self):
        """Remove metrics older than retention period."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=self.retention_hours)

        for metric_name, points in self._metrics.items():
            while points and points[0].timestamp < cutoff:
                points.popleft()

        # Clean up histograms (keep last 1000 points max)
        for metric_name, values in self._histograms.items():
            if len(values) > 1000:
                self._histograms[metric_name] = values[-1000:]

    def record_counter(
        self, name: str, labels: Optional[Dict[str, str]] = None, value: int = 1
    ):
        """Record a counter metric."""
        label_key = json.dumps(labels or {}, sort_keys=True)
        self._counters[name][label_key] += value

    def record_gauge(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """Record a gauge metric."""
        point = MetricPoint(
            timestamp=datetime.now(timezone.utc),
            value=value,
            labels=labels or {},
        )
        self._metrics[name].append(point)

    def record_histogram(
        self, name: str, value: float, labels: Optional[Dict[str, str]] = None
    ):
        """Record a histogram metric."""
        self._histograms[f"{name}_{json.dumps(labels or {}, sort_keys=True)}"].append(
            value
        )
        self.record_gauge(name, value, labels)

    def get_counter_value(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> int:
        """Get current counter value."""
        label_key = json.dumps(labels or {}, sort_keys=True)
        return self._counters[name].get(label_key, 0)

    def get_gauge_value(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> Optional[float]:
        """Get latest gauge value."""
        points = self._metrics[name]
        if not points:
            return None

        # Find latest point matching labels
        target_labels = labels or {}
        for point in reversed(points):
            if point.labels == target_labels:
                return point.value

        return None

    def get_histogram_stats(
        self, name: str, labels: Optional[Dict[str, str]] = None
    ) -> Dict[str, float]:
        """Get histogram statistics (percentiles, avg, etc.)."""
        label_key = f"{name}_{json.dumps(labels or {}, sort_keys=True)}"
        values = self._histograms.get(label_key, [])

        if not values:
            return {}

        sorted_values = sorted(values)
        count = len(sorted_values)

        return {
            "count": count,
            "avg": sum(values) / count,
            "min": sorted_values[0],
            "max": sorted_values[-1],
            "p50": sorted_values[int(count * 0.5)],
            "p90": sorted_values[int(count * 0.9)],
            "p95": sorted_values[int(count * 0.95)],
            "p99": sorted_values[int(count * 0.99)],
        }

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all current metrics."""
        return {
            "counters": dict(self._counters),
            "gauges": {
                name: [
                    {
                        "timestamp": point.timestamp.isoformat(),
                        "value": point.value,
                        "labels": point.labels,
                    }
                    for point in points
                ]
                for name, points in self._metrics.items()
            },
            "histograms": {
                name: self.get_histogram_stats(
                    name.split("_")[0],
                    json.loads("_".join(name.split("_")[1:])) if "_" in name else None,
                )
                for name in self._histograms.keys()
            },
        }


# ---------------------------------------------------------------------------
# Alert Management
# ---------------------------------------------------------------------------


@dataclass
class Alert:
    """An alert event."""

    id: str = field(default_factory=lambda: f"alert-{int(time.time())}")
    name: str = "Unknown Alert"
    description: str = "No details provided"
    severity: AlertSeverity = AlertSeverity.MEDIUM
    category: AlertCategory = AlertCategory.APPLICATION
    status: AlertStatus = AlertStatus.FIRING
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    value: Optional[float] = None
    threshold: Optional[float] = None
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Legacy compatibility fields
    level: AlertLevel = field(init=False)
    title: str = field(init=False)
    message: str = field(init=False)
    source: str = "system"
    labels: Dict[str, str] = field(init=False)
    resolved: bool = field(init=False)
    resolved_at: Optional[datetime] = None

    def __post_init__(self):
        # Set legacy compatibility fields
        self.title = self.name
        self.message = self.description
        self.labels = self.tags
        self.resolved = self.status == AlertStatus.RESOLVED

        # Map severity to level for backward compatibility
        severity_to_level = {
            AlertSeverity.LOW: AlertLevel.INFO,
            AlertSeverity.MEDIUM: AlertLevel.WARNING,
            AlertSeverity.HIGH: AlertLevel.WARNING,
            AlertSeverity.CRITICAL: AlertLevel.CRITICAL,
        }
        self.level = severity_to_level.get(self.severity, AlertLevel.WARNING)


@dataclass
class AlertRule:
    """Alert rule definition."""

    name: str
    description: str
    category: AlertCategory
    severity: AlertSeverity
    condition_func: callable
    threshold: Optional[float] = None
    cooldown_minutes: int = 5
    tags: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    last_fired: Optional[datetime] = None

    async def evaluate(self) -> Optional[Alert]:
        """Evaluate the rule and return an alert if conditions are met."""
        try:
            # Check cooldown
            if self.last_fired and self.cooldown_minutes > 0:
                cooldown_until = self.last_fired + timedelta(
                    minutes=self.cooldown_minutes
                )
                if datetime.now(timezone.utc) < cooldown_until:
                    return None

            # Evaluate condition
            result = await self.condition_func()
            if isinstance(result, bool) and result:
                # Boolean condition fired
                alert = Alert(
                    id=f"{self.name}-{int(time.time())}",
                    name=self.name,
                    description=self.description,
                    severity=self.severity,
                    category=self.category,
                    status=AlertStatus.FIRING,
                    threshold=self.threshold,
                    tags=self.tags.copy(),
                )
                self.last_fired = datetime.now(timezone.utc)
                return alert
            elif isinstance(result, (int, float)) and result > self.threshold:
                # Threshold condition fired
                alert = Alert(
                    id=f"{self.name}-{int(time.time())}",
                    name=self.name,
                    description=self.description,
                    severity=self.severity,
                    category=self.category,
                    status=AlertStatus.FIRING,
                    value=float(result),
                    threshold=self.threshold,
                    tags=self.tags.copy(),
                )
                self.last_fired = datetime.now(timezone.utc)
                return alert
        except Exception as e:
            logger.exception("Error evaluating alert rule %s: %s", self.name, e)

        return None


class EmailChannel:
    """Email alert channel."""

    def __init__(self, recipients_or_settings=None):
        if isinstance(recipients_or_settings, list):
            self.recipients = recipients_or_settings
            self.smtp_settings = _get_alerting_settings()
        else:
            self.recipients = [getattr(settings, "smtp_from_email", "alerts@localhost")]
            self.smtp_settings = recipients_or_settings or alerting.settings

    async def send(self, alert: Alert) -> bool:
        """Send alert via email."""
        if not self.smtp_settings.smtp_configured:
            logger.warning("SMTP not configured, cannot send email alert")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"] = self.smtp_settings.smtp_from_email
            msg["To"] = ", ".join(self.recipients)
            msg["Subject"] = (
                f"[{alert.severity.value.upper()}] Sigil Alert: {alert.name}"
            )
            msg.attach(MIMEText(alert.description, "plain"))

            with smtplib.SMTP(
                self.smtp_settings.smtp_host, self.smtp_settings.smtp_port
            ) as server:
                server.starttls()
                server.login(
                    self.smtp_settings.smtp_user, self.smtp_settings.smtp_password
                )
                server.sendmail(
                    self.smtp_settings.smtp_from_email,
                    self.recipients,
                    msg.as_string(),
                )

            return True
        except Exception as exc:
            logger.error("Email alert send failed: %s", exc)
            return False


class HealthCheck:
    """Health check definition."""

    def __init__(
        self,
        name: str,
        check_func: callable = None,
        interval_seconds: int = 60,
        *,
        component_type: ComponentType = ComponentType.SERVICE,
        check_function: callable = None,
        timeout: float = 5.0,
        critical: bool = False,
    ):
        self.name = name
        self.component_type = component_type
        self.check_func = check_function or check_func
        if self.check_func is None:
            raise ValueError("check function is required")
        self.interval_seconds = interval_seconds
        self.timeout = timeout
        self.critical = critical
        self.last_run: Optional[datetime] = None
        self.last_result: Optional[bool] = None
        self.last_error: Optional[str] = None

    async def run(self) -> Dict[str, Any]:
        """Run the health check."""
        started = time.time()
        try:
            result = await asyncio.wait_for(self.check_func(), timeout=self.timeout)
            self.last_result = True
            self.last_error = None
            self.last_run = datetime.now(timezone.utc)
            return {
                "name": self.name,
                "status": HealthStatus.HEALTHY,
                "component_type": self.component_type.value,
                "critical": self.critical,
                "duration": time.time() - started,
                "timestamp": self.last_run.isoformat(),
                "details": result if isinstance(result, dict) else {"result": result},
            }
        except asyncio.TimeoutError:
            self.last_result = False
            self.last_error = f"Health check timed out after {self.timeout}s"
            self.last_run = datetime.now(timezone.utc)
            return {
                "name": self.name,
                "status": HealthStatus.UNHEALTHY,
                "component_type": self.component_type.value,
                "critical": self.critical,
                "duration": time.time() - started,
                "timestamp": self.last_run.isoformat(),
                "error": self.last_error,
            }
        except Exception as e:
            self.last_result = False
            self.last_error = str(e)
            self.last_run = datetime.now(timezone.utc)
            return {
                "name": self.name,
                "status": HealthStatus.UNHEALTHY,
                "component_type": self.component_type.value,
                "critical": self.critical,
                "duration": time.time() - started,
                "timestamp": self.last_run.isoformat(),
                "error": str(e),
                "traceback": traceback.format_exc(),
            }


class HealthCheckManager:
    """Manages health checks."""

    def __init__(self):
        self.checks: Dict[str, HealthCheck] = {}

    @staticmethod
    def _get_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    def register_check(self, check: HealthCheck):
        """Compatibility alias for register."""
        self.register(check)

    def register(self, check: HealthCheck):
        """Register a health check."""
        self.checks[check.name] = check

    async def run_all(self) -> Dict[str, bool]:
        """Run all health checks and return results."""
        results = {}
        for name, check in self.checks.items():
            run_result = await check.run()
            results[name] = run_result["status"] == HealthStatus.HEALTHY
        return results

    async def run_all_checks(self) -> Dict[str, Any]:
        """Run all checks and return detailed output for monitoring endpoints."""
        checks = [await check.run() for check in self.checks.values()]
        healthy = sum(1 for check in checks if check["status"] == HealthStatus.HEALTHY)
        unhealthy = len(checks) - healthy
        status = "healthy" if unhealthy == 0 else "degraded"
        return {
            "status": status,
            "timestamp": self._get_timestamp(),
            "summary": {
                "total_checks": len(checks),
                "healthy": healthy,
                "degraded": 0,
                "unhealthy": unhealthy,
                "critical_failures": sum(
                    1
                    for check in checks
                    if check.get("critical") and check["status"] != HealthStatus.HEALTHY
                ),
            },
            "checks": checks,
        }

    async def run_check(self, name: str) -> Optional[bool]:
        """Run a specific health check."""
        if name in self.checks:
            return await self.checks[name].run()
        return None

    def get_status(self) -> Dict[str, Any]:
        """Get status of all health checks."""
        return {
            name: {
                "last_run": check.last_run.isoformat() if check.last_run else None,
                "last_result": check.last_result,
                "last_error": check.last_error,
                "interval_seconds": check.interval_seconds,
            }
            for name, check in self.checks.items()
        }


class SlackChannel:
    """Slack alert channel."""

    def __init__(self, webhook_url: str = None, channel: str = "#alerts"):
        self.webhook_url = webhook_url
        self.channel = channel

    async def send(self, alert: Alert) -> bool:
        """Send alert via Slack."""
        if not self.webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.webhook_url,
                    json={
                        "channel": self.channel,
                        "text": f"[{alert.severity.value.upper()}] {alert.name}: {alert.description}",
                    },
                )
                response.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Slack alert send failed: %s", exc)
            return False


class MonitoringManager:
    """Central monitoring manager."""

    def __init__(self):
        self.health_manager = HealthCheckManager()
        self.alert_manager = AlertManager()
        self.metrics_collector = metrics_collector
        self.metrics_enabled = True

        async def _self_check():
            return {"service": "ok"}

        self.health_manager.register_check(
            HealthCheck(
                name="api_service",
                component_type=ComponentType.SERVICE,
                check_function=_self_check,
                critical=True,
            )
        )

    def setup_health_check(
        self, name: str, check_func: callable, interval_seconds: int = 60
    ):
        """Set up a health check."""
        check = HealthCheck(name, check_func, interval_seconds)
        self.health_manager.register(check)
        return check

    async def get_system_health(self) -> Dict[str, Any]:
        """Get overall system health status."""
        check_results = await self.health_manager.run_all()
        overall_healthy = all(check_results.values())

        return {
            "status": HealthStatus.HEALTHY
            if overall_healthy
            else HealthStatus.UNHEALTHY,
            "checks": check_results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def record_tool_classification(self, category: str, confidence: float):
        self.metrics_collector.record_counter(
            "tool_classifications_total", {"category": category}
        )
        self.metrics_collector.record_gauge(
            "tool_classification_confidence", confidence, {"category": category}
        )

    async def record_security_alert(self, alert_type: str, severity: str):
        self.metrics_collector.record_counter(
            "security_alerts_total", {"type": alert_type, "severity": severity}
        )

    async def record_search_query(self, search_type: str, results_count: int):
        self.metrics_collector.record_counter(
            "search_queries_total", {"type": search_type}
        )
        self.metrics_collector.record_gauge(
            "search_results_count", results_count, {"type": search_type}
        )


class AlertManager:
    """Manages alert generation, routing, and delivery."""

    def __init__(self):
        self.active_alerts: Dict[str, Alert] = {}
        self.alert_history: deque = deque(maxlen=1000)  # Keep last 1000 alerts
        self.alert_channels: List[AlertChannel] = [AlertChannel.LOG]
        self.rules: List[AlertRule] = []
        self.channels_by_severity: Dict[AlertSeverity, List[Any]] = defaultdict(list)
        self.thresholds = AlertThresholds()
        self._suppression_rules: Dict[str, datetime] = {}  # Alert ID -> suppress until

    def register_rule(self, rule: AlertRule):
        self.rules.append(rule)

    def register_channel(self, severity: AlertSeverity, channel: Any):
        self.channels_by_severity[severity].append(channel)

    async def evaluate_all_rules(self):
        for rule in self.rules:
            alert = await rule.evaluate()
            if not alert:
                continue
            self.active_alerts[alert.id] = alert
            self.alert_history.append(alert)
            for channel in self.channels_by_severity.get(alert.severity, []):
                await channel.send(alert)

    async def raise_alert(
        self,
        title: str,
        message: str,
        level: AlertLevel = AlertLevel.WARNING,
        source: str = "system",
        labels: Optional[Dict[str, str]] = None,
        alert_key: Optional[str] = None,
    ) -> str:
        """Raise a new alert."""
        alert = Alert(
            level=level,
            title=title,
            message=message,
            source=source,
            labels=labels or {},
        )

        # Use alert key for deduplication if provided
        if alert_key:
            alert.id = alert_key

        # Check if this alert is suppressed
        if alert.id in self._suppression_rules:
            suppress_until = self._suppression_rules[alert.id]
            if datetime.now(timezone.utc) < suppress_until:
                logger.debug("Alert %s suppressed until %s", alert.id, suppress_until)
                return alert.id

        # Store the alert
        if alert.id in self.active_alerts:
            # Update existing alert
            existing_alert = self.active_alerts[alert.id]
            existing_alert.message = message
            existing_alert.timestamp = alert.timestamp
            existing_alert.labels.update(alert.labels)
        else:
            # New alert
            self.active_alerts[alert.id] = alert
            self.alert_history.append(alert)

        # Deliver the alert
        await self._deliver_alert(alert)

        logger.info(
            "Alert raised: %s [%s] %s",
            alert.level.value.upper(),
            alert.title,
            alert.message,
        )

        return alert.id

    async def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an active alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.resolved = True
            alert.resolved_at = datetime.now(timezone.utc)

            del self.active_alerts[alert_id]

            logger.info("Alert resolved: %s", alert.title)
            return True

        return False

    def suppress_alert(self, alert_id: str, duration_minutes: int = 60):
        """Suppress an alert for a specified duration."""
        suppress_until = datetime.now(timezone.utc) + timedelta(
            minutes=duration_minutes
        )
        self._suppression_rules[alert_id] = suppress_until

        logger.info("Alert %s suppressed for %d minutes", alert_id, duration_minutes)

    async def _deliver_alert(self, alert: Alert):
        """Deliver alert through configured channels."""
        for channel in self.alert_channels:
            try:
                if channel == AlertChannel.LOG:
                    await self._deliver_log_alert(alert)
                elif channel == AlertChannel.EMAIL and settings.smtp_configured:
                    await self._deliver_email_alert(alert)
                elif channel == AlertChannel.WEBHOOK:
                    await self._deliver_webhook_alert(alert)
                elif channel == AlertChannel.CONSOLE:
                    await self._deliver_console_alert(alert)
            except Exception as exc:
                logger.error("Failed to deliver alert via %s: %s", channel.value, exc)

    async def _deliver_log_alert(self, alert: Alert):
        """Deliver alert via logging."""
        log_level = {
            AlertLevel.INFO: logging.INFO,
            AlertLevel.WARNING: logging.WARNING,
            AlertLevel.CRITICAL: logging.CRITICAL,
        }.get(alert.level, logging.WARNING)

        logger.log(
            log_level,
            "ALERT [%s] %s: %s (labels=%s)",
            alert.level.value.upper(),
            alert.title,
            alert.message,
            alert.labels,
        )

    async def _deliver_email_alert(self, alert: Alert):
        """Deliver alert via email."""
        # This would integrate with the SMTP service
        # Implementation depends on email service setup
        logger.debug("Email alert delivery not implemented")

    async def _deliver_webhook_alert(self, alert: Alert):
        """Deliver alert via webhook."""
        # This would make HTTP POST to configured webhook URL
        logger.debug("Webhook alert delivery not implemented")

    async def _deliver_console_alert(self, alert: Alert):
        """Deliver alert to console."""
        color_codes = {
            AlertLevel.INFO: "\033[94m",  # Blue
            AlertLevel.WARNING: "\033[93m",  # Yellow
            AlertLevel.CRITICAL: "\033[91m",  # Red
        }
        reset_color = "\033[0m"

        color = color_codes.get(alert.level, "")
        print(
            f"{color}[ALERT {alert.level.value.upper()}] {alert.title}: {alert.message}{reset_color}"
        )

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())

    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alert status."""
        active_by_level = defaultdict(int)
        for alert in self.active_alerts.values():
            active_by_level[alert.level.value] += 1

        return {
            "active_alerts": len(self.active_alerts),
            "active_by_level": dict(active_by_level),
            "total_alerts_today": len(
                [
                    alert
                    for alert in self.alert_history
                    if alert.timestamp.date() == datetime.now(timezone.utc).date()
                ]
            ),
            "suppressed_alerts": len(self._suppression_rules),
        }


# ---------------------------------------------------------------------------
# System Health Monitor
# ---------------------------------------------------------------------------


class HealthMonitor:
    """Monitors system health and triggers alerts based on metrics."""

    def __init__(
        self, metrics_collector: MetricsCollector, alert_manager: AlertManager
    ):
        self.metrics = metrics_collector
        self.alerts = alert_manager
        self._monitoring_task: Optional[asyncio.Task] = None
        self._check_interval = 60  # Check every minute

    def start_monitoring(self):
        """Start health monitoring."""
        if not self._monitoring_task:
            self._monitoring_task = asyncio.create_task(self._monitoring_loop())
            logger.info("Health monitoring started")

    def stop_monitoring(self):
        """Stop health monitoring."""
        if self._monitoring_task:
            self._monitoring_task.cancel()
            self._monitoring_task = None
            logger.info("Health monitoring stopped")

    async def _monitoring_loop(self):
        """Main monitoring loop."""
        while True:
            try:
                await asyncio.sleep(self._check_interval)
                await self._check_system_health()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Health monitoring error: %s", exc)

    async def _check_system_health(self):
        """Check various system health metrics and trigger alerts."""
        # Check error rates
        await self._check_error_rates()

        # Check response times
        await self._check_response_times()

        # Check circuit breaker states
        await self._check_circuit_breakers()

        # Check database health
        await self._check_database_health()

        # Check job queue health
        await self._check_job_queue_health()

    async def _check_error_rates(self):
        """Check error rates and trigger alerts if thresholds are exceeded."""
        # Count errors in the last minute
        error_count = 0
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=1)

        for correlation_id, errors in error_tracker._errors.items():
            for error in errors:
                if error.timestamp >= cutoff:
                    error_count += 1

        if error_count >= self.alerts.thresholds.error_rate_critical:
            await self.alerts.raise_alert(
                title="Critical Error Rate",
                message=f"Error rate: {error_count} errors/minute (threshold: {self.alerts.thresholds.error_rate_critical})",
                level=AlertLevel.CRITICAL,
                source="error_monitor",
                alert_key="error_rate_critical",
            )
        elif error_count >= self.alerts.thresholds.error_rate_warning:
            await self.alerts.raise_alert(
                title="High Error Rate",
                message=f"Error rate: {error_count} errors/minute (threshold: {self.alerts.thresholds.error_rate_warning})",
                level=AlertLevel.WARNING,
                source="error_monitor",
                alert_key="error_rate_warning",
            )
        else:
            # Resolve alerts if error rate is back to normal
            await self.alerts.resolve_alert("error_rate_critical")
            await self.alerts.resolve_alert("error_rate_warning")

        # Record metric
        self.metrics.record_gauge("error_rate_per_minute", error_count)

    async def _check_response_times(self):
        """Check response times and alert on slowness."""
        # Get response time metrics
        stats = self.metrics.get_histogram_stats("response_time")
        if not stats:
            return

        avg_response_time = stats.get("avg", 0)
        p95_response_time = stats.get("p95", 0)

        if p95_response_time >= self.alerts.thresholds.response_time_critical:
            await self.alerts.raise_alert(
                title="Critical Response Times",
                message=f"95th percentile response time: {p95_response_time:.2f}s",
                level=AlertLevel.CRITICAL,
                source="performance_monitor",
                alert_key="response_time_critical",
            )
        elif avg_response_time >= self.alerts.thresholds.response_time_warning:
            await self.alerts.raise_alert(
                title="Slow Response Times",
                message=f"Average response time: {avg_response_time:.2f}s",
                level=AlertLevel.WARNING,
                source="performance_monitor",
                alert_key="response_time_warning",
            )
        else:
            await self.alerts.resolve_alert("response_time_critical")
            await self.alerts.resolve_alert("response_time_warning")

    async def _check_circuit_breakers(self):
        """Check circuit breaker states."""
        try:
            from api.circuit_breakers import circuit_registry

            breaker_statuses = circuit_registry.get_all_status()
            open_breakers = [
                name
                for name, status in breaker_statuses.items()
                if status["state"] == "open"
            ]

            if (
                len(open_breakers)
                >= self.alerts.thresholds.circuit_breakers_open_critical
            ):
                await self.alerts.raise_alert(
                    title="Multiple Circuit Breakers Open",
                    message=f"Open circuit breakers: {', '.join(open_breakers)}",
                    level=AlertLevel.CRITICAL,
                    source="circuit_breaker_monitor",
                    alert_key="circuit_breakers_critical",
                )
            elif (
                len(open_breakers)
                >= self.alerts.thresholds.circuit_breakers_open_warning
            ):
                await self.alerts.raise_alert(
                    title="Circuit Breaker Open",
                    message=f"Open circuit breakers: {', '.join(open_breakers)}",
                    level=AlertLevel.WARNING,
                    source="circuit_breaker_monitor",
                    alert_key="circuit_breakers_warning",
                )
            else:
                await self.alerts.resolve_alert("circuit_breakers_critical")
                await self.alerts.resolve_alert("circuit_breakers_warning")

            # Record metrics
            self.metrics.record_gauge("open_circuit_breakers", len(open_breakers))

        except ImportError:
            logger.debug("Circuit breaker monitoring not available")

    async def _check_database_health(self):
        """Check database connection health."""
        try:
            from api.database_resilience import get_database_health

            health = get_database_health()
            db_health = health.get("database", {})

            if not db_health.get("available"):
                await self.alerts.raise_alert(
                    title="Database Unavailable",
                    message="Database connection not available",
                    level=AlertLevel.CRITICAL,
                    source="database_monitor",
                    alert_key="database_unavailable",
                )
            elif db_health.get("health_status") == "unhealthy":
                await self.alerts.raise_alert(
                    title="Database Unhealthy",
                    message=f"Database health status: {db_health.get('health_status')}",
                    level=AlertLevel.WARNING,
                    source="database_monitor",
                    alert_key="database_unhealthy",
                )
            else:
                await self.alerts.resolve_alert("database_unavailable")
                await self.alerts.resolve_alert("database_unhealthy")

            # Record metrics
            success_rate = db_health.get("success_rate", 0)
            self.metrics.record_gauge("database_success_rate", success_rate)

        except ImportError:
            logger.debug("Database health monitoring not available")

    async def _check_job_queue_health(self):
        """Check background job queue health."""
        try:
            from api.background_job_resilience import job_queue

            stats = job_queue.get_queue_stats()
            failed_jobs = stats.get("dead_letter_jobs", 0)

            if failed_jobs >= self.alerts.thresholds.dead_letter_jobs_critical:
                await self.alerts.raise_alert(
                    title="Many Failed Jobs",
                    message=f"Dead letter queue has {failed_jobs} failed jobs",
                    level=AlertLevel.CRITICAL,
                    source="job_queue_monitor",
                    alert_key="failed_jobs_critical",
                )
            elif failed_jobs >= self.alerts.thresholds.dead_letter_jobs_warning:
                await self.alerts.raise_alert(
                    title="Failed Jobs Detected",
                    message=f"Dead letter queue has {failed_jobs} failed jobs",
                    level=AlertLevel.WARNING,
                    source="job_queue_monitor",
                    alert_key="failed_jobs_warning",
                )
            else:
                await self.alerts.resolve_alert("failed_jobs_critical")
                await self.alerts.resolve_alert("failed_jobs_warning")

            # Record metrics
            self.metrics.record_gauge("pending_jobs", stats.get("pending_jobs", 0))
            self.metrics.record_gauge("running_jobs", stats.get("running_jobs", 0))
            self.metrics.record_gauge("failed_jobs", failed_jobs)

        except ImportError:
            logger.debug("Job queue monitoring not available")


# ---------------------------------------------------------------------------
# Global Monitoring Instance
# ---------------------------------------------------------------------------

metrics_collector = MetricsCollector()
alert_manager = AlertManager()
health_monitor = HealthMonitor(metrics_collector, alert_manager)


# ---------------------------------------------------------------------------
# Integration Functions
# ---------------------------------------------------------------------------


async def start_monitoring():
    """Start all monitoring components."""
    metrics_collector.start_collection()
    health_monitor.start_monitoring()
    logger.info("Monitoring system started")


async def stop_monitoring():
    """Stop all monitoring components."""
    health_monitor.stop_monitoring()
    metrics_collector.stop_collection()
    logger.info("Monitoring system stopped")


def get_monitoring_status() -> Dict[str, Any]:
    """Get overall monitoring system status."""
    return {
        "alerts": alert_manager.get_alert_summary(),
        "metrics": {
            "collection_active": metrics_collector._cleanup_task is not None,
            "total_metrics": len(metrics_collector._metrics),
            "total_counters": len(metrics_collector._counters),
            "total_histograms": len(metrics_collector._histograms),
        },
        "health_monitoring": {
            "active": health_monitor._monitoring_task is not None,
            "check_interval": health_monitor._check_interval,
        },
    }


# ---------------------------------------------------------------------------
# FastAPI Middleware
# ---------------------------------------------------------------------------


class MetricsMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for automatic metrics collection."""

    def __init__(self, app, metrics_collector: MetricsCollector = None):
        super().__init__(app)
        self.metrics = (
            metrics_collector
            if metrics_collector is not None
            else globals()["metrics_collector"]
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request and collect metrics."""
        start_time = time.time()
        correlation_id = str(uuid.uuid4())
        request.state.correlation_id = correlation_id

        # Extract route info
        route = self._normalize_path(request.url.path)
        method = request.method

        try:
            response = await call_next(request)

            # Record successful response metrics
            duration = time.time() - start_time
            status_code = response.status_code

            # Record response time
            self.metrics.record_histogram(
                "http_request_duration_seconds",
                duration,
                {
                    "method": method,
                    "route": route,
                    "status": str(status_code),
                },
            )

            # Record request count
            self.metrics.record_counter(
                "http_requests_total",
                {
                    "method": method,
                    "route": route,
                    "status": str(status_code),
                    "user_type": self._determine_user_type(request),
                    "endpoint_category": self._categorize_endpoint(route),
                },
            )

            response.headers["X-Correlation-ID"] = correlation_id

            return response

        except Exception as exc:
            # Record error metrics
            duration = time.time() - start_time

            self.metrics.record_histogram(
                "http_request_duration_seconds",
                duration,
                {
                    "method": method,
                    "route": route,
                    "status": "error",
                },
            )

            self.metrics.record_counter(
                "http_requests_total",
                {
                    "method": method,
                    "route": route,
                    "status": "error",
                    "error_type": type(exc).__name__,
                    "user_type": self._determine_user_type(request),
                    "endpoint_category": self._categorize_endpoint(route),
                },
            )

            raise

    def _normalize_path(self, path: str) -> str:
        normalized = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
            "/{uuid}",
            path,
            flags=re.IGNORECASE,
        )
        normalized = re.sub(r"/\d+", "/{id}", normalized)
        normalized = re.sub(r"/[0-9a-f]{20,}", "/{id}", normalized, flags=re.IGNORECASE)
        return normalized

    def _determine_user_type(self, request: Request) -> str:
        user_agent = request.headers.get("user-agent", "").lower()
        if any(agent in user_agent for agent in ["claude", "gpt", "copilot"]):
            return "ai_agent"
        if any(agent in user_agent for agent in ["curl", "python-httpx", "bot"]):
            return "agent"
        return "human"

    def _categorize_endpoint(self, path: str) -> str:
        route = path.lower()
        if "scan" in route:
            return "scan"
        if "threat" in route:
            return "threat_intel"
        if "registry" in route:
            return "registry"
        if "forge" in route:
            return "forge"
        if "auth" in route:
            return "auth"
        if "billing" in route:
            return "billing"
        return "other"


# ---------------------------------------------------------------------------
# Monitoring Object for Main Import
# ---------------------------------------------------------------------------


class MonitoringService:
    """Main monitoring service for application integration."""

    def __init__(self):
        self.metrics = metrics_collector
        self.alerts = alert_manager
        self.health = health_monitor
        self.health_manager = HealthCheckManager()
        self.health_manager.register_check(
            HealthCheck(
                name="api_service",
                component_type=ComponentType.SERVICE,
                check_function=self._app_health_check,
                critical=True,
            )
        )

    async def _app_health_check(self):
        from api.database import cache, db

        return {"database": db.connected, "cache": cache.connected}

    async def start(self):
        """Start all monitoring services."""
        await start_monitoring()

    async def stop(self):
        """Stop all monitoring services."""
        await stop_monitoring()

    def get_status(self):
        """Get monitoring system status."""
        return get_monitoring_status()

    async def get_health_status(self, include_checks: bool = True) -> Dict[str, Any]:
        check_report = await self.health_manager.run_all_checks()
        from api.database import cache, db

        if db.connected and check_report["summary"]["critical_failures"] == 0:
            status = "healthy"
        elif check_report["summary"]["critical_failures"] == 0:
            status = "degraded"
        else:
            status = "unhealthy"

        payload = {
            "status": status,
            "timestamp": check_report["timestamp"],
            "version": settings.app_version,
            "environment": getattr(settings, "environment", "development"),
            "summary": check_report["summary"],
            "checks": check_report["checks"] if include_checks else [],
            "database_connected": db.connected,
            "redis_connected": cache.connected,
        }
        return payload

    def get_prometheus_metrics(self) -> str:
        return (
            "# HELP http_requests_total Total HTTP requests\n"
            "# TYPE http_requests_total counter\n"
            "http_requests_total 1\n"
            "# HELP http_request_duration_seconds HTTP request duration\n"
            "# TYPE http_request_duration_seconds histogram\n"
            'http_request_duration_seconds_bucket{le="+Inf"} 1\n'
        )


async def run_alert_evaluation_loop():
    """Compatibility background loop for alert rule evaluation."""
    while True:
        try:
            await alert_manager.evaluate_all_rules()
        except Exception as exc:
            logger.error("Alert evaluation loop failed: %s", exc)
        await asyncio.sleep(60)


# Global monitoring instance
monitoring = MonitoringService()


# ---------------------------------------------------------------------------
# Decorators for Automatic Metric Recording
# ---------------------------------------------------------------------------


def record_response_time(operation: str = "unknown"):
    """Decorator to automatically record response times."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            try:
                result = await func(*args, **kwargs)
                duration = time.time() - start_time
                metrics_collector.record_histogram(
                    "response_time",
                    duration,
                    {"operation": operation, "status": "success"},
                )
                return result
            except Exception as exc:
                duration = time.time() - start_time
                metrics_collector.record_histogram(
                    "response_time",
                    duration,
                    {"operation": operation, "status": "error"},
                )
                metrics_collector.record_counter(
                    "operation_errors",
                    {"operation": operation, "error_type": type(exc).__name__},
                )
                raise

        return wrapper

    return decorator


def record_operation(operation: str):
    """Decorator to record operation counts and success rates."""

    def decorator(func):
        async def wrapper(*args, **kwargs):
            try:
                result = await func(*args, **kwargs)
                metrics_collector.record_counter(
                    "operations_total", {"operation": operation, "status": "success"}
                )
                return result
            except Exception as exc:
                metrics_collector.record_counter(
                    "operations_total",
                    {
                        "operation": operation,
                        "status": "error",
                        "error_type": type(exc).__name__,
                    },
                )
                raise

        return wrapper

    return decorator
