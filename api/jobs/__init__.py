"""
Background Jobs Package

Central module for all background job runners and schedulers.
Jobs are designed to be executed by external cron or task schedulers.
"""

from .email_jobs import EmailJobRunner
from .collect_tool_metrics import ToolMetricsCollector

__all__ = [
    "EmailJobRunner", 
    "ToolMetricsCollector"
]

# Job registry for scheduled execution
JOB_REGISTRY = {
    "email_weekly_digest": "EmailJobRunner.generate_and_send_weekly_digest",
    "collect_tool_metrics": "ToolMetricsCollector.collect_all_metrics",
}

# Default cron schedules (can be overridden in deployment)
DEFAULT_SCHEDULES = {
    "email_weekly_digest": "0 9 * * 1",  # Monday 9 AM
    "collect_tool_metrics": "0 */6 * * *",  # Every 6 hours
}