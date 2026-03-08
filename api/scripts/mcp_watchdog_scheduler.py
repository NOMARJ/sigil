#!/usr/bin/env python3
"""
Sigil MCP Watchdog Scheduler

Automated scheduler for MCP server discovery and typosquat detection.
Runs as a background service to continuously monitor the MCP ecosystem.

Usage:
    # Run once
    python -m api.scripts.mcp_watchdog_scheduler --run-once

    # Run as daemon (for production)
    python -m api.scripts.mcp_watchdog_scheduler --daemon

    # Check status
    python -m api.scripts.mcp_watchdog_scheduler --status

Schedule:
    - Discovery scan: Every 12 hours
    - Typosquat check: Every 2 hours
    - Alert dispatch: Real-time when threats detected
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class MCPWatchdogScheduler:
    """Scheduler for MCP Watchdog operations."""

    def __init__(self):
        self.running = False
        self.tasks = []

    async def start(self, daemon_mode: bool = False):
        """Start the scheduler."""
        self.running = True
        logger.info("🐕 MCP Watchdog Scheduler starting...")

        if daemon_mode:
            # Set up signal handlers for graceful shutdown
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

        # Load configuration
        config = await self._load_config()
        if not config.get("enabled", True):
            logger.info("MCP Watchdog is disabled in configuration")
            return

        # Start background tasks
        self.tasks = [
            asyncio.create_task(self._discovery_scheduler(config)),
            asyncio.create_task(self._typosquat_scheduler(config)),
            asyncio.create_task(self._health_monitor()),
        ]

        try:
            # Wait for all tasks to complete (or be cancelled)
            await asyncio.gather(*self.tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info("Scheduler tasks cancelled")
        finally:
            logger.info("🐕 MCP Watchdog Scheduler stopped")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"Received signal {signum}, shutting down...")
        self.stop()

    def stop(self):
        """Stop the scheduler and cancel all tasks."""
        self.running = False
        for task in self.tasks:
            task.cancel()

    async def _load_config(self) -> dict:
        """Load configuration from api.database."""
        try:
            from database import db

            await db.connect()

            config = await db.select_one(
                "mcp_watchdog_config", {"id": "default_config"}
            )
            if config:
                return config
            else:
                # Create default config
                default_config = {
                    "id": "default_config",
                    "enabled": True,
                    "scan_interval_hours": 12,
                    "typosquat_threshold": 0.7,
                    "max_alerts_per_hour": 10,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }
                await db.insert("mcp_watchdog_config", default_config)
                return default_config

        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            # Return safe defaults
            return {
                "enabled": True,
                "scan_interval_hours": 12,
                "typosquat_threshold": 0.7,
                "max_alerts_per_hour": 10,
            }

    async def _discovery_scheduler(self, config: dict):
        """Schedule MCP server discovery scans."""
        interval_hours = config.get("scan_interval_hours", 12)

        while self.running:
            try:
                logger.info("🔍 Starting MCP server discovery scan...")
                await self._run_discovery()

                # Update last run time
                await self._update_config(
                    {"last_discovery_run": datetime.now(timezone.utc).isoformat()}
                )

                logger.info(
                    f"✅ Discovery scan complete. Next scan in {interval_hours} hours."
                )

                # Wait for next interval
                await asyncio.sleep(interval_hours * 3600)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Discovery scan failed: {e}")
                # Wait 1 hour before retry on error
                await asyncio.sleep(3600)

    async def _typosquat_scheduler(self, config: dict):
        """Schedule typosquat detection checks."""
        # Run typosquat checks every 2 hours
        check_interval = 2 * 3600  # 2 hours in seconds

        while self.running:
            try:
                logger.info("🚨 Starting typosquat detection check...")
                alerts_sent = await self._run_typosquat_check()

                # Update last check time and stats
                await self._update_config(
                    {
                        "last_typosquat_check": datetime.now(timezone.utc).isoformat(),
                        "total_alerts_sent": f"total_alerts_sent + {alerts_sent}",  # SQL increment
                    }
                )

                logger.info(f"✅ Typosquat check complete. {alerts_sent} alerts sent.")

                # Wait for next check
                await asyncio.sleep(check_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Typosquat check failed: {e}")
                # Wait 30 minutes before retry on error
                await asyncio.sleep(1800)

    async def _health_monitor(self):
        """Monitor scheduler health and log status."""
        while self.running:
            try:
                # Log status every hour
                from database import db

                # Count recent activity
                recent_scans = await db.select(
                    "public_scans",
                    filters={"ecosystem": "mcp"},
                    limit=10,
                    order_by="created_at",
                    order_desc=True,
                )

                recent_alerts = await db.select(
                    "typosquat_alerts",
                    filters={"ecosystem": "mcp"},
                    limit=10,
                    order_by="created_at",
                    order_desc=True,
                )

                logger.info(
                    f"🐕 MCP Watchdog Status: {len(recent_scans)} recent scans, "
                    f"{len(recent_alerts)} recent alerts"
                )

                await asyncio.sleep(3600)  # Log status every hour

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(3600)

    async def _run_discovery(self):
        """Run MCP server discovery."""
        from api.services.mcp_crawler import (
            discover_mcp_servers,
            store_mcp_results,
            scan_mcp_server,
        )

        # Discover new MCP servers
        servers = await discover_mcp_servers(max_pages=20)  # Comprehensive scan

        if not servers:
            logger.info("No new MCP servers discovered")
            return

        # Store server metadata
        from database import db

        stored_servers = 0

        for server in servers:
            now = datetime.now(timezone.utc)
            server_row = {
                "id": f"mcp_{server.repo_name.replace('/', '_')}",
                "repo_name": server.repo_name,
                "author": server.author,
                "description": server.description,
                "stars": server.stars,
                "forks": server.forks,
                "language": server.language,
                "topics": server.topics,  # Will be JSON serialized
                "homepage": server.homepage,
                "clone_url": server.clone_url,
                "mcp_config": server.mcp_config,  # Will be JSON serialized
                "first_seen": now.isoformat(),
                "last_updated": server.updated_at or now.isoformat(),
                "scan_status": "pending",
                "monitoring_enabled": True,
                "created_at": now.isoformat(),
            }

            try:
                # Use upsert to avoid duplicates
                await db.upsert(
                    "mcp_servers", server_row, conflict_columns=["repo_name"]
                )
                stored_servers += 1
            except Exception as e:
                logger.error(f"Failed to store MCP server {server.repo_name}: {e}")

        logger.info(f"📦 Stored {stored_servers} MCP servers")

        # Scan a subset of new/updated servers
        scan_results = []
        for server in servers[:5]:  # Limit to 5 scans per run to avoid overload
            try:
                result = await scan_mcp_server(server)
                scan_results.append(result)
            except Exception as e:
                logger.error(f"Failed to scan {server.repo_name}: {e}")

        if scan_results:
            stored_scans = await store_mcp_results(scan_results)
            logger.info(f"🔍 Completed {stored_scans} MCP server scans")

    async def _run_typosquat_check(self):
        """Run typosquat detection and send alerts."""
        from api.services.mcp_crawler import (
            detect_typosquats,
            send_typosquat_alerts,
            store_typosquat_alerts,
        )
        from database import db

        # Get all monitored MCP servers
        servers_data = await db.select(
            "mcp_servers",
            filters={"monitoring_enabled": True},
            limit=1000,  # Process up to 1000 servers
        )

        if not servers_data:
            logger.info("No MCP servers to check for typosquats")
            return 0

        # Convert to MCPServer objects for detection
        from api.services.mcp_crawler import MCPServer

        servers = []
        for server_data in servers_data:
            server = MCPServer(
                repo_name=server_data["repo_name"],
                author=server_data["author"],
                description=server_data.get("description", ""),
                stars=server_data.get("stars", 0),
                created_at=server_data.get("first_seen", ""),
                updated_at=server_data.get("last_updated", ""),
            )
            servers.append(server)

        # Detect typosquats
        alerts = await detect_typosquats(servers)

        if not alerts:
            logger.info("No typosquat threats detected")
            return 0

        # Filter out alerts we've already sent
        new_alerts = []
        for alert in alerts:
            existing = await db.select_one(
                "typosquat_alerts",
                {
                    "suspicious_package": alert.suspicious_repo,
                    "target_package": alert.target_repo,
                },
            )
            if not existing:
                new_alerts.append(alert)

        if not new_alerts:
            logger.info("No new typosquat alerts to send")
            return 0

        # Store alerts
        await store_typosquat_alerts(new_alerts)

        # Send alerts (rate limited)
        config = await self._load_config()
        max_alerts = config.get("max_alerts_per_hour", 10)

        alerts_to_send = new_alerts[:max_alerts]  # Rate limit
        alerts_sent = await send_typosquat_alerts(alerts_to_send)

        logger.info(
            f"🚨 Found {len(alerts)} total typosquat threats, "
            f"{len(new_alerts)} new, sent {alerts_sent} alerts"
        )

        return alerts_sent

    async def _update_config(self, updates: dict):
        """Update configuration in database."""
        try:
            from database import db

            config = await db.select_one(
                "mcp_watchdog_config", {"id": "default_config"}
            )
            if config:
                config.update(updates)
                config["updated_at"] = datetime.now(timezone.utc).isoformat()
                await db.upsert("mcp_watchdog_config", config)

        except Exception as e:
            logger.error(f"Failed to update config: {e}")


async def run_once():
    """Run the watchdog once (for testing or manual execution)."""
    scheduler = MCPWatchdogScheduler()

    logger.info("🐕 Running MCP Watchdog once...")

    # Load config
    await scheduler._load_config()

    # Run discovery
    await scheduler._run_discovery()

    # Run typosquat check
    alerts_sent = await scheduler._run_typosquat_check()

    logger.info(f"✅ MCP Watchdog run complete. {alerts_sent} alerts sent.")


async def show_status():
    """Show current MCP Watchdog status."""
    try:
        from database import db

        await db.connect()

        # Get configuration
        config = await db.select_one("mcp_watchdog_config", {"id": "default_config"})

        # Get recent stats
        recent_scans = await db.select(
            "public_scans",
            filters={"ecosystem": "mcp"},
            limit=1,
            order_by="created_at",
            order_desc=True,
        )

        recent_alerts = await db.select(
            "typosquat_alerts",
            filters={"ecosystem": "mcp"},
            limit=1,
            order_by="created_at",
            order_desc=True,
        )

        total_servers = await db.select("mcp_servers", limit=1000)
        total_alerts = await db.select(
            "typosquat_alerts", filters={"ecosystem": "mcp"}, limit=1000
        )

        print("🐕 MCP Watchdog Status")
        print("=" * 50)

        if config:
            print(f"Enabled: {config.get('enabled', 'unknown')}")
            print(
                f"Scan Interval: {config.get('scan_interval_hours', 'unknown')} hours"
            )
            print(f"Last Discovery: {config.get('last_discovery_run', 'never')}")
            print(
                f"Last Typosquat Check: {config.get('last_typosquat_check', 'never')}"
            )
        else:
            print("Configuration: Not found")

        print(f"\nDiscovered Servers: {len(total_servers) if total_servers else 0}")
        print(f"Total Alerts: {len(total_alerts) if total_alerts else 0}")

        if recent_scans:
            print(f"Last Scan: {recent_scans[0].get('scanned_at', 'unknown')}")

        if recent_alerts:
            print(f"Last Alert: {recent_alerts[0].get('created_at', 'unknown')}")

        print("\nFeeds Available:")
        print("- RSS: /feed/mcp.xml (MCP server scans)")
        print("- RSS: /feed/watchdog.xml (typosquat alerts)")
        print("- JSON: /api/v1/feed/mcp-watchdog (typosquat alerts)")
        print("- JSON: /api/v1/feed/mcp-servers (discovered servers)")

    except Exception as e:
        print(f"❌ Failed to get status: {e}")


async def main():
    import argparse

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    parser = argparse.ArgumentParser(description="Sigil MCP Watchdog Scheduler")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--daemon", action="store_true", help="Run as daemon")
    group.add_argument("--run-once", action="store_true", help="Run once and exit")
    group.add_argument("--status", action="store_true", help="Show status")

    args = parser.parse_args()

    if args.status:
        await show_status()
    elif args.run_once:
        await run_once()
    elif args.daemon:
        scheduler = MCPWatchdogScheduler()
        await scheduler.start(daemon_mode=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("🐕 MCP Watchdog Scheduler interrupted by user")
        sys.exit(0)
