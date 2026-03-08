"""
Tool Metrics Collection Background Job

Fetches tool download/star counts from various registries (npm, PyPI, GitHub)
and stores in forge_tool_metrics table with daily granularity.
Designed to be run by a cron job every 6 hours.
"""

import asyncio
import logging
import sys
import httpx
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Add the parent directory to the path so we can import from api
sys.path.append(str(Path(__file__).parent.parent))

from database import db
from config import settings

logger = logging.getLogger(__name__)


@dataclass
class ToolMetrics:
    """Data class for tool metrics."""

    tool_id: str
    date: date
    downloads: int = 0
    stars: int = 0
    version: Optional[str] = None
    forks: int = 0
    issues_open: int = 0
    issues_closed: int = 0
    trust_score: float = 0.0


class RegistryClient:
    """Base class for registry API clients."""

    def __init__(self, timeout: int = 30):
        self.client = httpx.AsyncClient(timeout=timeout)

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()


class NpmRegistryClient(RegistryClient):
    """Client for NPM registry API."""

    BASE_URL = "https://api.npmjs.org"

    async def get_package_info(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Fetch package info from NPM registry."""
        try:
            url = f"{self.BASE_URL}/downloads/point/last-day/{package_name}"
            response = await self.client.get(url)

            if response.status_code == 404:
                logger.warning(f"NPM package not found: {package_name}")
                return None

            response.raise_for_status()
            downloads_data = response.json()

            # Get package metadata
            metadata_url = f"https://registry.npmjs.org/{package_name}"
            metadata_response = await self.client.get(metadata_url)
            metadata_response.raise_for_status()
            metadata = metadata_response.json()

            return {
                "downloads": downloads_data.get("downloads", 0),
                "version": metadata.get("dist-tags", {}).get("latest", "unknown"),
                "repository": metadata.get("repository", {}),
                "stars": 0,  # NPM doesn't track stars directly
                "name": package_name,
            }

        except Exception as e:
            logger.error(f"Failed to fetch NPM data for {package_name}: {e}")
            return None


class PyPiRegistryClient(RegistryClient):
    """Client for PyPI registry API."""

    BASE_URL = "https://pypi.org/pypi"

    async def get_package_info(self, package_name: str) -> Optional[Dict[str, Any]]:
        """Fetch package info from PyPI registry."""
        try:
            url = f"{self.BASE_URL}/{package_name}/json"
            response = await self.client.get(url)

            if response.status_code == 404:
                logger.warning(f"PyPI package not found: {package_name}")
                return None

            response.raise_for_status()
            data = response.json()

            # PyPI doesn't provide download stats directly
            # We'll use a placeholder and enhance later with pypistats
            return {
                "downloads": 0,  # Would need pypistats API
                "version": data["info"]["version"],
                "repository": data["info"].get("project_urls", {}),
                "stars": 0,  # PyPI doesn't track stars
                "name": package_name,
            }

        except Exception as e:
            logger.error(f"Failed to fetch PyPI data for {package_name}: {e}")
            return None


class GitHubRegistryClient(RegistryClient):
    """Client for GitHub API."""

    BASE_URL = "https://api.github.com"

    def __init__(self, timeout: int = 30):
        super().__init__(timeout)
        # Add GitHub token if available
        if hasattr(settings, "github_token") and settings.github_token:
            self.client.headers.update(
                {"Authorization": f"Bearer {settings.github_token}"}
            )

    async def get_repository_info(self, repo_path: str) -> Optional[Dict[str, Any]]:
        """Fetch repository info from GitHub API."""
        try:
            url = f"{self.BASE_URL}/repos/{repo_path}"
            response = await self.client.get(url)

            if response.status_code == 404:
                logger.warning(f"GitHub repository not found: {repo_path}")
                return None

            response.raise_for_status()
            data = response.json()

            # Get releases info for download counts
            releases_url = f"{self.BASE_URL}/repos/{repo_path}/releases"
            releases_response = await self.client.get(releases_url)
            releases_data = (
                releases_response.json() if releases_response.status_code == 200 else []
            )

            total_downloads = 0
            latest_version = "unknown"

            if releases_data:
                latest_version = releases_data[0].get("tag_name", "unknown")
                for release in releases_data:
                    for asset in release.get("assets", []):
                        total_downloads += asset.get("download_count", 0)

            return {
                "downloads": total_downloads,
                "stars": data["stargazers_count"],
                "forks": data["forks_count"],
                "issues_open": data["open_issues_count"],
                "issues_closed": 0,  # Would need separate API call
                "version": latest_version,
                "name": data["full_name"],
            }

        except Exception as e:
            logger.error(f"Failed to fetch GitHub data for {repo_path}: {e}")
            return None


class ToolMetricsCollector:
    """Main class for collecting tool metrics from various registries."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    async def get_tools_from_database(self) -> List[Dict[str, str]]:
        """Fetch list of tools to collect metrics for from database."""
        try:
            # Use the global db client
                # Assuming we have a tools table or can derive from existing data
                # This would need to match your existing forge schema
                tools = await db.execute_raw_sql("""
                    SELECT DISTINCT tool_id, ecosystem, repository_url, package_name
                    FROM forge_tools 
                    WHERE status = 'active'
                    ORDER BY tool_id
                """, [])

                return [dict(row) for row in tools] if tools else []

        except Exception as e:
            self.logger.error(f"Failed to fetch tools from database: {e}")
            # Return some mock data for testing
            return [
                {
                    "tool_id": "test-npm-tool",
                    "ecosystem": "npm",
                    "repository_url": "https://github.com/example/tool",
                    "package_name": "example-tool",
                },
                {
                    "tool_id": "test-pypi-tool",
                    "ecosystem": "pypi",
                    "repository_url": "https://github.com/example/python-tool",
                    "package_name": "example-python-tool",
                },
            ]

    async def collect_metrics_for_tool(
        self, tool: Dict[str, str]
    ) -> Optional[ToolMetrics]:
        """Collect metrics for a single tool."""
        tool_id = tool["tool_id"]
        ecosystem = tool.get("ecosystem", "").lower()
        package_name = tool.get("package_name", "")
        repo_url = tool.get("repository_url", "")

        self.logger.info(f"Collecting metrics for {tool_id} ({ecosystem})")

        metrics = ToolMetrics(tool_id=tool_id, date=date.today())

        try:
            if ecosystem == "npm" and package_name:
                async with NpmRegistryClient() as client:
                    data = await client.get_package_info(package_name)
                    if data:
                        metrics.downloads = data.get("downloads", 0)
                        metrics.version = data.get("version", "unknown")

            elif ecosystem == "pypi" and package_name:
                async with PyPiRegistryClient() as client:
                    data = await client.get_package_info(package_name)
                    if data:
                        metrics.version = data.get("version", "unknown")

            # Always try to get GitHub data if repo URL is available
            if repo_url and "github.com" in repo_url:
                try:
                    # Extract repo path from URL
                    repo_path = repo_url.replace("https://github.com/", "").replace(
                        "http://github.com/", ""
                    )
                    repo_path = repo_path.rstrip("/").split("/")[:2]
                    repo_path = "/".join(repo_path)

                    async with GitHubRegistryClient() as client:
                        github_data = await client.get_repository_info(repo_path)
                        if github_data:
                            metrics.stars = github_data.get("stars", 0)
                            metrics.forks = github_data.get("forks", 0)
                            metrics.issues_open = github_data.get("issues_open", 0)
                            # Override downloads with GitHub releases if higher
                            github_downloads = github_data.get("downloads", 0)
                            if github_downloads > metrics.downloads:
                                metrics.downloads = github_downloads
                            # Override version with GitHub release if available
                            if github_data.get("version") != "unknown":
                                metrics.version = github_data.get("version")

                except Exception as e:
                    self.logger.warning(
                        f"Failed to parse GitHub URL for {tool_id}: {e}"
                    )

            # Calculate basic trust score based on available metrics
            metrics.trust_score = self._calculate_trust_score(metrics)

            return metrics

        except Exception as e:
            self.logger.error(f"Failed to collect metrics for {tool_id}: {e}")
            return None

    def _calculate_trust_score(self, metrics: ToolMetrics) -> float:
        """Calculate a basic trust score based on available metrics."""
        score = 0.0

        # Stars contribute to trust (logarithmic scale)
        if metrics.stars > 0:
            score += min(30, metrics.stars / 10)  # Max 30 points for stars

        # Downloads/usage contribute to trust
        if metrics.downloads > 0:
            score += min(25, metrics.downloads / 100)  # Max 25 points for downloads

        # Forks indicate community engagement
        if metrics.forks > 0:
            score += min(20, metrics.forks * 2)  # Max 20 points for forks

        # Having a version indicates maintenance
        if metrics.version and metrics.version != "unknown":
            score += 15  # 15 points for having a version

        # Low open issues relative to popularity is good
        if metrics.stars > 0 and metrics.issues_open >= 0:
            issue_ratio = metrics.issues_open / max(metrics.stars, 1)
            if issue_ratio < 0.1:
                score += 10  # 10 points for low issue ratio

        return min(100.0, score)

    async def store_metrics(self, metrics: ToolMetrics) -> bool:
        """Store metrics in database."""
        try:
            # Use the global db client
                await db.execute_raw_sql(
                    """
                    MERGE forge_tool_metrics AS target
                    USING (VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)) AS source 
                        (tool_id, date, downloads, stars, version, forks, issues_open, issues_closed, trust_score)
                    ON target.tool_id = source.tool_id AND target.date = source.date
                    WHEN MATCHED THEN 
                        UPDATE SET 
                            downloads = source.downloads,
                            stars = source.stars,
                            version = source.version,
                            forks = source.forks,
                            issues_open = source.issues_open,
                            issues_closed = source.issues_closed,
                            trust_score = source.trust_score,
                            updated_at = GETUTCDATE()
                    WHEN NOT MATCHED THEN
                        INSERT (tool_id, date, downloads, stars, version, forks, issues_open, issues_closed, trust_score)
                        VALUES (source.tool_id, source.date, source.downloads, source.stars, 
                               source.version, source.forks, source.issues_open, source.issues_closed, source.trust_score);
                """,
                    metrics.tool_id,
                    metrics.date,
                    metrics.downloads,
                    metrics.stars,
                    metrics.version,
                    metrics.forks,
                    metrics.issues_open,
                    metrics.issues_closed,
                    metrics.trust_score,
                )

                self.logger.info(
                    f"Stored metrics for {metrics.tool_id}: "
                    f"{metrics.downloads} downloads, {metrics.stars} stars"
                )
                return True

        except Exception as e:
            self.logger.error(f"Failed to store metrics for {metrics.tool_id}: {e}")
            return False

    async def collect_all_metrics(self) -> None:
        """Main entry point to collect metrics for all tools."""
        self.logger.info("Starting tool metrics collection...")

        tools = await self.get_tools_from_database()
        if not tools:
            self.logger.warning("No tools found to collect metrics for")
            return

        self.logger.info(f"Collecting metrics for {len(tools)} tools")

        successful = 0
        failed = 0

        for tool in tools:
            try:
                metrics = await self.collect_metrics_for_tool(tool)
                if metrics and await self.store_metrics(metrics):
                    successful += 1
                else:
                    failed += 1

                # Add small delay to avoid rate limiting
                await asyncio.sleep(0.1)

            except Exception as e:
                self.logger.error(
                    f"Error processing tool {tool.get('tool_id', 'unknown')}: {e}"
                )
                failed += 1

        self.logger.info(
            f"Metrics collection completed. Success: {successful}, Failed: {failed}"
        )


async def main():
    """Main function for running the metrics collection job."""
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    collector = ToolMetricsCollector()

    try:
        await collector.collect_all_metrics()
    except Exception as e:
        logger.error(f"Metrics collection job failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
