"""
Sigil API — MCP Permissions Map

Static page generator and API for MCP server permissions and access requirements.
Shows exactly what each MCP server can access on your machine.

Endpoints:
    GET /permissions                    — Main permissions directory
    GET /permissions/{mcp_name}         — Individual MCP server permissions page
    GET /api/v1/permissions/{mcp_name}  — JSON API for permissions data
    GET /api/v1/permissions/search      — Search MCP servers by permissions
"""

from __future__ import annotations

import html
import json
import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Path
from fastapi.responses import HTMLResponse

from api.database import db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["permissions"])

# Permissions categories and their descriptions
PERMISSION_CATEGORIES = {
    "environment": {
        "title": "Environment Variables",
        "description": "Environment variables this MCP server reads",
        "risk_level": "medium",
        "icon": "🔧",
    },
    "filesystem": {
        "title": "File System Access",
        "description": "Files and directories this MCP server accesses",
        "risk_level": "high",
        "icon": "📁",
    },
    "network": {
        "title": "Network Access",
        "description": "Network connections and external services",
        "risk_level": "medium",
        "icon": "🌐",
    },
    "database": {
        "title": "Database Access",
        "description": "Database connections and queries",
        "risk_level": "high",
        "icon": "💾",
    },
    "process": {
        "title": "Process Execution",
        "description": "External processes and system commands",
        "risk_level": "critical",
        "icon": "⚡",
    },
    "credentials": {
        "title": "Credentials & Secrets",
        "description": "API keys, tokens, and authentication",
        "risk_level": "critical",
        "icon": "🔐",
    },
}


def extract_permissions_from_scan(scan_data: dict) -> dict[str, list[str]]:
    """Extract permissions from Sigil scan findings."""
    permissions = {
        "environment": [],
        "filesystem": [],
        "network": [],
        "database": [],
        "process": [],
        "credentials": [],
    }

    findings = scan_data.get("findings_json", [])
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except (json.JSONDecodeError, TypeError):
            findings = []

    for finding in findings:
        snippet = finding.get("snippet", "").lower()
        rule = finding.get("rule", "").lower()

        # Environment variables
        env_patterns = [
            r"process\.env\.([A-Z_][A-Z0-9_]*)",
            r"os\.environ\[?['\"]([A-Z_][A-Z0-9_]*)['\"]?\]?",
            r"getenv\(['\"]([A-Z_][A-Z0-9_]*)['\"]?\)",
            r"\$\{?([A-Z_][A-Z0-9_]*)\}?",
        ]
        for pattern in env_patterns:
            matches = re.findall(pattern, snippet, re.IGNORECASE)
            for match in matches:
                env_var = match.upper()
                if env_var not in permissions["environment"]:
                    permissions["environment"].append(env_var)

        # File system access
        if any(
            keyword in rule
            for keyword in ["file", "path", "directory", "read", "write"]
        ):
            file_patterns = [
                r"([~/]\S+\.\w+)",
                r"(/[a-zA-Z0-9/_.-]+)",
                r"(\.\/[a-zA-Z0-9/_.-]+)",
            ]
            for pattern in file_patterns:
                matches = re.findall(pattern, snippet)
                for match in matches:
                    if match not in permissions["filesystem"]:
                        permissions["filesystem"].append(match)

        # Network access
        if any(keyword in rule for keyword in ["network", "http", "url", "request"]):
            network_patterns = [
                r"https?://([^/\s]+)",
                r"localhost:(\d+)",
                r":(\d+)",  # Port numbers
            ]
            for pattern in network_patterns:
                matches = re.findall(pattern, snippet)
                for match in matches:
                    if match not in permissions["network"]:
                        permissions["network"].append(match)

        # Database patterns
        db_indicators = [
            "database",
            "sql",
            "postgres",
            "mysql",
            "mongodb",
            "redis",
            "sqlite",
        ]
        if any(
            indicator in rule or indicator in snippet for indicator in db_indicators
        ):
            permissions["database"].append("Database connection required")

        # Process execution
        if any(keyword in rule for keyword in ["exec", "process", "spawn", "command"]):
            process_patterns = [
                r"exec\(['\"]([^'\"]+)['\"]",
                r"spawn\(['\"]([^'\"]+)['\"]",
                r"system\(['\"]([^'\"]+)['\"]",
            ]
            for pattern in process_patterns:
                matches = re.findall(pattern, snippet)
                for match in matches:
                    if match not in permissions["process"]:
                        permissions["process"].append(match)

        # Credentials
        cred_patterns = [
            r"(api[_-]?key)",
            r"(access[_-]?token)",
            r"(secret[_-]?key)",
            r"(password)",
            r"(token)",
            r"(credential)",
        ]
        for pattern in cred_patterns:
            if re.search(pattern, snippet, re.IGNORECASE):
                if "Requires authentication" not in permissions["credentials"]:
                    permissions["credentials"].append("Requires authentication")

    # Remove empty categories and duplicates
    return {k: list(set(v)) for k, v in permissions.items() if v}


def calculate_risk_score(permissions: dict[str, list[str]]) -> tuple[int, str]:
    """Calculate overall risk score based on permissions."""
    score = 0

    # Weight different permission types
    weights = {
        "process": 10,  # Critical - can execute system commands
        "credentials": 8,  # Critical - access to secrets
        "filesystem": 6,  # High - file access
        "database": 6,  # High - data access
        "network": 4,  # Medium - external connections
        "environment": 2,  # Low-medium - env var access
    }

    for category, items in permissions.items():
        if items and category in weights:
            score += weights[category] * len(items)

    # Determine risk level
    if score >= 20:
        risk_level = "HIGH"
    elif score >= 10:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level


@router.get(
    "/permissions", response_class=HTMLResponse, summary="MCP Permissions Directory"
)
async def permissions_directory() -> HTMLResponse:
    """Main directory of all MCP servers with permissions summary."""
    try:
        # Get all MCP server scans
        scans = await db.select(
            "public_scans",
            filters={"ecosystem": "mcp"},
            limit=100,
            order_by="created_at",
            order_desc=True,
        )

        servers = []
        for scan in scans:
            metadata = scan.get("metadata_json", {})
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            permissions = extract_permissions_from_scan(scan)
            risk_score, risk_level = calculate_risk_score(permissions)

            servers.append(
                {
                    "name": scan["package_name"],
                    "author": metadata.get("author", "unknown"),
                    "description": metadata.get("description", ""),
                    "stars": metadata.get("stars", 0),
                    "risk_level": risk_level,
                    "risk_score": risk_score,
                    "permissions_count": sum(len(v) for v in permissions.values()),
                    "categories": list(permissions.keys()),
                }
            )

        # Sort by popularity (stars) and risk
        servers.sort(key=lambda x: (x["stars"], -x["risk_score"]), reverse=True)

        # Generate HTML
        rows = []
        for server in servers:
            risk_color = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#dc3545"}
            risk_emoji = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨"}

            category_badges = " ".join(
                [
                    f'<span class="badge">{PERMISSION_CATEGORIES.get(cat, {}).get("icon", "")}</span>'
                    for cat in server["categories"][:4]  # Show first 4 categories
                ]
            )

            # Escape all user-controlled data for HTML output
            safe_name = html.escape(server["name"])
            safe_author = html.escape(server["author"])
            safe_desc = html.escape(server["description"][:80])

            rows.append(f"""
            <tr>
                <td>
                    <a href="/permissions/{safe_name}" class="server-name">{safe_name}</a>
                    <div class="server-meta">by {safe_author} • ⭐ {server["stars"]}</div>
                </td>
                <td>{safe_desc}{"..." if len(server["description"]) > 80 else ""}</td>
                <td class="text-center">{category_badges}</td>
                <td class="text-center">
                    <span class="risk-badge" style="background-color: {risk_color[server["risk_level"]]}">
                        {risk_emoji[server["risk_level"]]} {server["risk_level"]}
                    </span>
                </td>
            </tr>""")

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>MCP Permissions Map | Sigil Security</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background: #f8f9fa;
                }}
                .header {{
                    text-align: center;
                    margin-bottom: 40px;
                    padding: 30px;
                    background: white;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header h1 {{
                    margin: 0 0 10px 0;
                    color: #2c3e50;
                }}
                .header .subtitle {{
                    color: #7f8c8d;
                    font-size: 18px;
                }}
                .stats {{
                    display: flex;
                    justify-content: space-around;
                    margin: 20px 0;
                    padding: 20px;
                    background: #e9ecef;
                    border-radius: 8px;
                }}
                .stat {{
                    text-align: center;
                }}
                .stat-number {{
                    font-size: 28px;
                    font-weight: bold;
                    color: #2c3e50;
                }}
                .stat-label {{
                    font-size: 14px;
                    color: #7f8c8d;
                }}
                table {{
                    width: 100%;
                    background: white;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                th {{
                    background: #3498db;
                    color: white;
                    padding: 15px;
                    text-align: left;
                }}
                td {{
                    padding: 15px;
                    border-bottom: 1px solid #eee;
                }}
                .server-name {{
                    font-weight: bold;
                    color: #3498db;
                    text-decoration: none;
                }}
                .server-name:hover {{
                    text-decoration: underline;
                }}
                .server-meta {{
                    font-size: 12px;
                    color: #7f8c8d;
                    margin-top: 5px;
                }}
                .badge {{
                    display: inline-block;
                    padding: 4px 8px;
                    margin: 2px;
                    background: #ecf0f1;
                    border-radius: 12px;
                    font-size: 14px;
                }}
                .risk-badge {{
                    padding: 6px 12px;
                    border-radius: 20px;
                    color: white;
                    font-weight: bold;
                    font-size: 12px;
                }}
                .text-center {{
                    text-align: center;
                }}
                .footer {{
                    margin-top: 40px;
                    text-align: center;
                    padding: 20px;
                    color: #7f8c8d;
                    background: white;
                    border-radius: 8px;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 MCP Permissions Map</h1>
                <div class="subtitle">See exactly what every MCP server can access</div>
                <div class="stats">
                    <div class="stat">
                        <div class="stat-number">{len(servers)}</div>
                        <div class="stat-label">MCP Servers</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">{sum(1 for s in servers if s["risk_level"] == "HIGH")}</div>
                        <div class="stat-label">High Risk</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">{sum(1 for s in servers if s["risk_level"] == "MEDIUM")}</div>
                        <div class="stat-label">Medium Risk</div>
                    </div>
                    <div class="stat">
                        <div class="stat-number">{sum(1 for s in servers if s["risk_level"] == "LOW")}</div>
                        <div class="stat-label">Low Risk</div>
                    </div>
                </div>
            </div>
            
            <table>
                <thead>
                    <tr>
                        <th>MCP Server</th>
                        <th>Description</th>
                        <th>Permissions</th>
                        <th>Risk Level</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(rows)}
                </tbody>
            </table>
            
            <div class="footer">
                <p>📊 Data from <a href="https://sigilsec.ai">Sigil Security Scanner</a> • 
                   🔄 Updated every 12 hours •
                   📡 <a href="/api/v1/permissions/search">JSON API</a></p>
            </div>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    except Exception as e:
        logger.exception("Failed to generate permissions directory")
        return HTMLResponse(
            content=f"<html><body><h1>Error</h1><p>Failed to load permissions: {e}</p></body></html>"
        )


@router.get(
    "/permissions/{mcp_name}",
    response_class=HTMLResponse,
    summary="Individual MCP server permissions",
)
async def mcp_permissions_page(
    mcp_name: str = Path(
        ..., min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_\-/]+$"
    ),
) -> HTMLResponse:
    """Detailed permissions page for a specific MCP server."""
    try:
        # Validate and sanitize MCP name
        if ".." in mcp_name or mcp_name.startswith("/"):
            raise HTTPException(status_code=400, detail="Invalid MCP server name")

        # Validate mcp_name is safe

        # Get scan data for this MCP server
        scan = await db.select_one(
            "public_scans", {"ecosystem": "mcp", "package_name": mcp_name}
        )

        if not scan:
            raise HTTPException(
                status_code=404, detail=f"MCP server '{mcp_name}' not found"
            )

        metadata = scan.get("metadata_json", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                metadata = {}

        permissions = extract_permissions_from_scan(scan)
        risk_score, risk_level = calculate_risk_score(permissions)

        # Generate permission sections
        sections = []
        for category, items in permissions.items():
            if not items:
                continue

            cat_info = PERMISSION_CATEGORIES.get(category, {})
            icon = cat_info.get("icon", "")
            title = cat_info.get("title", category.title())
            description = cat_info.get("description", "")
            cat_info.get("risk_level", "medium")

            # Escape items for safe HTML output
            items_html = "".join(
                [f"<li><code>{html.escape(item)}</code></li>" for item in items]
            )

            sections.append(f"""
            <div class="permission-section">
                <h3>{icon} {title}</h3>
                <p class="permission-desc">{description}</p>
                <ul class="permission-list">
                    {items_html}
                </ul>
            </div>""")

        # Risk level styling
        risk_colors = {"LOW": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#dc3545"}
        risk_emoji = {"LOW": "✅", "MEDIUM": "⚠️", "HIGH": "🚨"}

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{mcp_name} Permissions | Sigil Security</title>
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 800px;
                    margin: 0 auto;
                    padding: 20px;
                    background: #f8f9fa;
                }}
                .header {{
                    background: white;
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    margin-bottom: 30px;
                }}
                .header h1 {{
                    margin: 0;
                    color: #2c3e50;
                }}
                .server-meta {{
                    margin: 15px 0;
                    padding: 15px;
                    background: #ecf0f1;
                    border-radius: 8px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }}
                .risk-badge {{
                    padding: 8px 16px;
                    border-radius: 20px;
                    color: white;
                    font-weight: bold;
                    background: {risk_colors[risk_level]};
                }}
                .description {{
                    margin: 20px 0;
                    font-size: 16px;
                    color: #555;
                }}
                .permission-section {{
                    background: white;
                    padding: 20px;
                    margin-bottom: 20px;
                    border-radius: 8px;
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                }}
                .permission-section h3 {{
                    margin: 0 0 10px 0;
                    color: #2c3e50;
                }}
                .permission-desc {{
                    color: #7f8c8d;
                    margin-bottom: 15px;
                }}
                .permission-list {{
                    margin: 0;
                    padding-left: 20px;
                }}
                .permission-list li {{
                    margin: 8px 0;
                }}
                .permission-list code {{
                    background: #f8f9fa;
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-family: 'Monaco', 'Menlo', monospace;
                }}
                .actions {{
                    background: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                    margin-top: 30px;
                }}
                .btn {{
                    display: inline-block;
                    padding: 10px 20px;
                    margin: 0 10px;
                    border-radius: 6px;
                    text-decoration: none;
                    font-weight: bold;
                }}
                .btn-primary {{
                    background: #3498db;
                    color: white;
                }}
                .btn-secondary {{
                    background: #95a5a6;
                    color: white;
                }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{html.escape(mcp_name)}</h1>
                <div class="server-meta">
                    <div>
                        <strong>Author:</strong> {html.escape(metadata.get("author", "unknown"))}<br>
                        <strong>Stars:</strong> ⭐ {metadata.get("stars", 0)}<br>
                        <strong>Language:</strong> {html.escape(metadata.get("language", "unknown"))}
                    </div>
                    <div class="risk-badge">
                        {risk_emoji[risk_level]} {risk_level} RISK
                    </div>
                </div>
                <div class="description">
                    {html.escape(metadata.get("description", "No description available."))}
                </div>
            </div>
            
            {"".join(sections) if sections else '<div class="permission-section"><p>No specific permissions detected. This MCP server may have limited system access.</p></div>'}
            
            <div class="actions">
                <a href="https://github.com/{html.escape(mcp_name, quote=True)}" class="btn btn-primary">View on GitHub</a>
                <a href="/api/v1/permissions/{html.escape(mcp_name, quote=True)}" class="btn btn-secondary">JSON API</a>
                <a href="/permissions" class="btn btn-secondary">← Back to Directory</a>
            </div>
        </body>
        </html>
        """

        return HTMLResponse(content=html_content)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to generate permissions page for %s", mcp_name)
        return HTMLResponse(
            content=f"<html><body><h1>Error</h1><p>Failed to load permissions for {mcp_name}: {e}</p></body></html>",
            status_code=500,
        )


@router.get("/api/v1/permissions/{mcp_name}", summary="MCP server permissions JSON API")
async def mcp_permissions_api(
    mcp_name: str = Path(
        ..., min_length=1, max_length=200, pattern=r"^[a-zA-Z0-9_\-/]+$"
    ),
) -> dict[str, Any]:
    """Get permissions data for an MCP server as JSON."""
    try:
        # Validate MCP name
        if ".." in mcp_name or mcp_name.startswith("/"):
            raise HTTPException(status_code=400, detail="Invalid MCP server name")

        scan = await db.select_one(
            "public_scans", {"ecosystem": "mcp", "package_name": mcp_name}
        )

        if not scan:
            raise HTTPException(
                status_code=404, detail=f"MCP server '{mcp_name}' not found"
            )

        metadata = scan.get("metadata_json", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except (json.JSONDecodeError, TypeError):
                metadata = {}

        permissions = extract_permissions_from_scan(scan)
        risk_score, risk_level = calculate_risk_score(permissions)

        return {
            "name": mcp_name,
            "author": metadata.get("author", "unknown"),
            "description": metadata.get("description", ""),
            "stars": metadata.get("stars", 0),
            "language": metadata.get("language", "unknown"),
            "risk_score": risk_score,
            "risk_level": risk_level,
            "permissions": permissions,
            "permissions_count": sum(len(v) for v in permissions.values()),
            "github_url": f"https://github.com/{mcp_name}",
            "scanned_at": scan["scanned_at"],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to get permissions for %s", mcp_name)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/v1/permissions/search", summary="Search MCP servers by permissions")
async def search_permissions(
    permission: str | None = Query(
        None,
        description="Permission type (environment, filesystem, network, etc.)",
        pattern="^(environment|filesystem|network|database|process|credentials)$",
    ),
    risk_level: str | None = Query(
        None,
        description="Risk level (LOW, MEDIUM, HIGH)",
        pattern="^(LOW|MEDIUM|HIGH)$",
    ),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
) -> list[dict[str, Any]]:
    """Search MCP servers by permission types or risk levels."""
    try:
        scans = await db.select(
            "public_scans",
            filters={"ecosystem": "mcp"},
            limit=limit * 2,  # Get extra to filter
            order_by="created_at",
            order_desc=True,
        )

        results = []
        for scan in scans:
            metadata = scan.get("metadata_json", {})
            if isinstance(metadata, str):
                try:
                    metadata = json.loads(metadata)
                except (json.JSONDecodeError, TypeError):
                    metadata = {}

            permissions = extract_permissions_from_scan(scan)
            calc_risk_score, calc_risk_level = calculate_risk_score(permissions)

            # Apply filters
            if permission and permission.lower() not in permissions:
                continue

            if risk_level and calc_risk_level != risk_level.upper():
                continue

            results.append(
                {
                    "name": scan["package_name"],
                    "author": metadata.get("author", "unknown"),
                    "description": metadata.get("description", "")[:100]
                    + ("..." if len(metadata.get("description", "")) > 100 else ""),
                    "stars": metadata.get("stars", 0),
                    "risk_level": calc_risk_level,
                    "risk_score": calc_risk_score,
                    "permissions": permissions,
                    "permissions_count": sum(len(v) for v in permissions.values()),
                    "github_url": f"https://github.com/{scan['package_name']}",
                    "permissions_url": f"/permissions/{scan['package_name']}",
                }
            )

            if len(results) >= limit:
                break

        return results

    except Exception as e:
        logger.exception("Failed to search permissions")
        raise HTTPException(status_code=500, detail=str(e))
