"""
Sigil Forge — API Endpoints

Provides REST API access to Forge classification data, matches, and stacks.
Supports both human and agent consumption.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from api.database import db
from api.services.forge_matcher import forge_matcher

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/forge", tags=["Sigil Forge"])


# ============================================================================
# Enums
# ============================================================================


class ToolCategory(str, Enum):
    """Categories for AI tools and MCPs."""

    AI_LLM_TOOLS = "ai_llm_tools"
    API_INTEGRATIONS = "api_integrations"
    CODE_TOOLS = "code_tools"
    COMMUNICATION_TOOLS = "communication_tools"
    DATABASE_CONNECTORS = "database_connectors"
    DATA_TOOLS = "data_tools"
    DEVOPS_TOOLS = "devops_tools"
    FILE_SYSTEM_TOOLS = "file_system_tools"
    MONITORING_TOOLS = "monitoring_tools"
    SEARCH_TOOLS = "search_tools"
    SECURITY_TOOLS = "security_tools"
    TESTING_TOOLS = "testing_tools"


class ToolCapability(str, Enum):
    """Capabilities that tools can provide."""

    AI_LLM = "ai_llm"
    AUTHENTICATION = "authentication"
    CODE = "code"
    DATABASE = "database"
    NETWORK = "network"
    SECURITY = "security"


# ============================================================================
# Tool Classification Model
# ============================================================================


class ClassifiedTool(BaseModel):
    """Result of tool classification."""

    name: str
    ecosystem: str
    category: ToolCategory
    capabilities: list[ToolCapability]
    trust_score: int
    verdict: str
    compatibility_signals: list[str]
    github_url: str | None = None
    install_command: str | None = None


# ============================================================================
# Helper Functions
# ============================================================================


async def classify_tool(ecosystem: str, name: str, scan_data: dict) -> ClassifiedTool:
    """Classify a tool based on its scan data and metadata."""
    # Basic classification logic for tests
    description = scan_data.get("metadata", {}).get("description", "")
    risk_score = scan_data.get("risk_score", 0)
    findings = scan_data.get("findings", [])

    # Determine category based on name and description
    category = _determine_category(name, description)

    # Determine capabilities based on findings and metadata
    capabilities = _determine_capabilities(findings, description)

    # Calculate trust score (100 - risk_score)
    trust_score = max(0, 100 - risk_score)

    # Extract compatibility signals
    compatibility_signals = _extract_compatibility_signals(findings)

    # Build GitHub URL if available
    github_url = None
    repo_url = scan_data.get("metadata", {}).get("repository", {}).get("url")
    if repo_url and "github.com" in repo_url:
        github_url = repo_url

    # Build install command
    install_command = None
    if ecosystem == "skill":
        install_command = f"npx skills add {name}"
    elif ecosystem == "mcp":
        install_command = f"npm install {name}"

    return ClassifiedTool(
        name=name,
        ecosystem=ecosystem,
        category=category,
        capabilities=capabilities,
        trust_score=trust_score,
        verdict=scan_data.get("verdict", "UNKNOWN"),
        compatibility_signals=compatibility_signals,
        github_url=github_url,
        install_command=install_command,
    )


def _determine_category(name: str, description: str) -> ToolCategory:
    """Determine tool category based on name and description."""
    name_lower = name.lower()
    desc_lower = description.lower()

    # Database related
    if any(
        term in name_lower
        for term in ["postgres", "mysql", "redis", "mongo", "db", "database"]
    ):
        return ToolCategory.DATABASE_CONNECTORS
    if any(
        term in desc_lower for term in ["database", "redis", "sql", "postgres", "mysql"]
    ):
        return ToolCategory.DATABASE_CONNECTORS

    # AI/LLM related
    if any(term in name_lower for term in ["gpt", "ai", "llm", "chat", "assistant"]):
        return ToolCategory.AI_LLM_TOOLS
    if any(term in desc_lower for term in ["gpt", "ai", "llm", "assistant", "chat"]):
        return ToolCategory.AI_LLM_TOOLS

    # Security related
    if any(term in name_lower for term in ["security", "audit", "scan"]):
        return ToolCategory.SECURITY_TOOLS
    if any(term in desc_lower for term in ["security", "audit", "vulnerabilit"]):
        return ToolCategory.SECURITY_TOOLS

    # API related
    if any(term in name_lower for term in ["api", "rest", "gateway"]):
        return ToolCategory.API_INTEGRATIONS
    if any(term in desc_lower for term in ["api", "rest", "gateway"]):
        return ToolCategory.API_INTEGRATIONS

    # Code tools
    if any(term in name_lower for term in ["lint", "format", "eslint", "code"]):
        return ToolCategory.CODE_TOOLS
    if any(term in desc_lower for term in ["lint", "format", "code", "syntax"]):
        return ToolCategory.CODE_TOOLS

    # File system
    if any(term in name_lower for term in ["file", "fs", "filesystem"]):
        return ToolCategory.FILE_SYSTEM_TOOLS
    if any(term in desc_lower for term in ["file", "filesystem", "directory"]):
        return ToolCategory.FILE_SYSTEM_TOOLS

    # DevOps
    if any(term in name_lower for term in ["docker", "deploy", "k8s", "kubernetes"]):
        return ToolCategory.DEVOPS_TOOLS
    if any(term in desc_lower for term in ["deploy", "docker", "kubernetes"]):
        return ToolCategory.DEVOPS_TOOLS

    # Search
    if any(term in name_lower for term in ["search", "elastic", "solr"]):
        return ToolCategory.SEARCH_TOOLS
    if any(term in desc_lower for term in ["search", "elastic", "index"]):
        return ToolCategory.SEARCH_TOOLS

    # Communication
    if any(term in name_lower for term in ["slack", "discord", "chat", "bot"]):
        return ToolCategory.COMMUNICATION_TOOLS
    if any(term in desc_lower for term in ["slack", "discord", "communication"]):
        return ToolCategory.COMMUNICATION_TOOLS

    # Monitoring
    if any(term in name_lower for term in ["monitor", "datadog", "metrics"]):
        return ToolCategory.MONITORING_TOOLS
    if any(term in desc_lower for term in ["monitor", "metrics", "observability"]):
        return ToolCategory.MONITORING_TOOLS

    # Data
    if any(term in name_lower for term in ["etl", "data", "pipeline"]):
        return ToolCategory.DATA_TOOLS
    if any(term in desc_lower for term in ["etl", "data", "pipeline"]):
        return ToolCategory.DATA_TOOLS

    # Testing
    if any(term in name_lower for term in ["test", "jest", "pytest", "spec"]):
        return ToolCategory.TESTING_TOOLS
    if any(term in desc_lower for term in ["test", "testing", "jest", "pytest"]):
        return ToolCategory.TESTING_TOOLS

    # Default fallback
    return ToolCategory.API_INTEGRATIONS


def _determine_capabilities(findings: list, description: str) -> list[ToolCapability]:
    """Determine tool capabilities based on findings and description."""
    capabilities = []
    desc_lower = description.lower()

    # Check findings for capability indicators
    for finding in findings:
        snippet = finding.get("snippet", "").lower()
        phase = finding.get("phase", "")

        if phase == "credentials" or "env" in snippet or "password" in snippet:
            capabilities.append(ToolCapability.AUTHENTICATION)
        if phase == "network_exfil" or "fetch" in snippet or "http" in snippet:
            capabilities.append(ToolCapability.NETWORK)
        if "database" in snippet or "sql" in snippet:
            capabilities.append(ToolCapability.DATABASE)
        if "security" in snippet or "audit" in snippet:
            capabilities.append(ToolCapability.SECURITY)
        if "code" in snippet or "eval" in snippet:
            capabilities.append(ToolCapability.CODE)

    # Check description for capability indicators
    if any(term in desc_lower for term in ["database", "sql", "postgres", "mysql"]):
        capabilities.append(ToolCapability.DATABASE)
    if any(term in desc_lower for term in ["ai", "gpt", "llm", "assistant"]):
        capabilities.append(ToolCapability.AI_LLM)
    if any(term in desc_lower for term in ["auth", "login", "password"]):
        capabilities.append(ToolCapability.AUTHENTICATION)
    if any(term in desc_lower for term in ["network", "http", "api", "fetch"]):
        capabilities.append(ToolCapability.NETWORK)
    if any(term in desc_lower for term in ["security", "audit", "scan"]):
        capabilities.append(ToolCapability.SECURITY)
    if any(term in desc_lower for term in ["code", "programming", "development"]):
        capabilities.append(ToolCapability.CODE)

    # Remove duplicates
    return list(set(capabilities))


def _extract_compatibility_signals(findings: list) -> list[str]:
    """Extract compatibility signals from findings."""
    signals = []
    env_vars = []
    endpoints = 0

    for finding in findings:
        snippet = finding.get("snippet", "")
        phase = finding.get("phase", "")

        if phase == "credentials":
            # Extract environment variable names
            if "process.env." in snippet:
                var_name = snippet.split("process.env.")[1].split()[0].rstrip(",);")
                env_vars.append(var_name)

        if phase == "network_exfil":
            endpoints += 1

    # Build signals
    if env_vars:
        signals.append(f"env_vars:{','.join(env_vars)}")

    if endpoints > 0:
        signals.append(f"network:{endpoints}_endpoints")

    # Add database compatibility signals based on env vars
    if any("DATABASE" in var or "POSTGRES" in var for var in env_vars):
        signals.append("database:postgres_compatible")

    return signals


def _normalize_ecosystem(ecosystem: str) -> str:
    """Normalize source ecosystem labels to API labels."""
    eco = (ecosystem or "").lower()
    if eco in {"clawhub", "skill"}:
        return "skill"
    if eco in {"github", "mcp"}:
        return "mcp"
    return eco


def _parse_jsonish(value: Any, default: Any):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    return default


def _build_scan_data_from_row(row: dict[str, Any]) -> dict[str, Any]:
    metadata = _parse_jsonish(
        row.get("metadata") or row.get("metadata_json") or row.get("metadata_jsonb"),
        {},
    )
    findings = _parse_jsonish(row.get("findings_json") or row.get("findings"), [])
    return {
        "verdict": row.get("verdict", "UNKNOWN"),
        "risk_score": row.get("risk_score", 0),
        "findings": findings,
        "metadata": metadata,
        "package_version": row.get("package_version", ""),
    }


async def _fetch_scan_rows(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch scan rows using compatibility methods used in tests."""
    if hasattr(db, "fetch_all"):
        return await db.fetch_all("SELECT * FROM public_scans LIMIT ?", [limit])
    return await db.select("public_scans", limit=limit)


async def _fetch_single_scan_row(
    ecosystem: str, package_name: str
) -> dict[str, Any] | None:
    if hasattr(db, "fetch_one"):
        return await db.fetch_one(
            "SELECT * FROM public_scans WHERE ecosystem = ? AND package_name = ?",
            [ecosystem, package_name],
        )
    return await db.select_one(
        "public_scans", {"ecosystem": ecosystem, "package_name": package_name}
    )


def _stack_name_for_use_case(use_case: str) -> str:
    text = use_case.lower()
    if any(term in text for term in ["postgres", "database", "sql", "query"]):
        return "Database Agent Stack"
    if any(term in text for term in ["api", "rest", "webhook"]):
        return "API Integration Stack"
    if any(term in text for term in ["rag", "embedding", "llm", "ai"]):
        return "AI/LLM Stack"
    return "General Agent Stack"


def _serialize_classified_tool(tool: ClassifiedTool) -> dict[str, Any]:
    return {
        "name": tool.name,
        "ecosystem": tool.ecosystem,
        "category": tool.category.value,
        "capabilities": [cap.value for cap in tool.capabilities],
        "trust_score": tool.trust_score,
        "verdict": tool.verdict,
        "compatibility_signals": tool.compatibility_signals,
        "github_url": tool.github_url,
        "install_command": tool.install_command,
    }


# ============================================================================
# Request/Response Models
# ============================================================================


class ClassificationResponse(BaseModel):
    """A tool classification with metadata."""

    id: str
    ecosystem: str
    package_name: str
    package_version: str = ""
    category: str
    subcategory: str = ""
    confidence_score: float
    description_summary: str = ""
    environment_vars: list[str] = Field(default_factory=list)
    network_protocols: list[str] = Field(default_factory=list)
    file_patterns: list[str] = Field(default_factory=list)
    import_patterns: list[str] = Field(default_factory=list)
    risk_indicators: list[str] = Field(default_factory=list)
    capabilities: list[dict[str, Any]] = Field(default_factory=list)
    trust_score: float = 0.0
    classified_at: datetime
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchRequest(BaseModel):
    """Search request for tools."""

    query: str = Field(..., description="Search query")
    ecosystem: str | None = Field(None, description="Filter by ecosystem")
    category: str | None = Field(None, description="Filter by category")
    min_trust_score: float | None = Field(None, description="Minimum trust score")
    limit: int = Field(20, description="Maximum results")


class SearchResponse(BaseModel):
    """Search results."""

    query: str
    results: list[ClassificationResponse]
    total: int
    categories: list[str] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)


class MatchResponse(BaseModel):
    """A tool match."""

    primary_tool: ClassificationResponse
    secondary_tool: ClassificationResponse
    match_type: str
    compatibility_score: float
    shared_elements: list[str]
    match_reason: str
    trust_score_combined: float


class StackRequest(BaseModel):
    """Request for a Forge Stack."""

    use_case: str = Field(..., description="Describe what you want to accomplish")
    max_tools: int = Field(5, description="Maximum tools in stack")
    min_trust_score: float = Field(70.0, description="Minimum trust score for tools")


class StackTool(BaseModel):
    """A tool in a Forge Stack."""

    classification: ClassificationResponse
    install_command: str
    trust_score: float
    reason: str = ""


class StackResponse(BaseModel):
    """A Forge Stack response."""

    name: str
    description: str
    tools: list[StackTool]
    total_trust_score: float
    use_case: str
    generated_at: datetime


class CategoryResponse(BaseModel):
    """Category information."""

    category: str
    display_name: str
    description: str
    tool_count: int
    parent_category: str | None = None
    sort_order: int


# ============================================================================
# Helper Functions
# ============================================================================


async def _get_trust_score(ecosystem: str, package_name: str) -> float:
    """Get trust score from public_scans."""
    scan = await db.select_one(
        "public_scans", {"ecosystem": ecosystem, "package_name": package_name}
    )

    if not scan:
        return 50.0  # Default neutral score

    risk_score = scan.get("risk_score", 0.0)
    return max(0.0, 100.0 - (risk_score * 5))


async def _build_classification_response(
    classification: dict[str, Any],
    capabilities: list[dict[str, Any]] = None,
    trust_scores: dict[str, float] = None,
) -> ClassificationResponse:
    """Build ClassificationResponse from database record with optional preloaded data."""
    # Use preloaded capabilities if provided, otherwise fetch individually (slower)
    if capabilities is None:
        capabilities = await db.select(
            "forge_capabilities", {"classification_id": classification["id"]}
        )

    # Use preloaded trust score if provided, otherwise fetch individually (slower)
    if trust_scores is not None:
        trust_score = trust_scores.get(
            f"{classification['ecosystem']}:{classification['package_name']}", 50.0
        )
    else:
        trust_score = await _get_trust_score(
            classification["ecosystem"], classification["package_name"]
        )

    return ClassificationResponse(
        id=classification["id"],
        ecosystem=classification["ecosystem"],
        package_name=classification["package_name"],
        package_version=classification.get("package_version", ""),
        category=classification["category"],
        subcategory=classification.get("subcategory", ""),
        confidence_score=classification.get("confidence_score", 0.0),
        description_summary=classification.get("description_summary", ""),
        environment_vars=json.loads(classification.get("environment_vars", "[]")),
        network_protocols=json.loads(classification.get("network_protocols", "[]")),
        file_patterns=json.loads(classification.get("file_patterns", "[]")),
        import_patterns=json.loads(classification.get("import_patterns", "[]")),
        risk_indicators=json.loads(classification.get("risk_indicators", "[]")),
        capabilities=[
            {
                "capability": cap["capability"],
                "confidence": cap.get("confidence", 1.0),
                "evidence": cap.get("evidence", ""),
            }
            for cap in capabilities
        ],
        trust_score=trust_score,
        classified_at=classification["classified_at"],
        metadata=json.loads(classification.get("metadata_json", "{}")),
    )


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/search")
async def search_tools(
    q: str = Query(..., description="Search query"),
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    type: str | None = Query(None, description="Compatibility filter: skill|mcp"),
    category: str | None = Query(None, description="Filter by category"),
    min_trust: float | None = Query(None, description="Minimum trust score"),
    limit: int = Query(20, description="Maximum results"),
):
    """Search tools with compatibility response expected by tests and clients."""
    try:
        rows = await _fetch_scan_rows(limit=limit * 5)
        requested_type = (type or ecosystem or "").lower()
        items: list[dict[str, Any]] = []

        for row in rows:
            normalized_ecosystem = _normalize_ecosystem(row.get("ecosystem", ""))
            if (
                requested_type in {"skill", "mcp"}
                and normalized_ecosystem != requested_type
            ):
                continue

            scan_data = _build_scan_data_from_row(row)
            package_name = row.get("package_name") or row.get("name") or "unknown"
            tool = await classify_tool(normalized_ecosystem, package_name, scan_data)

            if q:
                searchable = f"{tool.name} {scan_data.get('metadata', {}).get('description', '')}".lower()
                if q.lower() not in searchable:
                    continue

            if category and tool.category.value != category:
                continue

            if min_trust is not None and tool.trust_score < min_trust:
                continue

            items.append(_serialize_classified_tool(tool))
            if len(items) >= limit:
                break

        return {"query": q, "items": items, "total": len(items)}
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stack")
async def get_tool_stack(
    use_case: str = Query(..., description="Use case to build a stack for"),
    max_tools: int = Query(5, ge=1, le=20),
):
    """Return a lightweight stack recommendation compatible with legacy Forge tests."""
    rows = await _fetch_scan_rows(limit=max_tools * 5)
    tools: list[dict[str, Any]] = []
    risk_scores: list[float] = []

    for row in rows:
        normalized_ecosystem = _normalize_ecosystem(row.get("ecosystem", ""))
        scan_data = _build_scan_data_from_row(row)
        package_name = row.get("package_name") or row.get("name") or "unknown"
        tool = await classify_tool(normalized_ecosystem, package_name, scan_data)
        tools.append(_serialize_classified_tool(tool))
        risk_scores.append(float(scan_data.get("risk_score", 0)))
        if len(tools) >= max_tools:
            break

    avg_risk = (sum(risk_scores) / len(risk_scores)) if risk_scores else 0.0
    overall_risk = (
        "LOW_RISK" if avg_risk < 20 else "MEDIUM_RISK" if avg_risk < 50 else "HIGH_RISK"
    )

    needed_capabilities = []
    lc_use_case = use_case.lower()
    if any(term in lc_use_case for term in ["postgres", "database", "sql", "query"]):
        needed_capabilities.append("database")
    if any(term in lc_use_case for term in ["api", "rest", "webhook"]):
        needed_capabilities.append("network")
    if any(term in lc_use_case for term in ["rag", "embedding", "llm", "ai"]):
        needed_capabilities.append("ai")

    return {
        "name": _stack_name_for_use_case(use_case),
        "use_case": use_case,
        "tools": tools,
        "trust_summary": {
            "overall_risk": overall_risk,
            "average_trust_score": int(
                sum(t["trust_score"] for t in tools) / len(tools)
            )
            if tools
            else 0,
            "needed_capabilities": needed_capabilities,
        },
    }


@router.get("/tools/{ecosystem}/{name}")
async def get_tool_details(ecosystem: str, name: str):
    normalized_ecosystem = _normalize_ecosystem(ecosystem)
    row = await _fetch_single_scan_row(ecosystem, name)
    if row is None and normalized_ecosystem != ecosystem:
        row = await _fetch_single_scan_row(normalized_ecosystem, name)
    if row is None:
        raise HTTPException(status_code=404, detail="Tool not found")

    tool = await classify_tool(
        normalized_ecosystem,
        row.get("package_name") or name,
        _build_scan_data_from_row(row),
    )
    return _serialize_classified_tool(tool)


@router.get("/classifications/skills")
async def get_classified_skills(
    limit: int = Query(20, ge=1, le=200), min_trust_score: int = 0
):
    rows = await _fetch_scan_rows(limit=limit * 5)
    items: list[dict[str, Any]] = []
    for row in rows:
        if _normalize_ecosystem(row.get("ecosystem", "")) != "skill":
            continue
        tool = await classify_tool(
            "skill", row.get("package_name", "unknown"), _build_scan_data_from_row(row)
        )
        if tool.trust_score < min_trust_score:
            continue
        items.append(_serialize_classified_tool(tool))
    items.sort(key=lambda item: item["trust_score"], reverse=True)
    return items[:limit]


@router.get("/classifications/mcps")
async def get_classified_mcps(
    limit: int = Query(20, ge=1, le=200), min_trust_score: int = 0
):
    rows = await _fetch_scan_rows(limit=limit * 5)
    items: list[dict[str, Any]] = []
    for row in rows:
        if _normalize_ecosystem(row.get("ecosystem", "")) != "mcp":
            continue
        tool = await classify_tool(
            "mcp", row.get("package_name", "unknown"), _build_scan_data_from_row(row)
        )
        if tool.trust_score < min_trust_score:
            continue
        items.append(_serialize_classified_tool(tool))
    items.sort(key=lambda item: item["trust_score"], reverse=True)
    return items[:limit]


@router.post("/classify")
async def classify_package(payload: dict[str, Any]):
    ecosystem = payload.get("ecosystem", "")
    package_name = payload.get("package_name", "")
    normalized_ecosystem = _normalize_ecosystem(ecosystem)

    row = await _fetch_single_scan_row(ecosystem, package_name)
    if row is None and normalized_ecosystem != ecosystem:
        row = await _fetch_single_scan_row(normalized_ecosystem, package_name)
    if row is None:
        raise HTTPException(status_code=404, detail="No scan data available")

    tool = await classify_tool(
        normalized_ecosystem,
        row.get("package_name") or package_name,
        _build_scan_data_from_row(row),
    )
    return _serialize_classified_tool(tool)


@router.get("/browse/{category}", response_model=list[ClassificationResponse])
async def browse_category(
    category: str,
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    limit: int = Query(50, description="Maximum results"),
):
    """Browse tools by category."""

    try:
        filters = {"category": category}
        if ecosystem:
            filters["ecosystem"] = ecosystem

        classifications = await db.select(
            "forge_classification",
            filters,
            order_by="confidence_score",
            order_desc=True,
            limit=limit,
        )

        # Batch load capabilities for all classifications to avoid N+1
        classification_ids = [c["id"] for c in classifications]
        all_capabilities = {}
        if classification_ids:
            # Load all capabilities in one query
            if db.connected:
                # Use IN clause for better performance
                placeholders = ",".join(["?" for _ in classification_ids])
                capability_sql = f"SELECT * FROM forge_capabilities WHERE classification_id IN ({placeholders})"
                async with db._pool.acquire() as conn:
                    cursor = await conn.cursor()
                    await cursor.execute(capability_sql, tuple(classification_ids))
                    capability_rows = await cursor.fetchall()
                    capability_rows = [
                        db._row_to_dict(cursor, r) for r in capability_rows
                    ]
            else:
                # Fallback for in-memory mode
                capability_rows = []
                for cid in classification_ids:
                    caps = await db.select(
                        "forge_capabilities", {"classification_id": cid}
                    )
                    capability_rows.extend(caps)

            # Group capabilities by classification_id
            for cap in capability_rows:
                cid = cap["classification_id"]
                if cid not in all_capabilities:
                    all_capabilities[cid] = []
                all_capabilities[cid].append(cap)

        # Batch load trust scores
        trust_scores = {}
        unique_packages = list(
            set(f"{c['ecosystem']}:{c['package_name']}" for c in classifications)
        )
        for pkg_key in unique_packages:
            ecosystem, package_name = pkg_key.split(":", 1)
            trust_scores[pkg_key] = await _get_trust_score(ecosystem, package_name)

        results = []
        for classification in classifications:
            capabilities = all_capabilities.get(classification["id"], [])
            result = await _build_classification_response(
                classification, capabilities=capabilities, trust_scores=trust_scores
            )
            results.append(result)

        return results

    except Exception as e:
        logger.error(f"Browse category failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/categories", response_model=list[CategoryResponse])
async def list_categories():
    """Get all available categories with tool counts."""

    try:
        # Get category definitions
        categories = await db.select(
            "forge_categories", {"is_active": True}, order_by="sort_order"
        )

        # Get tool counts per category
        classification_counts = {}
        all_classifications = await db.select("forge_classification", {})
        for classification in all_classifications:
            category = classification["category"]
            classification_counts[category] = classification_counts.get(category, 0) + 1

        results = []
        for category in categories:
            results.append(
                CategoryResponse(
                    category=category["category"],
                    display_name=category["display_name"],
                    description=category["description"],
                    tool_count=classification_counts.get(category["category"], 0),
                    parent_category=category.get("parent_category"),
                    sort_order=category["sort_order"],
                )
            )

        return results

    except Exception as e:
        logger.error(f"List categories failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tool/{ecosystem}/{package_name}", response_model=ClassificationResponse)
async def get_tool(ecosystem: str, package_name: str, version: str = ""):
    """Get detailed information about a specific tool."""

    try:
        filters = {"ecosystem": ecosystem, "package_name": package_name}
        if version:
            filters["package_version"] = version

        classification = await db.select_one("forge_classification", filters)
        if not classification:
            raise HTTPException(status_code=404, detail="Tool not found")

        return await _build_classification_response(classification)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get tool failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get(
    "/tool/{ecosystem}/{package_name}/matches", response_model=list[MatchResponse]
)
async def get_tool_matches(
    ecosystem: str,
    package_name: str,
    version: str = "",
    limit: int = Query(10, description="Maximum matches"),
):
    """Get compatible tools for a specific tool."""

    try:
        # Get tool classification
        filters = {"ecosystem": ecosystem, "package_name": package_name}
        if version:
            filters["package_version"] = version

        classification = await db.select_one("forge_classification", filters)
        if not classification:
            raise HTTPException(status_code=404, detail="Tool not found")

        classification_id = classification["id"]

        # Get matches with JOIN for better performance
        if db.connected:
            match_sql = """
            SELECT 
                m.*,
                p.ecosystem as primary_ecosystem, p.package_name as primary_package_name,
                p.category as primary_category, p.confidence_score as primary_confidence,
                p.description_summary as primary_description, p.classified_at as primary_classified_at,
                s.ecosystem as secondary_ecosystem, s.package_name as secondary_package_name,
                s.category as secondary_category, s.confidence_score as secondary_confidence,
                s.description_summary as secondary_description, s.classified_at as secondary_classified_at
            FROM forge_matches m
            JOIN forge_classification p ON m.primary_classification_id = p.id
            JOIN forge_classification s ON m.secondary_classification_id = s.id
            WHERE m.primary_classification_id = ?
            ORDER BY m.compatibility_score DESC
            """

            async with db._pool.acquire() as conn:
                cursor = await conn.cursor()
                await cursor.execute(
                    match_sql + f" OFFSET 0 ROWS FETCH NEXT {limit} ROWS ONLY",
                    (classification_id,),
                )
                match_rows = await cursor.fetchall()
                matches_with_tools = [db._row_to_dict(cursor, r) for r in match_rows]
        else:
            # Fallback for in-memory mode
            matches = await db.select(
                "forge_matches",
                {"primary_classification_id": classification_id},
                order_by="compatibility_score",
                order_desc=True,
                limit=limit,
            )
            matches_with_tools = []
            for match in matches:
                primary = await db.select_one(
                    "forge_classification", {"id": match["primary_classification_id"]}
                )
                secondary = await db.select_one(
                    "forge_classification", {"id": match["secondary_classification_id"]}
                )
                if primary and secondary:
                    combined = {**match}
                    for k, v in primary.items():
                        combined[f"primary_{k}"] = v
                    for k, v in secondary.items():
                        combined[f"secondary_{k}"] = v
                    matches_with_tools.append(combined)

        # Batch load capabilities and trust scores for all tools
        all_classification_ids = set()
        trust_score_keys = set()
        for match_data in matches_with_tools:
            if db.connected:
                # From JOIN query
                primary_id = match_data["primary_classification_id"]
                secondary_id = match_data["secondary_classification_id"]
                trust_score_keys.add(
                    f"{match_data['primary_ecosystem']}:{match_data['primary_package_name']}"
                )
                trust_score_keys.add(
                    f"{match_data['secondary_ecosystem']}:{match_data['secondary_package_name']}"
                )
            else:
                # From fallback mode
                primary_id = match_data["primary_id"]
                secondary_id = match_data["secondary_id"]
                trust_score_keys.add(
                    f"{match_data['primary_ecosystem']}:{match_data['primary_package_name']}"
                )
                trust_score_keys.add(
                    f"{match_data['secondary_ecosystem']}:{match_data['secondary_package_name']}"
                )
            all_classification_ids.add(primary_id)
            all_classification_ids.add(secondary_id)

        # Batch load capabilities
        all_capabilities = {}
        if all_classification_ids and db.connected:
            placeholders = ",".join(["?" for _ in all_classification_ids])
            capability_sql = f"SELECT * FROM forge_capabilities WHERE classification_id IN ({placeholders})"
            async with db._pool.acquire() as conn:
                cursor = await conn.cursor()
                await cursor.execute(capability_sql, tuple(all_classification_ids))
                capability_rows = await cursor.fetchall()
                capability_rows = [db._row_to_dict(cursor, r) for r in capability_rows]

                for cap in capability_rows:
                    cid = cap["classification_id"]
                    if cid not in all_capabilities:
                        all_capabilities[cid] = []
                    all_capabilities[cid].append(cap)

        # Batch load trust scores
        trust_scores = {}
        for pkg_key in trust_score_keys:
            ecosystem, package_name = pkg_key.split(":", 1)
            trust_scores[pkg_key] = await _get_trust_score(ecosystem, package_name)

        results = []
        for match_data in matches_with_tools:
            if db.connected:
                # Build from JOIN query data
                primary = {
                    "id": match_data["primary_classification_id"],
                    "ecosystem": match_data["primary_ecosystem"],
                    "package_name": match_data["primary_package_name"],
                    "category": match_data["primary_category"],
                    "confidence_score": match_data["primary_confidence"],
                    "description_summary": match_data["primary_description"],
                    "classified_at": match_data["primary_classified_at"],
                    # Set defaults for missing fields
                    "package_version": "",
                    "subcategory": "",
                    "environment_vars": "[]",
                    "network_protocols": "[]",
                    "file_patterns": "[]",
                    "import_patterns": "[]",
                    "risk_indicators": "[]",
                    "metadata_json": "{}",
                }

                secondary = {
                    "id": match_data["secondary_classification_id"],
                    "ecosystem": match_data["secondary_ecosystem"],
                    "package_name": match_data["secondary_package_name"],
                    "category": match_data["secondary_category"],
                    "confidence_score": match_data["secondary_confidence"],
                    "description_summary": match_data["secondary_description"],
                    "classified_at": match_data["secondary_classified_at"],
                    # Set defaults for missing fields
                    "package_version": "",
                    "subcategory": "",
                    "environment_vars": "[]",
                    "network_protocols": "[]",
                    "file_patterns": "[]",
                    "import_patterns": "[]",
                    "risk_indicators": "[]",
                    "metadata_json": "{}",
                }
            else:
                # Use fallback mode data
                primary = {
                    k.replace("primary_", ""): v
                    for k, v in match_data.items()
                    if k.startswith("primary_")
                }
                secondary = {
                    k.replace("secondary_", ""): v
                    for k, v in match_data.items()
                    if k.startswith("secondary_")
                }

            primary_capabilities = all_capabilities.get(primary["id"], [])
            secondary_capabilities = all_capabilities.get(secondary["id"], [])

            primary_response = await _build_classification_response(
                primary, capabilities=primary_capabilities, trust_scores=trust_scores
            )
            secondary_response = await _build_classification_response(
                secondary,
                capabilities=secondary_capabilities,
                trust_scores=trust_scores,
            )

            results.append(
                MatchResponse(
                    primary_tool=primary_response,
                    secondary_tool=secondary_response,
                    match_type=match_data["match_type"],
                    compatibility_score=match_data["compatibility_score"],
                    shared_elements=json.loads(match_data.get("shared_elements", "[]")),
                    match_reason=match_data.get("match_reason", ""),
                    trust_score_combined=match_data.get("trust_score_combined", 0.0),
                )
            )

        return results

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get matches failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/stack", response_model=StackResponse)
async def generate_stack(request: StackRequest):
    """Generate a Forge Stack for a specific use case."""

    try:
        # Generate stack using matcher
        stack_data = await forge_matcher.generate_forge_stack(request.use_case)

        # Build response
        tools = []
        for tool_data in stack_data["tools"][: request.max_tools]:
            if tool_data["trust_score"] >= request.min_trust_score:
                classification = await _build_classification_response(tool_data)
                tools.append(
                    StackTool(
                        classification=classification,
                        install_command=tool_data["install_command"],
                        trust_score=tool_data["trust_score"],
                        reason=f"Selected for {classification.category} capability",
                    )
                )

        return StackResponse(
            name=stack_data["stack"]["name"],
            description=stack_data["stack"]["description"],
            tools=tools,
            total_trust_score=stack_data["total_trust_score"],
            use_case=request.use_case,
            generated_at=datetime.fromisoformat(
                stack_data["generated_at"].replace("Z", "+00:00")
            ),
        )

    except Exception as e:
        logger.error(f"Generate stack failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats")
async def get_forge_stats():
    """Get Forge statistics."""

    try:
        # Count tools by ecosystem
        all_classifications = await db.select("forge_classification", {})

        ecosystem_counts = {}
        category_counts = {}
        total_tools = len(all_classifications)

        for classification in all_classifications:
            ecosystem = classification["ecosystem"]
            category = classification["category"]

            ecosystem_counts[ecosystem] = ecosystem_counts.get(ecosystem, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1

        # Count total matches
        matches = await db.select("forge_matches", {})
        total_matches = len(matches)

        return {
            "total_tools": total_tools,
            "total_matches": total_matches,
            "ecosystems": ecosystem_counts,
            "categories": category_counts,
            "last_updated": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Get stats failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# MCP-compatible endpoints for agent consumption
@router.get("/mcp/search")
async def mcp_search(query: str, type: str = "both", limit: int = 10):
    """MCP-compatible search endpoint for agents."""

    ecosystem_filter = None
    if type == "skill":
        ecosystem_filter = "clawhub"
    elif type == "mcp":
        ecosystem_filter = "mcp"

    results = await search_tools(q=query, ecosystem=ecosystem_filter, limit=limit)

    # Simplified format for agents
    return {
        "tools": [
            {
                "name": r.package_name,
                "ecosystem": r.ecosystem,
                "category": r.category,
                "description": r.description_summary,
                "trust_score": r.trust_score,
                "capabilities": [c["capability"] for c in r.capabilities],
            }
            for r in results.results
        ],
        "total": results.total,
    }


@router.get("/mcp/stack")
async def mcp_stack(use_case: str):
    """MCP-compatible stack generation for agents."""

    request = StackRequest(use_case=use_case)
    stack = await generate_stack(request)

    # Simplified format for agents
    return {
        "name": stack.name,
        "description": stack.description,
        "tools": [
            {
                "name": tool.classification.package_name,
                "ecosystem": tool.classification.ecosystem,
                "install": tool.install_command,
                "trust_score": tool.trust_score,
            }
            for tool in stack.tools
        ],
    }


@router.get("/mcp/check")
async def mcp_check(name: str, ecosystem: str):
    """MCP-compatible tool check for agents."""

    tool = await get_tool(ecosystem, name)

    # Simplified format for agents
    return {
        "name": tool.package_name,
        "ecosystem": tool.ecosystem,
        "category": tool.category,
        "trust_score": tool.trust_score,
        "capabilities": [c["capability"] for c in tool.capabilities],
        "environment_vars": tool.environment_vars,
        "protocols": tool.network_protocols,
        "verdict": "LOW_RISK"
        if tool.trust_score >= 80
        else "MEDIUM_RISK"
        if tool.trust_score >= 60
        else "HIGH_RISK",
    }


# Additional endpoints required by deployment validation
@router.get("/stacks")
async def get_stacks_alias(
    use_case: str = Query(..., description="Use case to build a stack for"),
    max_tools: int = Query(5, ge=1, le=20),
):
    """Alias for /stack endpoint (required by deployment validation)."""
    return await get_tool_stack(use_case=use_case, max_tools=max_tools)


@router.get("/jobs")
async def get_forge_jobs(
    limit: int = Query(10, ge=1, le=100, description="Maximum number of jobs to return"),
    offset: int = Query(0, ge=0, description="Number of jobs to skip"),
    status: str = Query(None, description="Filter by job status"),
):
    """Get forge bot scan jobs and processing status."""
    try:
        # This endpoint provides visibility into the forge bot scanning queue
        # Since we don't have a dedicated jobs table, return recent scan activities
        # from public_scans as a proxy for job status
        
        filters = {}
        if status and status.upper() in ['SUCCESS', 'ERROR', 'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK']:
            filters['verdict'] = status.upper()
        
        if db.connected:
            # Query recent scans as job proxy
            sql = """
            SELECT id, ecosystem, package_name as name, package_version as version,
                   verdict, risk_score, scanned_at, metadata_json
            FROM public_scans 
            WHERE 1=1
            """
            params = []
            
            if status:
                sql += " AND verdict = ?"
                params.append(status.upper())
                
            sql += " ORDER BY scanned_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            
            rows = await db.fetch_all(sql, params)
            jobs = []
            
            for row in rows:
                metadata = row.get('metadata_json', {})
                if isinstance(metadata, str):
                    try:
                        import json
                        metadata = json.loads(metadata)
                    except json.JSONDecodeError:
                        metadata = {}
                
                jobs.append({
                    "id": row.get('id'),
                    "ecosystem": row.get('ecosystem'),
                    "name": row.get('name'),  
                    "version": row.get('version'),
                    "status": "completed",
                    "verdict": row.get('verdict', 'UNKNOWN'),
                    "risk_score": row.get('risk_score', 0),
                    "completed_at": row.get('scanned_at'),
                    "metadata": {
                        "source": metadata.get("source", "forge-bot"),
                        "duration_ms": metadata.get("duration_ms"),
                        "files_scanned": metadata.get("files_scanned"),
                    }
                })
        else:
            jobs = []
            
        return {
            "jobs": jobs,
            "total": len(jobs),
            "limit": limit,
            "offset": offset,
            "status_filter": status,
        }
    except Exception as e:
        logger.error(f"Jobs query failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve forge jobs")


@router.get("/stats/detailed")
async def get_forge_stats_detailed():
    """Get detailed forge statistics and status."""
    try:
        if db.connected:
            # Get scan statistics from public_scans table
            stats_sql = """
            SELECT 
                COUNT(*) as total_scans,
                COUNT(CASE WHEN verdict = 'CRITICAL_RISK' THEN 1 END) as critical_scans,
                COUNT(CASE WHEN verdict = 'HIGH_RISK' THEN 1 END) as high_risk_scans,
                COUNT(CASE WHEN verdict = 'MEDIUM_RISK' THEN 1 END) as medium_risk_scans,
                COUNT(CASE WHEN verdict = 'LOW_RISK' THEN 1 END) as low_risk_scans,
                COUNT(DISTINCT ecosystem) as ecosystems_covered,
                MAX(scanned_at) as last_scan_at
            FROM public_scans
            WHERE scanned_at >= DATEADD(day, -7, GETDATE())
            """
            
            stats_row = await db.fetch_one(stats_sql)
            
            return {
                "status": "operational",
                "total_scans_7d": stats_row.get("total_scans", 0),
                "critical_scans_7d": stats_row.get("critical_scans", 0), 
                "high_risk_scans_7d": stats_row.get("high_risk_scans", 0),
                "medium_risk_scans_7d": stats_row.get("medium_risk_scans", 0),
                "low_risk_scans_7d": stats_row.get("low_risk_scans", 0),
                "ecosystems_covered": stats_row.get("ecosystems_covered", 0),
                "last_scan_at": stats_row.get("last_scan_at"),
                "database_connected": True
            }
        else:
            return {
                "status": "database_disconnected",
                "total_scans_7d": 0,
                "database_connected": False
            }
    except Exception as e:
        logger.error(f"Stats query failed: {e}")
        return {
            "status": "error",
            "error": str(e),
            "database_connected": db.connected if hasattr(db, 'connected') else False
        }


@router.get("/feed.json")
async def get_forge_feed():
    """RSS/JSON feed of latest tools (required by deployment validation)."""
    try:
        # Get recent classifications
        recent_tools = []
        rows = await _fetch_scan_rows(limit=50)

        for row in rows:
            normalized_ecosystem = _normalize_ecosystem(row.get("ecosystem", ""))
            scan_data = _build_scan_data_from_row(row)
            package_name = row.get("package_name") or row.get("name") or "unknown"
            tool = await classify_tool(normalized_ecosystem, package_name, scan_data)

            recent_tools.append(
                {
                    "title": f"{tool.name} ({tool.ecosystem})",
                    "description": scan_data.get("metadata", {}).get("description", ""),
                    "category": tool.category.value,
                    "trust_score": tool.trust_score,
                    "verdict": tool.verdict,
                    "url": f"/forge/tools/{tool.ecosystem}/{tool.name}",
                    "published": datetime.utcnow().isoformat(),
                }
            )

            if len(recent_tools) >= 20:
                break
        return {
            "version": "https://jsonfeed.org/version/1.1",
            "title": "Sigil Forge - Latest Tools",
            "home_page_url": "/forge",
            "feed_url": "/forge/feed.json",
            "description": "Latest classified AI agent tools and packages",
            "items": recent_tools,
        }
    except Exception as e:
        logger.error(f"Feed generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
