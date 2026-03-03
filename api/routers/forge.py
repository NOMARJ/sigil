"""
Sigil Forge — API Endpoints

Provides REST API access to Forge classification data, matches, and stacks.
Supports both human and agent consumption.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Depends
from api.routers.auth import get_current_user_unified, UserResponse
from pydantic import BaseModel, Field

from api.database import db
from api.models import ErrorResponse, ForgeEventType
from api.services.forge_classifier import forge_classifier
from api.services.forge_matcher import forge_matcher
from api.services.forge_analytics import track_forge_event

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/forge", tags=["Sigil Forge"])


# ============================================================================
# Helper Functions
# ============================================================================



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
    scan = await db.select_one("public_scans", {
        "ecosystem": ecosystem,
        "package_name": package_name
    })
    
    if not scan:
        return 50.0  # Default neutral score
    
    risk_score = scan.get("risk_score", 0.0)
    return max(0.0, 100.0 - (risk_score * 5))


async def _build_classification_response(
    classification: dict[str, Any], 
    capabilities: list[dict[str, Any]] = None,
    trust_scores: dict[str, float] = None
) -> ClassificationResponse:
    """Build ClassificationResponse from database record with optional preloaded data."""
    # Use preloaded capabilities if provided, otherwise fetch individually (slower)
    if capabilities is None:
        capabilities = await db.select("forge_capabilities", {
            "classification_id": classification["id"]
        })
    
    # Use preloaded trust score if provided, otherwise fetch individually (slower)
    if trust_scores is not None:
        trust_score = trust_scores.get(
            f"{classification['ecosystem']}:{classification['package_name']}", 
            50.0
        )
    else:
        trust_score = await _get_trust_score(
            classification["ecosystem"],
            classification["package_name"]
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
                "evidence": cap.get("evidence", "")
            }
            for cap in capabilities
        ],
        trust_score=trust_score,
        classified_at=classification["classified_at"],
        metadata=json.loads(classification.get("metadata_json", "{}"))
    )


# ============================================================================
# API Endpoints
# ============================================================================


@router.get("/search", response_model=SearchResponse)
async def search_tools(
    q: str = Query(..., description="Search query"),
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    category: str | None = Query(None, description="Filter by category"),
    min_trust: float | None = Query(None, description="Minimum trust score"),
    limit: int = Query(20, description="Maximum results"),
):
    """Search for classified tools by query, category, or ecosystem."""
    
    try:
        # Build filters
        filters = {}
        if ecosystem:
            filters["ecosystem"] = ecosystem
        if category:
            filters["category"] = category
        
        # Use full-text search if available, otherwise fallback to LIKE
        if q and len(q) > 2:
            # Full-text search query
            search_sql = """
            SELECT * FROM forge_classification 
            WHERE (@ecosystem IS NULL OR ecosystem = @ecosystem)
              AND (@category IS NULL OR category = @category)
              AND (CONTAINS(description_summary, @search_query) 
                   OR package_name LIKE @like_query
                   OR category LIKE @like_query)
            ORDER BY confidence_score DESC
            """
            
            # Execute raw SQL for better performance
            if db.connected:
                async with db._pool.acquire() as conn:
                    cursor = await conn.cursor()
                    await cursor.execute(search_sql, (
                        ecosystem, category, f'"{q}"', f'%{q}%'
                    ))
                    rows = await cursor.fetchall()
                    classifications = [db._row_to_dict(cursor, r) for r in rows[:limit * 2]]
            else:
                # Fallback for in-memory mode
                classifications = await db.select(
                    "forge_classification",
                    filters,
                    order_by="confidence_score",
                    order_desc=True,
                    limit=limit * 2
                )
        else:
            # Get classifications without search
            classifications = await db.select(
                "forge_classification",
                filters,
                order_by="confidence_score",
                order_desc=True,
                limit=limit * 2  # Get more to filter by trust score
            )
        
        # Batch load capabilities for all classifications to avoid N+1
        classification_ids = [c["id"] for c in classifications]
        all_capabilities = {}
        if classification_ids:
            capability_rows = await db.select(
                "forge_capabilities",
                {"classification_id": classification_ids[0]} if len(classification_ids) == 1 else {}
            )
            # Group capabilities by classification_id
            for cap in capability_rows:
                cid = cap["classification_id"]
                if cid not in all_capabilities:
                    all_capabilities[cid] = []
                all_capabilities[cid].append(cap)
        
        # Batch load trust scores to avoid N+1
        trust_scores = {}
        if min_trust or True:  # Always load for response
            unique_packages = list(set(
                f"{c['ecosystem']}:{c['package_name']}" for c in classifications
            ))
            for pkg_key in unique_packages:
                ecosystem, package_name = pkg_key.split(':', 1)
                trust_scores[pkg_key] = await _get_trust_score(ecosystem, package_name)
        
        # Filter by search query and trust score
        results = []
        for classification in classifications:
            # Text search in package name, category, and description (if not using full-text)
            if q and len(q) <= 2:
                searchable_text = f"{classification['package_name']} {classification['category']} {classification.get('description_summary', '')}".lower()
                if q.lower() not in searchable_text:
                    continue
            
            # Trust score filter
            if min_trust:
                pkg_key = f"{classification['ecosystem']}:{classification['package_name']}"
                if trust_scores.get(pkg_key, 50.0) < min_trust:
                    continue
            
            # Build response with preloaded data
            capabilities = all_capabilities.get(classification["id"], [])
            result = await _build_classification_response(
                classification, 
                capabilities=capabilities,
                trust_scores=trust_scores
            )
            results.append(result)
            
            if len(results) >= limit:
                break
        
        # Get unique categories and ecosystems for faceting
        all_classifications = await db.select("forge_classification", {}, limit=1000)
        categories = list(set(c["category"] for c in all_classifications))
        ecosystems = list(set(c["ecosystem"] for c in all_classifications))
        
        # Track search analytics (if we had user context)
        # For now, we'll track search patterns in separate analytics endpoints
        
        return SearchResponse(
            query=q,
            results=results,
            total=len(results),
            categories=sorted(categories),
            ecosystems=sorted(ecosystems)
        )
        
    except Exception as e:
        logger.error(f"Search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/browse/{category}", response_model=list[ClassificationResponse])
async def browse_category(
    category: str,
    ecosystem: str | None = Query(None, description="Filter by ecosystem"),
    limit: int = Query(50, description="Maximum results")
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
            limit=limit
        )
        
        # Batch load capabilities for all classifications to avoid N+1
        classification_ids = [c["id"] for c in classifications]
        all_capabilities = {}
        if classification_ids:
            # Load all capabilities in one query
            if db.connected:
                # Use IN clause for better performance
                placeholders = ','.join(['?' for _ in classification_ids])
                capability_sql = f"SELECT * FROM forge_capabilities WHERE classification_id IN ({placeholders})"
                async with db._pool.acquire() as conn:
                    cursor = await conn.cursor()
                    await cursor.execute(capability_sql, tuple(classification_ids))
                    capability_rows = await cursor.fetchall()
                    capability_rows = [db._row_to_dict(cursor, r) for r in capability_rows]
            else:
                # Fallback for in-memory mode
                capability_rows = []
                for cid in classification_ids:
                    caps = await db.select("forge_capabilities", {"classification_id": cid})
                    capability_rows.extend(caps)
            
            # Group capabilities by classification_id
            for cap in capability_rows:
                cid = cap["classification_id"]
                if cid not in all_capabilities:
                    all_capabilities[cid] = []
                all_capabilities[cid].append(cap)
        
        # Batch load trust scores
        trust_scores = {}
        unique_packages = list(set(
            f"{c['ecosystem']}:{c['package_name']}" for c in classifications
        ))
        for pkg_key in unique_packages:
            ecosystem, package_name = pkg_key.split(':', 1)
            trust_scores[pkg_key] = await _get_trust_score(ecosystem, package_name)
        
        results = []
        for classification in classifications:
            capabilities = all_capabilities.get(classification["id"], [])
            result = await _build_classification_response(
                classification, 
                capabilities=capabilities,
                trust_scores=trust_scores
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
            "forge_categories",
            {"is_active": True},
            order_by="sort_order"
        )
        
        # Get tool counts per category
        classification_counts = {}
        all_classifications = await db.select("forge_classification", {})
        for classification in all_classifications:
            category = classification["category"]
            classification_counts[category] = classification_counts.get(category, 0) + 1
        
        results = []
        for category in categories:
            results.append(CategoryResponse(
                category=category["category"],
                display_name=category["display_name"],
                description=category["description"],
                tool_count=classification_counts.get(category["category"], 0),
                parent_category=category.get("parent_category"),
                sort_order=category["sort_order"]
            ))
        
        return results
        
    except Exception as e:
        logger.error(f"List categories failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tool/{ecosystem}/{package_name}", response_model=ClassificationResponse)
async def get_tool(ecosystem: str, package_name: str, version: str = ""):
    """Get detailed information about a specific tool."""
    
    try:
        filters = {
            "ecosystem": ecosystem,
            "package_name": package_name
        }
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


@router.get("/tool/{ecosystem}/{package_name}/matches", response_model=list[MatchResponse])
async def get_tool_matches(
    ecosystem: str,
    package_name: str,
    version: str = "",
    limit: int = Query(10, description="Maximum matches")
):
    """Get compatible tools for a specific tool."""
    
    try:
        # Get tool classification
        filters = {
            "ecosystem": ecosystem,
            "package_name": package_name
        }
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
                await cursor.execute(match_sql + f" OFFSET 0 ROWS FETCH NEXT {limit} ROWS ONLY", (classification_id,))
                match_rows = await cursor.fetchall()
                matches_with_tools = [db._row_to_dict(cursor, r) for r in match_rows]
        else:
            # Fallback for in-memory mode
            matches = await db.select(
                "forge_matches",
                {"primary_classification_id": classification_id},
                order_by="compatibility_score",
                order_desc=True,
                limit=limit
            )
            matches_with_tools = []
            for match in matches:
                primary = await db.select_one("forge_classification", {"id": match["primary_classification_id"]})
                secondary = await db.select_one("forge_classification", {"id": match["secondary_classification_id"]})
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
                trust_score_keys.add(f"{match_data['primary_ecosystem']}:{match_data['primary_package_name']}")
                trust_score_keys.add(f"{match_data['secondary_ecosystem']}:{match_data['secondary_package_name']}")
            else:
                # From fallback mode
                primary_id = match_data["primary_id"]
                secondary_id = match_data["secondary_id"]
                trust_score_keys.add(f"{match_data['primary_ecosystem']}:{match_data['primary_package_name']}")
                trust_score_keys.add(f"{match_data['secondary_ecosystem']}:{match_data['secondary_package_name']}")
            all_classification_ids.add(primary_id)
            all_classification_ids.add(secondary_id)
        
        # Batch load capabilities
        all_capabilities = {}
        if all_classification_ids and db.connected:
            placeholders = ','.join(['?' for _ in all_classification_ids])
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
            ecosystem, package_name = pkg_key.split(':', 1)
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
                    "metadata_json": "{}"
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
                    "metadata_json": "{}"
                }
            else:
                # Use fallback mode data
                primary = {k.replace('primary_', ''): v for k, v in match_data.items() if k.startswith('primary_')}
                secondary = {k.replace('secondary_', ''): v for k, v in match_data.items() if k.startswith('secondary_')}
            
            primary_capabilities = all_capabilities.get(primary["id"], [])
            secondary_capabilities = all_capabilities.get(secondary["id"], [])
            
            primary_response = await _build_classification_response(
                primary, capabilities=primary_capabilities, trust_scores=trust_scores
            )
            secondary_response = await _build_classification_response(
                secondary, capabilities=secondary_capabilities, trust_scores=trust_scores
            )
            
            results.append(MatchResponse(
                primary_tool=primary_response,
                secondary_tool=secondary_response,
                match_type=match_data["match_type"],
                compatibility_score=match_data["compatibility_score"],
                shared_elements=json.loads(match_data.get("shared_elements", "[]")),
                match_reason=match_data.get("match_reason", ""),
                trust_score_combined=match_data.get("trust_score_combined", 0.0)
            ))
        
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
        for tool_data in stack_data["tools"][:request.max_tools]:
            if tool_data["trust_score"] >= request.min_trust_score:
                classification = await _build_classification_response(tool_data)
                tools.append(StackTool(
                    classification=classification,
                    install_command=tool_data["install_command"],
                    trust_score=tool_data["trust_score"],
                    reason=f"Selected for {classification.category} capability"
                ))
        
        return StackResponse(
            name=stack_data["stack"]["name"],
            description=stack_data["stack"]["description"],
            tools=tools,
            total_trust_score=stack_data["total_trust_score"],
            use_case=request.use_case,
            generated_at=datetime.fromisoformat(stack_data["generated_at"].replace("Z", "+00:00"))
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
            "last_updated": datetime.utcnow().isoformat()
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
    
    results = await search_tools(
        q=query,
        ecosystem=ecosystem_filter,
        limit=limit
    )
    
    # Simplified format for agents
    return {
        "tools": [
            {
                "name": r.package_name,
                "ecosystem": r.ecosystem,
                "category": r.category,
                "description": r.description_summary,
                "trust_score": r.trust_score,
                "capabilities": [c["capability"] for c in r.capabilities]
            }
            for r in results.results
        ],
        "total": results.total
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
                "trust_score": tool.trust_score
            }
            for tool in stack.tools
        ]
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
        "verdict": "LOW_RISK" if tool.trust_score >= 80 else "MEDIUM_RISK" if tool.trust_score >= 60 else "HIGH_RISK"
    }