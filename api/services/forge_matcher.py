"""
Sigil Forge — Tool Matching Engine

Implements compatibility matching between skills and MCPs based on:
- Shared environment variables
- Compatible protocols
- Complementary capabilities
- Category relationships

Generates Forge Stacks (curated tool combinations) with trust scores.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from api.database import db

logger = logging.getLogger(__name__)


@dataclass
class ToolMatch:
    """A match between two tools."""
    
    primary_id: str
    secondary_id: str
    match_type: str  # 'env_vars', 'protocols', 'complementary', 'category'
    compatibility_score: float
    shared_elements: list[str]
    match_reason: str
    trust_score_combined: float


class ForgeMatcher:
    """Generates compatible tool pairings for Forge Stacks."""
    
    def __init__(self):
        self.match_threshold = 0.3  # Minimum compatibility score for matches
        
    async def find_env_var_matches(self, classification_id: str) -> list[ToolMatch]:
        """Find tools that share environment variables."""
        # Get the tool's environment variables
        tool = await db.select_one("forge_classification", {"id": classification_id})
        if not tool:
            return []
        
        tool_env_vars = set(json.loads(tool.get("environment_vars", "[]")))
        if not tool_env_vars:
            return []
        
        # Find other tools with overlapping env vars
        candidates = await db.select("forge_classification", {}, limit=1000)
        matches = []
        
        for candidate in candidates:
            if candidate["id"] == classification_id:
                continue
            
            candidate_env_vars = set(json.loads(candidate.get("environment_vars", "[]")))
            shared_env_vars = tool_env_vars.intersection(candidate_env_vars)
            
            if shared_env_vars:
                # Get trust scores from public_scans
                primary_trust = await self._get_trust_score(tool["ecosystem"], tool["package_name"])
                secondary_trust = await self._get_trust_score(candidate["ecosystem"], candidate["package_name"])
                combined_trust = (primary_trust + secondary_trust) / 2
                
                compatibility_score = len(shared_env_vars) / max(len(tool_env_vars), len(candidate_env_vars))
                
                if compatibility_score >= self.match_threshold:
                    matches.append(ToolMatch(
                        primary_id=classification_id,
                        secondary_id=candidate["id"],
                        match_type="env_vars",
                        compatibility_score=compatibility_score,
                        shared_elements=list(shared_env_vars),
                        match_reason=f"Share {len(shared_env_vars)} environment variables: {', '.join(list(shared_env_vars)[:3])}",
                        trust_score_combined=combined_trust
                    ))
        
        return matches
    
    async def find_protocol_matches(self, classification_id: str) -> list[ToolMatch]:
        """Find tools that use compatible network protocols."""
        tool = await db.select_one("forge_classification", {"id": classification_id})
        if not tool:
            return []
        
        tool_protocols = set(json.loads(tool.get("network_protocols", "[]")))
        if not tool_protocols:
            return []
        
        # Protocol compatibility matrix
        compatible_protocols = {
            "HTTP": ["HTTP", "REST", "Webhook"],
            "WebSocket": ["WebSocket", "HTTP"],
            "gRPC": ["gRPC", "HTTP"],
            "GraphQL": ["GraphQL", "HTTP"],
            "Webhook": ["Webhook", "HTTP"]
        }
        
        # Find compatible tools
        candidates = await db.select("forge_classification", {}, limit=1000)
        matches = []
        
        for candidate in candidates:
            if candidate["id"] == classification_id:
                continue
            
            candidate_protocols = set(json.loads(candidate.get("network_protocols", "[]")))
            
            # Check for protocol compatibility
            compatible = False
            shared_protocols = []
            for tool_protocol in tool_protocols:
                for candidate_protocol in candidate_protocols:
                    if candidate_protocol in compatible_protocols.get(tool_protocol, []):
                        compatible = True
                        shared_protocols.append(f"{tool_protocol}-{candidate_protocol}")
            
            if compatible:
                primary_trust = await self._get_trust_score(tool["ecosystem"], tool["package_name"])
                secondary_trust = await self._get_trust_score(candidate["ecosystem"], candidate["package_name"])
                combined_trust = (primary_trust + secondary_trust) / 2
                
                compatibility_score = min(0.8, len(shared_protocols) * 0.4)  # Cap at 0.8
                
                matches.append(ToolMatch(
                    primary_id=classification_id,
                    secondary_id=candidate["id"],
                    match_type="protocols",
                    compatibility_score=compatibility_score,
                    shared_elements=shared_protocols,
                    match_reason=f"Compatible protocols: {', '.join(shared_protocols[:2])}",
                    trust_score_combined=combined_trust
                ))
        
        return matches
    
    async def find_complementary_matches(self, classification_id: str) -> list[ToolMatch]:
        """Find tools with complementary capabilities."""
        # Get tool's capabilities
        capabilities = await db.select("forge_capabilities", {"classification_id": classification_id})
        if not capabilities:
            return []
        
        tool_caps = {cap["capability"] for cap in capabilities}
        
        # Complementary capability mappings
        complementary_caps = {
            "accesses_database": ["reads_files", "processes_user_input"],
            "makes_network_calls": ["handles_credentials", "processes_user_input"],
            "reads_files": ["processes_user_input", "generates_content"],
            "processes_user_input": ["generates_content", "accesses_database"],
            "handles_credentials": ["makes_network_calls", "accesses_database"]
        }
        
        # Find tools with complementary capabilities
        all_classifications = await db.select("forge_classification", {}, limit=1000)
        matches = []
        
        for classification in all_classifications:
            if classification["id"] == classification_id:
                continue
            
            # Get candidate capabilities
            candidate_caps_data = await db.select("forge_capabilities", {"classification_id": classification["id"]})
            candidate_caps = {cap["capability"] for cap in candidate_caps_data}
            
            # Check for complementary relationships
            complement_score = 0.0
            complementary_pairs = []
            
            for tool_cap in tool_caps:
                for comp_cap in complementary_caps.get(tool_cap, []):
                    if comp_cap in candidate_caps:
                        complement_score += 0.3
                        complementary_pairs.append(f"{tool_cap}+{comp_cap}")
            
            if complement_score >= self.match_threshold:
                primary_trust = await self._get_trust_score(classification["ecosystem"], classification["package_name"])
                tool_data = await db.select_one("forge_classification", {"id": classification_id})
                secondary_trust = await self._get_trust_score(tool_data["ecosystem"], tool_data["package_name"])
                combined_trust = (primary_trust + secondary_trust) / 2
                
                matches.append(ToolMatch(
                    primary_id=classification_id,
                    secondary_id=classification["id"],
                    match_type="complementary",
                    compatibility_score=min(complement_score, 1.0),
                    shared_elements=complementary_pairs,
                    match_reason=f"Complementary capabilities: {', '.join(complementary_pairs[:2])}",
                    trust_score_combined=combined_trust
                ))
        
        return matches
    
    async def find_category_matches(self, classification_id: str) -> list[ToolMatch]:
        """Find tools in related categories."""
        tool = await db.select_one("forge_classification", {"id": classification_id})
        if not tool:
            return []
        
        tool_category = tool["category"]
        
        # Category relationship matrix (which categories work well together)
        related_categories = {
            "Database": ["API Integration", "Data Pipeline", "Monitoring"],
            "API Integration": ["Database", "Communication", "Security"],
            "Code Tools": ["Testing", "DevOps", "Security"],
            "File System": ["Code Tools", "Data Pipeline", "Security"],
            "AI/LLM": ["API Integration", "Data Pipeline", "Communication"],
            "Security": ["Code Tools", "API Integration", "Monitoring"],
            "DevOps": ["Code Tools", "Monitoring", "Security"],
            "Communication": ["API Integration", "AI/LLM"],
            "Data Pipeline": ["Database", "AI/LLM", "File System"],
            "Testing": ["Code Tools", "DevOps"],
            "Search": ["Database", "API Integration", "AI/LLM"],
            "Monitoring": ["DevOps", "Database", "Security"]
        }
        
        related = related_categories.get(tool_category, [])
        if not related:
            return []
        
        # Find tools in related categories
        matches = []
        for category in related:
            candidates = await db.select("forge_classification", {"category": category}, limit=50)
            
            for candidate in candidates:
                if candidate["id"] == classification_id:
                    continue
                
                # Different ecosystems get bonus points (skill + MCP pairing)
                ecosystem_bonus = 0.2 if tool["ecosystem"] != candidate["ecosystem"] else 0.0
                base_score = 0.4 + ecosystem_bonus
                
                primary_trust = await self._get_trust_score(tool["ecosystem"], tool["package_name"])
                secondary_trust = await self._get_trust_score(candidate["ecosystem"], candidate["package_name"])
                combined_trust = (primary_trust + secondary_trust) / 2
                
                matches.append(ToolMatch(
                    primary_id=classification_id,
                    secondary_id=candidate["id"],
                    match_type="category",
                    compatibility_score=base_score,
                    shared_elements=[f"{tool_category}-{category}"],
                    match_reason=f"{tool_category} + {category} category pairing",
                    trust_score_combined=combined_trust
                ))
        
        return matches[:10]  # Limit category matches
    
    async def _get_trust_score(self, ecosystem: str, package_name: str) -> float:
        """Get trust score from Sigil scan (inverse of risk_score)."""
        scan = await db.select_one("public_scans", {
            "ecosystem": ecosystem,
            "package_name": package_name
        })
        
        if not scan:
            return 50.0  # Default neutral score
        
        risk_score = scan.get("risk_score", 0.0)
        # Convert risk score to trust score (inverse relationship)
        # Risk 0-10 -> Trust 100-90, Risk 10-20 -> Trust 90-80, etc.
        trust_score = max(0.0, 100.0 - (risk_score * 5))
        return trust_score
    
    async def generate_all_matches(self, classification_id: str) -> list[ToolMatch]:
        """Generate all types of matches for a tool."""
        all_matches = []
        
        # Get matches from different sources
        env_matches = await self.find_env_var_matches(classification_id)
        protocol_matches = await self.find_protocol_matches(classification_id)
        complementary_matches = await self.find_complementary_matches(classification_id)
        category_matches = await self.find_category_matches(classification_id)
        
        all_matches.extend(env_matches)
        all_matches.extend(protocol_matches)
        all_matches.extend(complementary_matches)
        all_matches.extend(category_matches)
        
        # Sort by compatibility score and trust
        all_matches.sort(key=lambda m: (m.compatibility_score * m.trust_score_combined), reverse=True)
        
        # Remove duplicates (same tool pair)
        seen_pairs = set()
        unique_matches = []
        for match in all_matches:
            pair_key = tuple(sorted([match.primary_id, match.secondary_id]))
            if pair_key not in seen_pairs:
                seen_pairs.add(pair_key)
                unique_matches.append(match)
        
        return unique_matches[:20]  # Top 20 matches per tool
    
    async def save_matches(self, matches: list[ToolMatch]) -> int:
        """Save matches to database."""
        saved_count = 0
        
        for match in matches:
            try:
                await db.insert("forge_matches", {
                    "primary_classification_id": match.primary_id,
                    "secondary_classification_id": match.secondary_id,
                    "match_type": match.match_type,
                    "compatibility_score": match.compatibility_score,
                    "shared_elements": json.dumps(match.shared_elements),
                    "match_reason": match.match_reason,
                    "trust_score_combined": match.trust_score_combined,
                    "created_at": datetime.now(timezone.utc),
                    "updated_at": datetime.now(timezone.utc)
                })
                saved_count += 1
            except Exception as e:
                logger.error(f"Failed to save match: {e}")
                continue
        
        return saved_count
    
    async def generate_forge_stack(self, use_case: str) -> dict[str, Any]:
        """Generate a Forge Stack for a specific use case."""
        # Simple use case matching for now
        use_case_lower = use_case.lower()
        
        stack_config = {}
        
        if "database" in use_case_lower and "postgres" in use_case_lower:
            stack_config = {
                "name": "PostgreSQL Agent Stack",
                "description": "Complete stack for PostgreSQL database operations",
                "required_categories": ["Database"],
                "preferred_env_vars": ["DATABASE_URL", "POSTGRES_URL"],
                "ecosystem_mix": True  # Prefer skill + MCP combination
            }
        elif "github" in use_case_lower:
            stack_config = {
                "name": "GitHub Integration Stack",
                "description": "Tools for GitHub API operations and code review",
                "required_categories": ["API Integration", "Code Tools"],
                "preferred_env_vars": ["GITHUB_TOKEN"],
                "ecosystem_mix": True
            }
        elif "web" in use_case_lower and ("search" in use_case_lower or "research" in use_case_lower):
            stack_config = {
                "name": "Web Research Stack", 
                "description": "Web search and content analysis tools",
                "required_categories": ["Search", "AI/LLM"],
                "preferred_env_vars": ["OPENAI_API_KEY", "ANTHROPIC_API_KEY"],
                "ecosystem_mix": True
            }
        else:
            stack_config = {
                "name": "General Purpose Stack",
                "description": "Versatile tools for common tasks", 
                "required_categories": ["Code Tools", "File System"],
                "preferred_env_vars": [],
                "ecosystem_mix": False
            }
        
        # Find tools matching the stack requirements
        stack_tools = []
        for category in stack_config["required_categories"]:
            tools = await db.select(
                "forge_classification",
                {"category": category},
                order_by="confidence_score",
                order_desc=True,
                limit=5
            )
            
            # Filter by trust score
            for tool in tools:
                trust_score = await self._get_trust_score(tool["ecosystem"], tool["package_name"])
                if trust_score >= 70:  # High trust threshold for stacks
                    stack_tools.append({
                        **tool,
                        "trust_score": trust_score,
                        "install_command": self._generate_install_command(tool)
                    })
                    break  # One tool per category
        
        return {
            "stack": stack_config,
            "tools": stack_tools,
            "total_trust_score": sum(t["trust_score"] for t in stack_tools) / len(stack_tools) if stack_tools else 0,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
    
    def _generate_install_command(self, tool: dict[str, Any]) -> str:
        """Generate installation command for a tool."""
        ecosystem = tool["ecosystem"]
        name = tool["package_name"]
        version = tool.get("package_version", "")
        
        if ecosystem == "clawhub":
            return f"npx skills add {name}" + (f"@{version}" if version else "")
        elif ecosystem == "mcp":
            return f"# Add to claude_desktop_config.json: {name}"
        elif ecosystem == "npm":
            return f"npm install {name}" + (f"@{version}" if version else "")
        elif ecosystem == "pypi":
            return f"pip install {name}" + (f"=={version}" if version else "")
        else:
            return f"# Install {name} from {ecosystem}"


# Global instance
forge_matcher = ForgeMatcher()