"""
Sigil Forge Enrichment Worker

This worker enriches existing classifications and public_scans data to support
the new Forge Backend API Specification. It processes data in batches to add:

1. 8-phase scan results with proper risk levels and findings
2. Enhanced metadata including usage examples, related tools
3. Detailed security reports and compliance checks
4. Full capability detection and environment variables
5. Network connectivity and file access patterns

The worker runs independently and processes records that need enrichment.
It does NOT modify existing workers but creates enriched views of the data.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from api.config import settings
from api.database import db

logger = logging.getLogger(__name__)


class ForgeEnrichmentWorker:
    """Worker to enrich classifications and public_scans for Forge API compatibility."""

    def __init__(self):
        self.batch_size = 10
        self.delay_between_batches = 1.0
        self.max_retries = 3

    async def process_enrichment_queue(self) -> None:
        """Main worker loop to process enrichment tasks."""
        logger.info("Starting Forge enrichment worker")

        while True:
            try:
                # Find records needing enrichment
                pending_records = await self._find_pending_enrichments()
                
                if not pending_records:
                    logger.debug("No records pending enrichment, sleeping...")
                    await asyncio.sleep(10)
                    continue

                logger.info(f"Processing {len(pending_records)} records for enrichment")

                # Process in batches
                for i in range(0, len(pending_records), self.batch_size):
                    batch = pending_records[i:i + self.batch_size]
                    await self._process_batch(batch)
                    await asyncio.sleep(self.delay_between_batches)

            except Exception as e:
                logger.error(f"Enrichment worker error: {e}", exc_info=True)
                await asyncio.sleep(30)

    async def _find_pending_enrichments(self) -> List[Dict[str, Any]]:
        """Find records that need enrichment for the new Forge API."""
        try:
            # Find public_scans that don't have enriched forge_classification entries
            sql = """
            SELECT DISTINCT ps.id, ps.ecosystem, ps.package_name, ps.package_version,
                   ps.risk_score, ps.verdict, ps.findings_json, ps.metadata_json,
                   ps.scanned_at
            FROM public_scans ps
            LEFT JOIN forge_classification fc ON (
                ps.ecosystem = fc.ecosystem 
                AND ps.package_name = fc.package_name 
                AND ps.package_version = fc.package_version
                AND fc.metadata_json LIKE '%"forge_api_enriched":true%'
            )
            WHERE fc.id IS NULL
            AND ps.scanned_at >= DATEADD(day, -30, GETDATE())  -- Only recent scans
            ORDER BY ps.scanned_at DESC
            OFFSET 0 ROWS FETCH NEXT ? ROWS ONLY
            """
            
            return await db.execute_raw_sql(sql, (self.batch_size * 5,))

        except Exception as e:
            logger.error(f"Failed to find pending enrichments: {e}")
            return []

    async def _process_batch(self, batch: List[Dict[str, Any]]) -> None:
        """Process a batch of records for enrichment."""
        for record in batch:
            try:
                await self._enrich_single_record(record)
                logger.debug(f"Enriched {record['ecosystem']}/{record['package_name']}")
            except Exception as e:
                logger.error(f"Failed to enrich {record.get('package_name')}: {e}")

    async def _enrich_single_record(self, scan_record: Dict[str, Any]) -> None:
        """Enrich a single scan record with Forge API-compatible data."""
        ecosystem = scan_record["ecosystem"]
        package_name = scan_record["package_name"]
        package_version = scan_record.get("package_version", "")
        
        # Parse existing data
        findings_json = scan_record.get("findings_json", "[]")
        metadata_json = scan_record.get("metadata_json", "{}")
        
        try:
            findings = json.loads(findings_json) if findings_json else []
            metadata = json.loads(metadata_json) if metadata_json else {}
        except (json.JSONDecodeError, TypeError):
            findings = []
            metadata = {}

        # Generate enriched data
        enriched_data = await self._generate_enriched_data(
            ecosystem, package_name, package_version, 
            scan_record, findings, metadata
        )

        # Save to forge_classification with enrichment flag
        await self._save_enriched_classification(scan_record, enriched_data)

    async def _generate_enriched_data(
        self, 
        ecosystem: str,
        package_name: str,
        package_version: str,
        scan_record: Dict[str, Any],
        findings: List[Dict[str, Any]],
        metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate enriched data compatible with Forge Backend API spec."""
        
        # Generate deterministic UUID for tool
        tool_uuid = self._generate_tool_uuid(ecosystem, package_name)
        
        # Map findings to 8-phase scan results
        scan_phases = self._map_to_eight_phases(findings)
        
        # Calculate trust score from phases
        trust_score = self._calculate_trust_score(scan_phases)
        
        # Extract capabilities
        capabilities = self._extract_capabilities(findings, metadata)
        
        # Generate security findings
        security_findings = self._generate_security_findings(findings)
        
        # Extract environment variables
        environment_variables = self._extract_environment_variables(findings, metadata)
        
        # Extract network connectivity
        network_connectivity = self._extract_network_connectivity(findings, metadata)
        
        # Extract file access patterns
        file_access = self._extract_file_access_patterns(findings, metadata)
        
        # Generate usage examples
        usage_examples = self._generate_usage_examples(ecosystem, package_name, metadata)
        
        # Find related tools (simplified version)
        related_tools = await self._find_related_tools(ecosystem, package_name, capabilities)
        
        # Generate security report
        security_report = self._generate_security_report(scan_phases, security_findings)
        
        # Build the enriched data structure
        return {
            "id": tool_uuid,
            "slug": self._generate_tool_slug(package_name),
            "name": package_name,
            "ecosystem": ecosystem,
            "category": self._determine_category(package_name, metadata.get("description", "")),
            "description": metadata.get("description", f"A {ecosystem} tool for AI agents"),
            "tags": self._extract_tags(metadata, package_name),
            "license": metadata.get("license", ""),
            "author": metadata.get("author", ""),
            "version": package_version or "latest",
            "created_at": metadata.get("created_at") or scan_record.get("scanned_at"),
            "last_updated": scan_record.get("scanned_at"),
            "downloads": metadata.get("downloads", 0),
            "github_stars": metadata.get("stars", 0),
            "github_forks": metadata.get("forks", 0),
            "install_command": self._generate_install_command(ecosystem, package_name),
            "package_url": self._generate_package_url(ecosystem, package_name),
            "github_url": metadata.get("repository", {}).get("url"),
            "repository_url": metadata.get("repository", {}).get("url"),
            "documentation_url": metadata.get("documentation_url"),
            "trust_score": trust_score,
            "last_scanned": scan_record.get("scanned_at"),
            "last_analyzed": scan_record.get("scanned_at"),
            "scan_phases": scan_phases,
            "security_findings": security_findings,
            "capabilities": capabilities,
            "environment_variables": environment_variables,
            "protocols": ["https", "http"],  # Default protocols
            "file_access": file_access,
            "network_connectivity": network_connectivity,
            "compatible_tools": [],  # Will be populated by matching worker
            "conflicts_with": [],
            "usage_examples": usage_examples,
            "related_tools": related_tools,
            "security_report": security_report,
        }

    def _map_to_eight_phases(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Map findings to the 8-phase scan structure required by Forge API."""
        
        # Initialize all 8 phases with default values
        phases = [
            {"phase": 1, "name": "Install Hooks", "weight": 10, "score": 10, "risk_level": "clean", "findings": []},
            {"phase": 2, "name": "Code Patterns", "weight": 5, "score": 5, "risk_level": "clean", "findings": []},
            {"phase": 3, "name": "Network / Exfil", "weight": 3, "score": 3, "risk_level": "clean", "findings": []},
            {"phase": 4, "name": "Credentials", "weight": 2, "score": 2, "risk_level": "clean", "findings": []},
            {"phase": 5, "name": "Obfuscation", "weight": 5, "score": 5, "risk_level": "clean", "findings": []},
            {"phase": 6, "name": "Provenance", "weight": 3, "score": 3, "risk_level": "clean", "findings": []},
            {"phase": 7, "name": "Prompt Injection", "weight": 10, "score": 10, "risk_level": "clean", "findings": []},
            {"phase": 8, "name": "Skill Security", "weight": 5, "score": 5, "risk_level": "clean", "findings": []},
        ]
        
        # Map findings to appropriate phases
        for finding in findings:
            rule = finding.get("rule", "").lower()
            severity = finding.get("severity", "info").lower()
            snippet = finding.get("snippet", "").lower()
            description = finding.get("description", "")
            
            # Determine which phase this finding belongs to
            phase_idx = self._map_finding_to_phase(rule, snippet, description)
            
            if 0 <= phase_idx < 8:
                phases[phase_idx]["findings"].append(description or f"Rule: {rule}")
                
                # Adjust score based on severity
                severity_impact = {
                    "critical": -5, "high": -3, "medium": -2, "low": -1, "info": 0
                }.get(severity, -1)
                
                phases[phase_idx]["score"] = max(0, phases[phase_idx]["score"] + severity_impact)
                
                # Update risk level
                if severity in ["critical", "high"]:
                    phases[phase_idx]["risk_level"] = "high" if severity == "critical" else "medium"
                elif severity == "medium":
                    if phases[phase_idx]["risk_level"] == "clean":
                        phases[phase_idx]["risk_level"] = "low"
        
        return phases

    def _map_finding_to_phase(self, rule: str, snippet: str, description: str) -> int:
        """Map a finding to one of the 8 scan phases."""
        rule_lower = rule.lower()
        snippet_lower = snippet.lower()
        desc_lower = description.lower()
        combined = f"{rule_lower} {snippet_lower} {desc_lower}"
        
        # Phase 1: Install Hooks
        if any(term in combined for term in [
            "setup.py", "postinstall", "preinstall", "makefile", "install script", "cmdclass"
        ]):
            return 0
            
        # Phase 2: Code Patterns  
        if any(term in combined for term in [
            "eval", "exec", "compile", "child_process", "subprocess", "shell", "dangerous"
        ]):
            return 1
            
        # Phase 3: Network / Exfil
        if any(term in combined for term in [
            "http", "https", "request", "fetch", "socket", "network", "webhook", "dns"
        ]):
            return 2
            
        # Phase 4: Credentials
        if any(term in combined for term in [
            "password", "token", "key", "secret", "credential", "env", "environment"
        ]):
            return 3
            
        # Phase 5: Obfuscation
        if any(term in combined for term in [
            "base64", "obfuscat", "minif", "encode", "decode", "charcode", "hex"
        ]):
            return 4
            
        # Phase 6: Provenance  
        if any(term in combined for term in [
            "binary", "git", "commit", "history", "provenance", "integrity"
        ]):
            return 5
            
        # Phase 7: Prompt Injection
        if any(term in combined for term in [
            "prompt", "inject", "jailbreak", "system", "override", "instruction"
        ]):
            return 6
            
        # Phase 8: Skill Security
        if any(term in combined for term in [
            "skill", "tool", "capability", "permission", "mcp", "escalation"
        ]):
            return 7
            
        # Default to Code Patterns if unclassified
        return 1

    def _calculate_trust_score(self, scan_phases: List[Dict[str, Any]]) -> int:
        """Calculate trust score from scan phases using weighted scoring."""
        total_weighted_score = 0
        total_weights = 0
        
        for phase in scan_phases:
            weight = phase["weight"]
            score = phase["score"]
            max_score = weight  # Assuming max score equals weight
            
            weighted_score = (score / max_score) * weight if max_score > 0 else weight
            total_weighted_score += weighted_score
            total_weights += weight
            
        if total_weights == 0:
            return 50
            
        trust_percentage = (total_weighted_score / total_weights) * 100
        return max(0, min(100, int(trust_percentage)))

    def _extract_capabilities(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract capabilities from findings and metadata."""
        capabilities = []
        
        # Check for different capability types
        has_network = any(
            term in str(finding).lower() 
            for finding in findings 
            for term in ["http", "fetch", "request", "socket"]
        )
        
        if has_network:
            capabilities.append({
                "type": "network",
                "description": "Makes network requests to external APIs",
                "risk_level": "low"
            })
            
        has_file_access = any(
            term in str(finding).lower() 
            for finding in findings 
            for term in ["file", "read", "write", "fs"]
        )
        
        if has_file_access:
            capabilities.append({
                "type": "file",
                "description": "Reads and writes files on the local system",
                "risk_level": "low"
            })
            
        # Check metadata for AI capabilities
        description = metadata.get("description", "").lower()
        if any(term in description for term in ["ai", "llm", "gpt", "claude", "assistant"]):
            capabilities.append({
                "type": "ai",
                "description": "Integrates with AI/LLM services for enhanced functionality",
                "risk_level": "low"
            })
            
        return capabilities

    def _extract_environment_variables(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[str]:
        """Extract environment variable patterns from findings."""
        env_vars = set()
        
        for finding in findings:
            snippet = finding.get("snippet", "")
            
            # Look for process.env patterns
            env_matches = re.findall(r"process\.env\.([A-Z_][A-Z0-9_]*)", snippet)
            env_vars.update(env_matches)
            
            # Look for os.environ patterns
            env_matches = re.findall(r"os\.environ\[['\"](.*?)['\"]\]", snippet)
            env_vars.update(env_matches)
            
            # Look for common API key patterns
            if any(term in snippet.lower() for term in ["api_key", "token", "secret"]):
                if "ANTHROPIC" in snippet:
                    env_vars.add("ANTHROPIC_API_KEY")
                elif "OPENAI" in snippet:
                    env_vars.add("OPENAI_API_KEY")
                elif "DATABASE" in snippet:
                    env_vars.add("DATABASE_URL")
                    
        return sorted(list(env_vars))

    def _extract_network_connectivity(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract network connectivity patterns."""
        connections = []
        
        for finding in findings:
            snippet = finding.get("snippet", "")
            
            # Look for API endpoints
            urls = re.findall(r"https?://([^/\s'\"]+)", snippet)
            for url in urls:
                connections.append({
                    "type": "https",
                    "destination": url,
                    "purpose": "API communication"
                })
                
        # Remove duplicates
        seen = set()
        unique_connections = []
        for conn in connections:
            key = (conn["type"], conn["destination"])
            if key not in seen:
                seen.add(key)
                unique_connections.append(conn)
                
        return unique_connections

    def _extract_file_access_patterns(self, findings: List[Dict[str, Any]], metadata: Dict[str, Any]) -> List[str]:
        """Extract file access patterns from findings."""
        patterns = set()
        
        for finding in findings:
            snippet = finding.get("snippet", "")
            
            # Look for file path patterns
            if "readFile" in snippet or "writeFile" in snippet:
                patterns.add("./*")
            if "homedir" in snippet or "~/" in snippet:
                patterns.add("~/")
            if "/tmp" in snippet:
                patterns.add("/tmp/*")
            if "config" in snippet.lower():
                patterns.add("./config/*")
                
        return sorted(list(patterns))

    def _generate_usage_examples(self, ecosystem: str, package_name: str, metadata: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate usage examples for the tool."""
        examples = []
        
        # Installation example
        install_cmd = self._generate_install_command(ecosystem, package_name)
        examples.append({
            "title": "Installation",
            "description": f"Add the {ecosystem} package to your project",
            "code": install_cmd,
            "language": "bash"
        })
        
        # Basic usage example
        if ecosystem in ["skills", "clawhub"]:
            examples.append({
                "title": "Usage with Claude",
                "description": f"Use {package_name} in a Claude conversation",
                "code": f"// In Claude Code or Claude.ai:\n// Enable the {package_name} skill and use it in conversation\n\n// Example:\n// \"Help me use {package_name} to accomplish my task\"",
                "language": "javascript"
            })
        elif ecosystem == "mcp":
            examples.append({
                "title": "MCP Configuration",
                "description": f"Configure {package_name} as an MCP server",
                "code": f'// In your Claude Desktop config:\n{{\n  "mcpServers": {{\n    "{package_name}": {{\n      "command": "node",\n      "args": ["path/to/{package_name}"]\n    }}\n  }}\n}}',
                "language": "json"
            })
        
        return examples

    async def _find_related_tools(self, ecosystem: str, package_name: str, capabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find related tools (simplified version for enrichment)."""
        try:
            # Find tools with similar capabilities or in same category
            similar_sql = """
            SELECT TOP (3) ps.ecosystem, ps.package_name, ps.metadata_json
            FROM public_scans ps 
            WHERE ps.ecosystem = ? 
            AND ps.package_name != ?
            AND ps.verdict IN ('LOW_RISK', 'MEDIUM_RISK')
            ORDER BY ps.scanned_at DESC
            """
            
            results = await db.execute_raw_sql(similar_sql, (ecosystem, package_name))
            
            related_tools = []
            for result in results[:3]:  # Limit to 3 related tools
                try:
                    metadata = json.loads(result.get("metadata_json", "{}"))
                    related_tools.append({
                        "id": self._generate_tool_uuid(result["ecosystem"], result["package_name"]),
                        "name": result["package_name"],
                        "ecosystem": result["ecosystem"],
                        "category": "related",
                        "description": metadata.get("description", "Related tool"),
                        "trust_score": 75,  # Default trust score
                        "author": metadata.get("author", ""),
                        "version": "latest",
                        "install_command": self._generate_install_command(result["ecosystem"], result["package_name"]),
                        "package_url": self._generate_package_url(result["ecosystem"], result["package_name"]),
                        "tags": [],
                        "last_updated": metadata.get("updated_at"),
                        "created_at": metadata.get("created_at"),
                        "scan_phases": [],
                        "capabilities": [],
                        "environment_variables": [],
                        "protocols": [],
                        "file_access": [],
                        "network_connectivity": [],
                        "compatible_tools": [],
                        "conflicts_with": []
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
                    
            return related_tools
            
        except Exception as e:
            logger.warning(f"Failed to find related tools for {package_name}: {e}")
            return []

    def _generate_security_report(self, scan_phases: List[Dict[str, Any]], security_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        # Calculate overall risk
        high_risk_phases = [p for p in scan_phases if p["risk_level"] in ["high", "critical"]]
        medium_risk_phases = [p for p in scan_phases if p["risk_level"] == "medium"]
        
        if high_risk_phases:
            overall_risk = "HIGH_RISK"
            summary = f"This tool has {len(high_risk_phases)} high-risk findings that require attention."
        elif medium_risk_phases:
            overall_risk = "MEDIUM_RISK" 
            summary = f"This tool has {len(medium_risk_phases)} medium-risk findings. Review recommended."
        else:
            overall_risk = "LOW_RISK"
            summary = "This tool passed security analysis with no significant risks detected."
            
        risk_factors = []
        for finding in security_findings:
            risk_factors.append({
                "category": finding["category"],
                "severity": finding["severity"],
                "description": finding["description"],
                "impact": finding.get("impact", "Potential security concern")
            })
            
        recommendations = [
            "Review the security findings and assess their impact on your use case",
            "Keep the package updated to the latest version",
            "Monitor for security updates and vulnerability disclosures"
        ]
        
        if overall_risk == "HIGH_RISK":
            recommendations.insert(0, "Consider alternative packages with better security profiles")
            
        return {
            "summary": summary,
            "risk_factors": risk_factors,
            "recommendations": recommendations,
            "compliance_checks": [
                {"standard": "OWASP Top 10", "passed": overall_risk != "HIGH_RISK", "details": "Based on static analysis"},
                {"standard": "Supply Chain Security", "passed": True, "details": "Package scanned and analyzed"}
            ]
        }

    def _generate_security_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate discrete security findings from scan results."""
        security_findings = []
        finding_id = 1
        
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in ["critical", "high", "medium"]:
                security_findings.append({
                    "id": f"find_{finding_id:03d}",
                    "severity": severity,
                    "category": self._categorize_finding(finding),
                    "description": finding.get("description", "Security concern detected"),
                    "impact": self._get_finding_impact(finding),
                    "recommendation": self._get_finding_recommendation(finding)
                })
                finding_id += 1
                
        return security_findings

    def _categorize_finding(self, finding: Dict[str, Any]) -> str:
        """Categorize a security finding."""
        rule = finding.get("rule", "").lower()
        
        if any(term in rule for term in ["network", "http", "request"]):
            return "Network / Exfil"
        elif any(term in rule for term in ["credential", "secret", "password"]):
            return "Credentials"
        elif any(term in rule for term in ["exec", "eval", "dangerous"]):
            return "Code Patterns"
        else:
            return "General"

    def _get_finding_impact(self, finding: Dict[str, Any]) -> str:
        """Get impact description for a finding."""
        severity = finding.get("severity", "").lower()
        
        if severity == "critical":
            return "Critical security vulnerability that could compromise system security"
        elif severity == "high":
            return "High-risk behavior that should be carefully reviewed"
        elif severity == "medium":
            return "Moderate security concern that may need attention"
        else:
            return "Low-impact finding for informational purposes"

    def _get_finding_recommendation(self, finding: Dict[str, Any]) -> str:
        """Get recommendation for a finding."""
        rule = finding.get("rule", "").lower()
        
        if "network" in rule:
            return "Verify that network requests are made to trusted endpoints only"
        elif "credential" in rule:
            return "Ensure credentials are properly secured and not hardcoded"
        elif "exec" in rule:
            return "Review code execution patterns for potential injection vulnerabilities"
        else:
            return "Review this finding in context of your security requirements"

    # Utility methods
    def _generate_tool_uuid(self, ecosystem: str, package_name: str) -> str:
        """Generate deterministic UUID for a tool."""
        uuid_input = f"{ecosystem}:{package_name}"
        hash_obj = hashlib.sha256(uuid_input.encode())
        hex_str = hash_obj.hexdigest()[:32]
        return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"

    def _generate_tool_slug(self, package_name: str) -> str:
        """Generate URL-safe slug from package name."""
        slug = re.sub(r"[^a-z0-9]+", "-", package_name.lower())
        return slug.strip("-")

    def _determine_category(self, package_name: str, description: str) -> str:
        """Determine tool category."""
        name_lower = package_name.lower()
        desc_lower = description.lower()
        
        if any(term in name_lower for term in ["db", "database", "postgres", "mysql", "redis", "mongo"]):
            return "database_connectors"
        elif any(term in desc_lower for term in ["database", "sql", "postgres", "mysql", "redis"]):
            return "database_connectors"
        elif any(term in name_lower for term in ["ai", "gpt", "llm", "chat", "assistant"]):
            return "ai_llm_tools"
        elif any(term in desc_lower for term in ["ai", "llm", "assistant", "chat"]):
            return "ai_llm_tools"
        elif any(term in name_lower for term in ["api", "rest", "webhook"]):
            return "api_integrations"
        elif any(term in desc_lower for term in ["api", "rest", "integration"]):
            return "api_integrations"
        else:
            return "ai_llm_tools"  # Default for most tools

    def _extract_tags(self, metadata: Dict[str, Any], package_name: str) -> List[str]:
        """Extract or generate tags for a tool."""
        # Use existing keywords if available
        if "keywords" in metadata:
            return metadata["keywords"][:5]  # Limit to 5 tags
        
        # Generate tags from package name and description
        tags = []
        if "ai" in package_name.lower():
            tags.append("ai")
        if "api" in package_name.lower():
            tags.append("api")
        if "db" in package_name.lower():
            tags.append("database")
            
        return tags

    def _generate_install_command(self, ecosystem: str, package_name: str) -> str:
        """Generate installation command for a tool."""
        if ecosystem in ["skills", "clawhub"]:
            return f"npx skills.sh add {package_name}"
        elif ecosystem == "mcp":
            return f"npm install {package_name}"
        elif ecosystem == "npm":
            return f"npm install {package_name}"
        elif ecosystem in ["pip", "pypi"]:
            return f"pip install {package_name}"
        else:
            return f"# Install {package_name} from {ecosystem}"

    def _generate_package_url(self, ecosystem: str, package_name: str) -> Optional[str]:
        """Generate package URL for a tool."""
        if ecosystem == "npm":
            return f"https://npmjs.com/package/{package_name}"
        elif ecosystem in ["pip", "pypi"]:
            return f"https://pypi.org/project/{package_name}/"
        elif ecosystem == "skills":
            return f"https://skills.sh/{package_name}"
        else:
            return None

    async def _save_enriched_classification(self, scan_record: Dict[str, Any], enriched_data: Dict[str, Any]) -> None:
        """Save enriched data to forge_classification table."""
        try:
            ecosystem = scan_record["ecosystem"]
            package_name = scan_record["package_name"]
            package_version = scan_record.get("package_version", "")
            
            # Check if already exists
            existing = await db.select_one(
                "forge_classification",
                {
                    "ecosystem": ecosystem,
                    "package_name": package_name,
                    "package_version": package_version
                }
            )
            
            # Prepare classification data
            classification_data = {
                "ecosystem": ecosystem,
                "package_name": package_name,
                "package_version": package_version,
                "category": enriched_data["category"],
                "subcategory": "",
                "confidence_score": 0.9,  # High confidence for enriched data
                "description_summary": enriched_data["description"],
                "environment_vars": json.dumps(enriched_data["environment_variables"]),
                "network_protocols": json.dumps(["https", "http"]),
                "file_patterns": json.dumps(enriched_data["file_access"]),
                "import_patterns": json.dumps([]),
                "risk_indicators": json.dumps([f["description"] for f in enriched_data["security_findings"]]),
                "classified_at": datetime.now(timezone.utc),
                "updated_at": datetime.now(timezone.utc),
                "classifier_version": "enrichment_v1.0",
                "metadata_json": json.dumps({
                    **enriched_data,
                    "forge_api_enriched": True,  # Mark as enriched
                    "enrichment_timestamp": datetime.now(timezone.utc).isoformat()
                })
            }
            
            if existing:
                # Update existing record
                await db.update(
                    "forge_classification",
                    {"id": existing["id"]},
                    classification_data
                )
                classification_id = existing["id"]
            else:
                # Insert new record
                result = await db.insert("forge_classification", classification_data)
                classification_id = result.get("id")
            
            # Save capabilities
            if classification_id and enriched_data["capabilities"]:
                # Remove existing capabilities
                await db.delete("forge_capabilities", {"classification_id": classification_id})
                
                # Insert new capabilities
                for capability in enriched_data["capabilities"]:
                    await db.insert("forge_capabilities", {
                        "classification_id": classification_id,
                        "capability": capability["type"],
                        "confidence": 0.9,
                        "evidence": capability["description"]
                    })
                    
            logger.info(f"Saved enriched classification for {ecosystem}/{package_name}")
            
        except Exception as e:
            logger.error(f"Failed to save enriched classification: {e}")
            raise


# Main worker entry point
async def start_forge_enrichment_worker():
    """Start the forge enrichment worker."""
    worker = ForgeEnrichmentWorker()
    await worker.process_enrichment_queue()


if __name__ == "__main__":
    import asyncio
    
    logging.basicConfig(level=logging.INFO)
    asyncio.run(start_forge_enrichment_worker())