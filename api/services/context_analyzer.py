"""
Contextual Threat Analysis Service
Analyzes code context to understand attack patterns and threat intent.
"""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from models import Finding
from llm_models import (
    LLMAnalysisRequest,
    LLMAnalysisType,
)
from services.llm_service import llm_service


logger = logging.getLogger(__name__)


class ContextAnalyzer:
    """Service for analyzing code context and correlating threats across files."""

    def __init__(self):
        self.correlation_cache = {}
        self.max_cache_entries = 1000

    async def analyze_repository_context(
        self,
        file_contents: dict[str, str],
        static_findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Analyze the overall repository context for threat patterns."""

        # Build repository fingerprint for caching
        repo_fingerprint = self._build_repository_fingerprint(
            file_contents, static_findings
        )

        if repo_fingerprint in self.correlation_cache:
            logger.info("Using cached repository context analysis")
            return self.correlation_cache[repo_fingerprint]

        try:
            # Analyze file relationships and architecture
            architecture_analysis = self._analyze_architecture(file_contents)

            # Correlate findings across files
            correlation_analysis = self._correlate_findings(
                static_findings, file_contents
            )

            # Identify attack patterns
            attack_patterns = await self._identify_attack_patterns(
                file_contents, static_findings, metadata or {}
            )

            # Build comprehensive context
            context = {
                "repository_fingerprint": repo_fingerprint,
                "architecture": architecture_analysis,
                "correlations": correlation_analysis,
                "attack_patterns": attack_patterns,
                "risk_factors": self._assess_risk_factors(
                    file_contents, static_findings
                ),
                "recommendations": self._generate_recommendations(
                    architecture_analysis, correlation_analysis, attack_patterns
                ),
            }

            # Cache the analysis
            self._cache_analysis(repo_fingerprint, context)

            return context

        except Exception as e:
            logger.exception(f"Context analysis failed: {e}")
            return {
                "repository_fingerprint": repo_fingerprint,
                "error": str(e),
                "architecture": {"files": len(file_contents), "analysis": "failed"},
                "correlations": {"cross_file_threats": []},
                "attack_patterns": {"detected_patterns": []},
                "risk_factors": {"overall_risk": "unknown"},
                "recommendations": ["Unable to perform context analysis due to error"],
            }

    def _analyze_architecture(self, file_contents: dict[str, str]) -> dict[str, Any]:
        """Analyze the repository architecture and file relationships."""

        file_types = {}
        dependencies = []
        entry_points = []
        configuration_files = []
        suspicious_patterns = []

        for filename, content in file_contents.items():
            # Categorize files by type
            file_ext = filename.split(".")[-1] if "." in filename else "unknown"
            file_types[file_ext] = file_types.get(file_ext, 0) + 1

            # Identify entry points
            if self._is_entry_point(filename, content):
                entry_points.append(filename)

            # Identify configuration files
            if self._is_config_file(filename):
                configuration_files.append(filename)

            # Extract dependencies
            file_deps = self._extract_dependencies(filename, content)
            dependencies.extend(file_deps)

            # Look for suspicious architectural patterns
            patterns = self._detect_suspicious_architecture_patterns(filename, content)
            suspicious_patterns.extend(patterns)

        return {
            "total_files": len(file_contents),
            "file_types": file_types,
            "entry_points": entry_points,
            "configuration_files": configuration_files,
            "dependencies": list(set(dependencies)),  # Remove duplicates
            "suspicious_patterns": suspicious_patterns,
            "complexity_score": self._calculate_complexity_score(file_contents),
        }

    def _correlate_findings(
        self, findings: list[Finding], file_contents: dict[str, str]
    ) -> dict[str, Any]:
        """Correlate findings across files to identify coordinated threats."""

        cross_file_threats = []
        finding_clusters = {}
        attack_chains = []

        # Group findings by file
        findings_by_file = {}
        for finding in findings:
            if finding.file not in findings_by_file:
                findings_by_file[finding.file] = []
            findings_by_file[finding.file].append(finding)

        # Look for cross-file patterns
        if len(findings_by_file) > 1:
            cross_file_threats = self._identify_cross_file_threats(
                findings_by_file, file_contents
            )

        # Cluster similar findings
        finding_clusters = self._cluster_similar_findings(findings)

        # Identify potential attack chains
        attack_chains = self._identify_attack_chains(findings, file_contents)

        return {
            "cross_file_threats": cross_file_threats,
            "finding_clusters": finding_clusters,
            "attack_chains": attack_chains,
            "correlation_strength": self._calculate_correlation_strength(findings),
        }

    async def _identify_attack_patterns(
        self,
        file_contents: dict[str, str],
        static_findings: list[Finding],
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        """Use LLM to identify sophisticated attack patterns."""

        try:
            # Prepare static findings data
            static_findings_data = [
                {
                    "phase": f.phase.value,
                    "rule": f.rule,
                    "severity": f.severity.value,
                    "file": f.file,
                    "description": f.description,
                }
                for f in static_findings
            ]

            # Request contextual correlation analysis from LLM
            analysis_request = LLMAnalysisRequest(
                file_contents=file_contents,
                static_findings=static_findings_data,
                repository_context=metadata,
                analysis_types=[LLMAnalysisType.CONTEXTUAL_CORRELATION],
                max_insights=10,
                include_context_analysis=True,
            )

            llm_response = await llm_service.analyze_threat(analysis_request)

            if llm_response.success and llm_response.context_analysis:
                return {
                    "llm_analysis_available": True,
                    "attack_chain_detected": llm_response.context_analysis.attack_chain_detected,
                    "coordinated_threat": llm_response.context_analysis.coordinated_threat,
                    "attack_chain_steps": llm_response.context_analysis.attack_chain_steps,
                    "overall_intent": llm_response.context_analysis.overall_intent,
                    "sophistication_level": llm_response.context_analysis.sophistication_level,
                    "correlation_insights": llm_response.context_analysis.correlation_insights,
                }
            else:
                logger.warning("LLM contextual analysis failed or unavailable")
                return {
                    "llm_analysis_available": False,
                    "fallback_patterns": self._detect_basic_attack_patterns(
                        file_contents, static_findings
                    ),
                }

        except Exception as e:
            logger.exception(f"LLM attack pattern analysis failed: {e}")
            return {
                "llm_analysis_available": False,
                "error": str(e),
                "fallback_patterns": self._detect_basic_attack_patterns(
                    file_contents, static_findings
                ),
            }

    def _assess_risk_factors(
        self, file_contents: dict[str, str], findings: list[Finding]
    ) -> dict[str, Any]:
        """Assess overall risk factors based on code and findings."""

        risk_factors = {
            "high_severity_findings": len(
                [f for f in findings if f.severity.value in ("HIGH", "CRITICAL")]
            ),
            "network_activity": len(
                [f for f in findings if "network" in f.rule or "http" in f.rule]
            ),
            "credential_access": len(
                [f for f in findings if "cred" in f.rule or "password" in f.rule]
            ),
            "code_execution": len(
                [f for f in findings if "eval" in f.rule or "exec" in f.rule]
            ),
            "obfuscation": len(
                [f for f in findings if "obf" in f.rule or "base64" in f.rule]
            ),
            "external_dependencies": self._count_external_dependencies(file_contents),
            "binary_files": len(
                [f for f in file_contents.keys() if self._is_binary_filename(f)]
            ),
        }

        # Calculate overall risk score
        risk_score = (
            risk_factors["high_severity_findings"] * 3
            + risk_factors["network_activity"] * 2
            + risk_factors["credential_access"] * 2
            + risk_factors["code_execution"] * 3
            + risk_factors["obfuscation"] * 2
            + min(risk_factors["external_dependencies"], 10)
            + risk_factors["binary_files"]
        )

        risk_level = "LOW"
        if risk_score > 15:
            risk_level = "CRITICAL"
        elif risk_score > 10:
            risk_level = "HIGH"
        elif risk_score > 5:
            risk_level = "MEDIUM"

        risk_factors.update(
            {
                "overall_risk_score": risk_score,
                "overall_risk_level": risk_level,
            }
        )

        return risk_factors

    def _generate_recommendations(
        self,
        architecture: dict[str, Any],
        correlations: dict[str, Any],
        attack_patterns: dict[str, Any],
    ) -> list[str]:
        """Generate security recommendations based on analysis."""

        recommendations = []

        # Architecture-based recommendations
        if len(architecture["entry_points"]) > 3:
            recommendations.append(
                "Consider reducing the number of entry points to minimize attack surface"
            )

        if architecture["complexity_score"] > 8:
            recommendations.append(
                "High code complexity detected - consider refactoring for better security review"
            )

        if architecture["suspicious_patterns"]:
            recommendations.append(
                f"Address {len(architecture['suspicious_patterns'])} suspicious architectural patterns"
            )

        # Correlation-based recommendations
        if correlations["cross_file_threats"]:
            recommendations.append(
                "Cross-file threat patterns detected - review coordinated security controls"
            )

        if correlations["attack_chains"]:
            recommendations.append(
                "Potential attack chains identified - implement defense in depth"
            )

        # Attack pattern-based recommendations
        if attack_patterns.get("attack_chain_detected"):
            recommendations.append(
                "Multi-stage attack pattern detected - review and strengthen all affected components"
            )

        if attack_patterns.get("sophistication_level") == "advanced":
            recommendations.append(
                "Advanced threat patterns detected - consider professional security audit"
            )

        # Default recommendations
        if not recommendations:
            recommendations.extend(
                [
                    "Implement comprehensive input validation across all entry points",
                    "Enable security logging and monitoring",
                    "Regular security dependency updates",
                    "Code review with security focus",
                ]
            )

        return recommendations

    def _build_repository_fingerprint(
        self, file_contents: dict[str, str], findings: list[Finding]
    ) -> str:
        """Build a fingerprint for repository content for caching."""
        content_hash = hashlib.sha256()

        # Hash file contents
        for filename in sorted(file_contents.keys()):
            content = file_contents[filename]
            content_hash.update(f"{filename}:{len(content)}".encode())

        # Hash findings summary
        findings_summary = f"{len(findings)}:{[f.rule for f in findings[:10]]}"
        content_hash.update(findings_summary.encode())

        return content_hash.hexdigest()[:16]

    def _cache_analysis(self, fingerprint: str, analysis: dict[str, Any]) -> None:
        """Cache analysis results."""
        if len(self.correlation_cache) >= self.max_cache_entries:
            # Remove oldest entry
            oldest_key = next(iter(self.correlation_cache))
            del self.correlation_cache[oldest_key]

        self.correlation_cache[fingerprint] = analysis

    # Helper methods for analysis
    def _is_entry_point(self, filename: str, content: str) -> bool:
        """Check if file is likely an entry point."""
        entry_patterns = [
            "main.py",
            "index.js",
            "app.py",
            "__main__.py",
            "setup.py",
            "main.go",
            "main.c",
            "main.cpp",
            "App.java",
        ]

        if any(pattern in filename for pattern in entry_patterns):
            return True

        # Check for main function or similar
        main_patterns = [
            "def main(",
            "function main(",
            "int main(",
            "if __name__ == '__main__'",
        ]
        return any(pattern in content for pattern in main_patterns)

    def _is_config_file(self, filename: str) -> bool:
        """Check if file is a configuration file."""
        config_patterns = [
            ".env",
            "config.",
            "settings.",
            ".ini",
            ".cfg",
            ".conf",
            "package.json",
            "requirements.txt",
            "Gemfile",
            "pom.xml",
        ]
        return any(pattern in filename for pattern in config_patterns)

    def _extract_dependencies(self, filename: str, content: str) -> list[str]:
        """Extract dependencies from file content."""
        deps = []

        # Python imports
        if filename.endswith(".py"):
            import re

            imports = re.findall(r"import\s+([a-zA-Z_][a-zA-Z0-9_\.]*)", content)
            from_imports = re.findall(r"from\s+([a-zA-Z_][a-zA-Z0-9_\.]*)", content)
            deps.extend(imports + from_imports)

        # JavaScript requires/imports
        elif filename.endswith((".js", ".ts")):
            import re

            requires = re.findall(r'require\(["\']([^"\']+)["\']\)', content)
            imports = re.findall(r'import.*from\s+["\']([^"\']+)["\']', content)
            deps.extend(requires + imports)

        return deps

    def _detect_suspicious_architecture_patterns(
        self, filename: str, content: str
    ) -> list[str]:
        """Detect suspicious architectural patterns."""
        patterns = []

        # Multiple credential handling
        if content.count("password") > 3 or content.count("secret") > 3:
            patterns.append(f"Multiple credential references in {filename}")

        # Extensive network activity
        if content.count("http") > 5 or content.count("socket") > 3:
            patterns.append(f"Extensive network activity in {filename}")

        # Complex obfuscation
        if content.count("base64") > 2 and content.count("decode") > 1:
            patterns.append(f"Complex encoding patterns in {filename}")

        return patterns

    def _identify_cross_file_threats(
        self, findings_by_file: dict[str, list[Finding]], file_contents: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Identify threats that span multiple files."""
        threats = []

        # Look for coordinated credential access
        cred_files = [
            f
            for f, findings in findings_by_file.items()
            if any("cred" in finding.rule for finding in findings)
        ]
        if len(cred_files) > 1:
            threats.append(
                {
                    "type": "coordinated_credential_access",
                    "files": cred_files,
                    "description": "Credential access patterns across multiple files",
                }
            )

        # Look for distributed network activity
        network_files = [
            f
            for f, findings in findings_by_file.items()
            if any(
                "network" in finding.rule or "http" in finding.rule
                for finding in findings
            )
        ]
        if len(network_files) > 1:
            threats.append(
                {
                    "type": "distributed_network_activity",
                    "files": network_files,
                    "description": "Network activity coordinated across files",
                }
            )

        return threats

    def _cluster_similar_findings(
        self, findings: list[Finding]
    ) -> dict[str, list[str]]:
        """Cluster findings by similarity."""
        clusters = {}

        for finding in findings:
            cluster_key = f"{finding.phase.value}_{finding.severity.value}"
            if cluster_key not in clusters:
                clusters[cluster_key] = []
            clusters[cluster_key].append(finding.file)

        return clusters

    def _identify_attack_chains(
        self, findings: list[Finding], file_contents: dict[str, str]
    ) -> list[dict[str, Any]]:
        """Identify potential attack chains."""
        chains = []

        # Simple heuristic: look for escalation patterns
        phases = [f.phase.value for f in findings]

        if "install_hooks" in phases and "code_patterns" in phases:
            chains.append(
                {
                    "type": "installation_to_execution",
                    "steps": ["installation", "code_execution"],
                    "risk": "high",
                }
            )

        if "credentials" in phases and "network_exfil" in phases:
            chains.append(
                {
                    "type": "credential_theft_to_exfiltration",
                    "steps": ["credential_access", "data_exfiltration"],
                    "risk": "critical",
                }
            )

        return chains

    def _calculate_complexity_score(self, file_contents: dict[str, str]) -> int:
        """Calculate a complexity score for the repository."""
        total_lines = sum(
            len(content.split("\n")) for content in file_contents.values()
        )
        num_files = len(file_contents)

        # Simple complexity heuristic
        if num_files > 20 or total_lines > 10000:
            return 10
        elif num_files > 10 or total_lines > 5000:
            return 7
        elif num_files > 5 or total_lines > 1000:
            return 5
        else:
            return 3

    def _calculate_correlation_strength(self, findings: list[Finding]) -> str:
        """Calculate the strength of correlations between findings."""
        if len(findings) > 10:
            return "high"
        elif len(findings) > 5:
            return "medium"
        else:
            return "low"

    def _detect_basic_attack_patterns(
        self, file_contents: dict[str, str], findings: list[Finding]
    ) -> list[str]:
        """Fallback method for basic attack pattern detection."""
        patterns = []

        finding_rules = [f.rule for f in findings]

        if any("eval" in rule for rule in finding_rules) and any(
            "network" in rule for rule in finding_rules
        ):
            patterns.append("Dynamic code execution with network activity")

        if any("cred" in rule for rule in finding_rules) and any(
            "obf" in rule for rule in finding_rules
        ):
            patterns.append("Credential access with obfuscation")

        return patterns

    def _count_external_dependencies(self, file_contents: dict[str, str]) -> int:
        """Count external dependencies across all files."""
        deps = set()
        for filename, content in file_contents.items():
            file_deps = self._extract_dependencies(filename, content)
            deps.update(file_deps)
        return len(deps)

    def _is_binary_filename(self, filename: str) -> bool:
        """Check if filename suggests a binary file."""
        binary_extensions = {".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".img"}
        return any(filename.endswith(ext) for ext in binary_extensions)


# Global context analyzer instance
context_analyzer = ContextAnalyzer()
