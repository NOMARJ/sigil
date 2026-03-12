"""
Context Expander Service
Dynamically expands analysis context by including additional files and dependencies
"""

from __future__ import annotations

import logging
import json
from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from pathlib import Path

from api.database import db
from api.services.credit_service import credit_service
from api.services.llm_service import llm_service
from api.models import Finding, Severity
from api.llm_models import LLMAnalysisRequest, LLMAnalysisType

logger = logging.getLogger(__name__)


@dataclass
class ContextExpansion:
    """Represents an expansion of analysis context"""
    original_files: List[str]
    expanded_files: List[str]
    dependencies_added: List[str]
    context_size_kb: float
    credit_cost: int
    findings_before: List[Finding]
    findings_after: List[Finding]
    assessment_changes: List[Dict[str, Any]]
    confidence_improvement: float


class ContextExpander:
    """Expands analysis context for more accurate security assessment"""

    # File patterns that indicate dependencies
    DEPENDENCY_FILES = {
        'python': ['requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
        'javascript': ['package.json', 'package-lock.json', 'yarn.lock'],
        'java': ['pom.xml', 'build.gradle', 'build.gradle.kts'],
        'ruby': ['Gemfile', 'Gemfile.lock'],
        'go': ['go.mod', 'go.sum'],
        'rust': ['Cargo.toml', 'Cargo.lock'],
        'php': ['composer.json', 'composer.lock'],
        'csharp': ['*.csproj', 'packages.config'],
    }

    # Config files that affect security
    SECURITY_CONFIGS = [
        '.env', '.env.local', '.env.production',
        'config.json', 'config.yaml', 'config.yml',
        'settings.py', 'settings.json',
        'application.properties', 'application.yml',
        'docker-compose.yml', 'Dockerfile',
        '.github/workflows/*.yml', '.gitlab-ci.yml',
        'terraform/*.tf', 'cloudformation/*.json'
    ]

    async def expand_context(
        self,
        initial_findings: List[Finding],
        scan_path: str,
        user_id: str,
        expansion_type: str = "smart",
        specific_files: Optional[List[str]] = None,
        session_id: Optional[str] = None
    ) -> ContextExpansion:
        """
        Expand analysis context to improve finding accuracy.
        
        Args:
            initial_findings: Original findings with limited context
            scan_path: Root path of scanned code
            user_id: User requesting expansion
            expansion_type: "smart", "dependencies", "configs", or "custom"
            specific_files: Specific files to add (for custom expansion)
            session_id: Optional session ID for tracking
            
        Returns:
            ContextExpansion with before/after comparison
        """
        # Determine credit cost based on expansion type
        credit_costs = {
            "smart": 4,      # Intelligent selection
            "dependencies": 3,  # Just dependency files
            "configs": 2,    # Just config files
            "custom": 2      # User-specified files
        }
        credit_cost = credit_costs.get(expansion_type, 4)
        
        # Check and deduct credits
        if not await credit_service.has_credits(user_id, credit_cost):
            raise ValueError(f"Insufficient credits. Need {credit_cost} credits for context expansion.")
        
        await credit_service.deduct_credits(
            user_id=user_id,
            amount=credit_cost,
            transaction_type="context_expansion",
            session_id=session_id,
            metadata={"expansion_type": expansion_type}
        )
        
        try:
            # Get original context files
            original_files = self._extract_files_from_findings(initial_findings)
            
            # Determine which files to add
            if expansion_type == "custom" and specific_files:
                files_to_add = specific_files
            else:
                files_to_add = await self._determine_files_to_expand(
                    scan_path, 
                    original_files,
                    expansion_type
                )
            
            # Load the additional files
            expanded_context = await self._load_expanded_files(
                scan_path,
                files_to_add
            )
            
            # Re-analyze with expanded context
            findings_after = await self._reanalyze_with_context(
                initial_findings,
                expanded_context,
                user_id
            )
            
            # Compare assessments
            assessment_changes = self._compare_assessments(
                initial_findings,
                findings_after
            )
            
            # Calculate confidence improvement
            confidence_improvement = self._calculate_confidence_improvement(
                initial_findings,
                findings_after
            )
            
            # Track dependencies found
            dependencies = self._extract_dependencies(expanded_context)
            
            # Calculate context size
            context_size = sum(len(content) for content in expanded_context.values()) / 1024
            
            expansion = ContextExpansion(
                original_files=original_files,
                expanded_files=list(expanded_context.keys()),
                dependencies_added=dependencies,
                context_size_kb=round(context_size, 2),
                credit_cost=credit_cost,
                findings_before=initial_findings,
                findings_after=findings_after,
                assessment_changes=assessment_changes,
                confidence_improvement=confidence_improvement
            )
            
            # Store in session if provided
            if session_id:
                await self._store_expansion(session_id, expansion)
            
            logger.info(
                f"Context expanded: {len(original_files)} → {len(expansion.expanded_files)} files, "
                f"confidence improved by {confidence_improvement:.1%}"
            )
            
            return expansion
            
        except Exception as e:
            logger.exception(f"Context expansion failed: {e}")
            raise

    def _extract_files_from_findings(self, findings: List[Finding]) -> List[str]:
        """Extract unique files referenced in findings"""
        files = set()
        for finding in findings:
            if finding.file:
                files.add(finding.file)
        return list(files)

    async def _determine_files_to_expand(
        self,
        scan_path: str,
        original_files: List[str],
        expansion_type: str
    ) -> List[str]:
        """Determine which files to add based on expansion type"""
        files_to_add = []
        scan_root = Path(scan_path)
        
        if expansion_type in ["smart", "dependencies"]:
            # Add dependency files
            for lang_deps in self.DEPENDENCY_FILES.values():
                for dep_pattern in lang_deps:
                    if '*' in dep_pattern:
                        # Handle wildcards
                        for file in scan_root.glob(dep_pattern):
                            if file.is_file() and str(file) not in original_files:
                                files_to_add.append(str(file.relative_to(scan_root)))
                    else:
                        dep_file = scan_root / dep_pattern
                        if dep_file.exists() and str(dep_file) not in original_files:
                            files_to_add.append(dep_pattern)
        
        if expansion_type in ["smart", "configs"]:
            # Add security-relevant config files
            for config_pattern in self.SECURITY_CONFIGS:
                if '*' in config_pattern:
                    # Handle wildcards
                    for file in scan_root.glob(config_pattern):
                        if file.is_file() and str(file) not in original_files:
                            files_to_add.append(str(file.relative_to(scan_root)))
                else:
                    config_file = scan_root / config_pattern
                    if config_file.exists() and str(config_file) not in original_files:
                        files_to_add.append(config_pattern)
        
        if expansion_type == "smart":
            # Add files that are imported/required by original files
            imports = await self._find_imported_files(scan_path, original_files)
            files_to_add.extend(imports)
        
        # Limit to reasonable number of files
        return files_to_add[:20]  # Max 20 additional files

    async def _find_imported_files(
        self,
        scan_path: str,
        original_files: List[str]
    ) -> List[str]:
        """Find files imported by the original files"""
        imported = set()
        scan_root = Path(scan_path)
        
        for file_path in original_files:
            full_path = scan_root / file_path
            if not full_path.exists():
                continue
            
            try:
                content = full_path.read_text(errors='ignore')
                
                # Python imports
                if file_path.endswith('.py'):
                    import re
                    # Find import statements
                    imports = re.findall(r'from\s+(\S+)\s+import|import\s+(\S+)', content)
                    for imp in imports:
                        module = imp[0] or imp[1]
                        if '.' in module:
                            # Convert module to file path
                            potential_file = module.replace('.', '/') + '.py'
                            if (scan_root / potential_file).exists():
                                imported.add(potential_file)
                
                # JavaScript/TypeScript imports
                elif file_path.endswith(('.js', '.ts', '.jsx', '.tsx')):
                    import re
                    # Find import/require statements
                    imports = re.findall(r'from\s+["\']([^"\']+)["\']|require\(["\']([^"\']+)["\']\)', content)
                    for imp in imports:
                        import_path = imp[0] or imp[1]
                        if import_path.startswith('.'):
                            # Relative import
                            base_dir = Path(file_path).parent
                            potential_file = base_dir / import_path
                            # Try with different extensions
                            for ext in ['.js', '.ts', '.jsx', '.tsx', '/index.js', '/index.ts']:
                                check_file = scan_root / f"{potential_file}{ext}"
                                if check_file.exists():
                                    imported.add(str(check_file.relative_to(scan_root)))
                                    break
                    
            except Exception as e:
                logger.warning(f"Failed to analyze imports in {file_path}: {e}")
        
        return list(imported)

    async def _load_expanded_files(
        self,
        scan_path: str,
        files: List[str]
    ) -> Dict[str, str]:
        """Load content of expanded files"""
        expanded_context = {}
        scan_root = Path(scan_path)
        
        for file_path in files:
            full_path = scan_root / file_path
            if full_path.exists() and full_path.is_file():
                try:
                    # Limit file size to prevent memory issues
                    if full_path.stat().st_size < 500_000:  # 500KB limit
                        content = full_path.read_text(errors='ignore')
                        expanded_context[file_path] = content[:50000]  # Limit to 50K chars
                except Exception as e:
                    logger.warning(f"Failed to read {file_path}: {e}")
        
        return expanded_context

    async def _reanalyze_with_context(
        self,
        original_findings: List[Finding],
        expanded_context: Dict[str, str],
        user_id: str
    ) -> List[Finding]:
        """Re-analyze findings with expanded context"""
        
        # Build enhanced analysis request
        static_findings = [
            {
                "phase": f.phase.value if f.phase else "unknown",
                "rule": f.rule,
                "severity": f.severity.value,
                "file": f.file,
                "line": f.line,
                "snippet": f.snippet,
                "description": f.description,
            }
            for f in original_findings
        ]
        
        analysis_request = LLMAnalysisRequest(
            file_contents=expanded_context,
            static_findings=static_findings,
            repository_context={"expanded_context": True},
            analysis_types=[
                LLMAnalysisType.CONTEXTUAL_CORRELATION,
                LLMAnalysisType.BEHAVIORAL_PATTERN
            ],
            max_insights=10,
            include_context_analysis=True
        )
        
        # Use Haiku for context expansion (cheaper)
        analysis_request.model_override = "claude-3-haiku-20240307"
        
        # Perform re-analysis
        response = await llm_service.analyze_threat(analysis_request)
        
        # Update original findings based on new insights
        updated_findings = []
        for finding in original_findings:
            updated = self._update_finding_with_context(finding, response)
            updated_findings.append(updated)
        
        # Add any new findings discovered with context
        for insight in response.insights:
            if self._is_new_finding(insight, original_findings):
                new_finding = self._insight_to_finding(insight)
                updated_findings.append(new_finding)
        
        return updated_findings

    def _update_finding_with_context(self, finding: Finding, response: Any) -> Finding:
        """Update finding based on new context insights"""
        # Look for insights that relate to this finding
        for insight in response.insights:
            if (insight.affected_files and finding.file in insight.affected_files and
                self._rules_match(finding.rule, insight.title)):
                
                # Update confidence/severity based on context
                if insight.false_positive_likelihood > 0.7:
                    # High likelihood of false positive with context
                    finding.severity = Severity.LOW
                    finding.description = f"[LIKELY FALSE POSITIVE] {finding.description}"
                elif insight.confidence > 0.8:
                    # High confidence threat with context
                    if finding.severity == Severity.MEDIUM:
                        finding.severity = Severity.HIGH
                    finding.description = f"[CONFIRMED WITH CONTEXT] {finding.description}"
                
                # Add context information
                if insight.reasoning:
                    finding.explanation = f"{finding.explanation or ''} | Context: {insight.reasoning}"
        
        return finding

    def _rules_match(self, rule1: str, rule2: str) -> bool:
        """Check if two rules refer to same issue"""
        rule1_lower = rule1.lower()
        rule2_lower = rule2.lower()
        
        # Check for common keywords
        common_keywords = ['injection', 'xss', 'eval', 'exec', 'traversal', 'deserial']
        for keyword in common_keywords:
            if keyword in rule1_lower and keyword in rule2_lower:
                return True
        
        # Check for exact match
        return rule1_lower == rule2_lower

    def _is_new_finding(self, insight: Any, original_findings: List[Finding]) -> bool:
        """Check if insight represents a new finding"""
        for finding in original_findings:
            if (insight.affected_files and finding.file in insight.affected_files and
                self._rules_match(finding.rule, insight.title)):
                return False
        return True

    def _insight_to_finding(self, insight: Any) -> Finding:
        """Convert LLM insight to Finding"""
        from api.models import ScanPhase
        
        # severity_map = {
        #     'critical': Severity.CRITICAL,
        #     'high': Severity.HIGH,
        #     'medium': Severity.MEDIUM,
        #     'low': Severity.LOW
        # }
        
        # Determine severity from threat category
        severity = Severity.MEDIUM
        if hasattr(insight, 'threat_category'):
            category = insight.threat_category.value.lower()
            if 'critical' in category or 'backdoor' in category:
                severity = Severity.CRITICAL
            elif 'high' in category or 'injection' in category:
                severity = Severity.HIGH
        
        return Finding(
            phase=ScanPhase.LLM_ANALYSIS,
            rule=f"context-{insight.analysis_type.value}",
            severity=severity,
            file=insight.affected_files[0] if insight.affected_files else "unknown",
            line=0,
            snippet=insight.evidence_snippets[0] if insight.evidence_snippets else "",
            weight=insight.confidence * 5,
            description=insight.description,
            explanation=insight.reasoning
        )

    def _compare_assessments(
        self,
        before: List[Finding],
        after: List[Finding]
    ) -> List[Dict[str, Any]]:
        """Compare findings before and after context expansion"""
        changes = []
        
        # Create maps for comparison
        before_map = {f"{f.file}:{f.rule}": f for f in before}
        after_map = {f"{f.file}:{f.rule}": f for f in after}
        
        # Check for severity changes
        for key in set(before_map.keys()) & set(after_map.keys()):
            if before_map[key].severity != after_map[key].severity:
                changes.append({
                    "type": "severity_change",
                    "file": before_map[key].file,
                    "rule": before_map[key].rule,
                    "before": before_map[key].severity.value,
                    "after": after_map[key].severity.value,
                    "reason": "Context provided additional evidence"
                })
        
        # Check for new findings
        for key in set(after_map.keys()) - set(before_map.keys()):
            changes.append({
                "type": "new_finding",
                "file": after_map[key].file,
                "rule": after_map[key].rule,
                "severity": after_map[key].severity.value,
                "reason": "Discovered with expanded context"
            })
        
        # Check for removed findings (false positives)
        for key in set(before_map.keys()) - set(after_map.keys()):
            changes.append({
                "type": "false_positive",
                "file": before_map[key].file,
                "rule": before_map[key].rule,
                "reason": "Identified as false positive with context"
            })
        
        return changes

    def _calculate_confidence_improvement(
        self,
        before: List[Finding],
        after: List[Finding]
    ) -> float:
        """Calculate confidence improvement from context expansion"""
        # Simple heuristic: reduction in false positives and increase in confirmed threats
        
        before_count = len(before)
        after_count = len(after)
        
        # Count likely false positives
        false_positives_before = sum(1 for f in before if 'false' in f.description.lower())
        false_positives_after = sum(1 for f in after if 'false' in f.description.lower())
        
        # Count confirmed threats
        confirmed_after = sum(1 for f in after if 'confirmed' in f.description.lower())
        
        if before_count == 0:
            return 0.0
        
        # Calculate improvement
        false_positive_reduction = (false_positives_before - false_positives_after) / before_count
        confirmation_rate = confirmed_after / after_count if after_count > 0 else 0
        
        improvement = (false_positive_reduction + confirmation_rate) / 2
        return max(0.0, min(1.0, improvement))  # Clamp to 0-1

    def _extract_dependencies(self, expanded_context: Dict[str, str]) -> List[str]:
        """Extract dependency names from expanded files"""
        dependencies = []
        
        for file_path, content in expanded_context.items():
            if 'package.json' in file_path:
                try:
                    data = json.loads(content)
                    dependencies.extend(data.get('dependencies', {}).keys())
                    dependencies.extend(data.get('devDependencies', {}).keys())
                except Exception:
                    pass
            
            elif 'requirements.txt' in file_path:
                for line in content.split('\n'):
                    if line and not line.startswith('#'):
                        dep = line.split('==')[0].split('>=')[0].split('<=')[0].strip()
                        if dep:
                            dependencies.append(dep)
            
            elif 'pom.xml' in file_path:
                import re
                # Simple regex for Maven dependencies
                deps = re.findall(r'<artifactId>([^<]+)</artifactId>', content)
                dependencies.extend(deps)
        
        return list(set(dependencies))[:50]  # Limit to 50 dependencies

    async def _store_expansion(
        self,
        session_id: str,
        expansion: ContextExpansion
    ) -> None:
        """Store context expansion in session"""
        try:
            expansion_data = {
                "type": "context_expansion",
                "original_files": expansion.original_files,
                "expanded_files": expansion.expanded_files,
                "dependencies": expansion.dependencies_added,
                "context_size_kb": expansion.context_size_kb,
                "credit_cost": expansion.credit_cost,
                "confidence_improvement": expansion.confidence_improvement,
                "assessment_changes": expansion.assessment_changes
            }
            
            await db.execute(
                """
                UPDATE interactive_sessions
                SET conversation_history = JSON_MODIFY(
                    ISNULL(conversation_history, '[]'),
                    'append $',
                    :expansion
                ),
                last_activity = GETDATE()
                WHERE session_id = :session_id
                """,
                {
                    "session_id": session_id,
                    "expansion": json.dumps(expansion_data)
                }
            )
        except Exception as e:
            logger.warning(f"Failed to store context expansion: {e}")


# Global service instance
context_expander = ContextExpander()