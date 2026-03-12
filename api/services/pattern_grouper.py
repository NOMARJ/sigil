"""
Pattern Grouper Service
Groups security findings by similar patterns for bulk analysis
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional
from collections import defaultdict

from ..models import Finding

logger = logging.getLogger(__name__)


class PatternGrouper:
    """Groups findings by similar patterns"""

    # Pattern types for grouping
    PATTERN_TYPES = {
        "SQL_INJECTION": {
            "rules": ["SQL_INJECTION", "SQLI", "DATABASE_INJECTION"],
            "indicators": ["SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "UNION"],
            "group_name": "SQL Injection Vulnerabilities"
        },
        "XSS": {
            "rules": ["XSS_REFLECTED", "XSS_STORED", "XSS_DOM", "CROSS_SITE_SCRIPTING"],
            "indicators": ["<script>", "onerror", "onclick", "javascript:", "alert("],
            "group_name": "Cross-Site Scripting (XSS)"
        },
        "COMMAND_INJECTION": {
            "rules": ["COMMAND_INJECTION", "OS_COMMAND", "SHELL_INJECTION"],
            "indicators": ["exec(", "system(", "eval(", "shell_exec", "subprocess"],
            "group_name": "Command Injection"
        },
        "PATH_TRAVERSAL": {
            "rules": ["PATH_TRAVERSAL", "DIRECTORY_TRAVERSAL", "FILE_INCLUSION"],
            "indicators": ["../", "..\\", "%2e%2e", "file://"],
            "group_name": "Path Traversal"
        },
        "HARDCODED_SECRET": {
            "rules": ["HARDCODED_SECRET", "API_KEY", "PASSWORD_PLAINTEXT", "CREDENTIAL"],
            "indicators": ["api_key", "secret", "password", "token", "bearer"],
            "group_name": "Hardcoded Secrets"
        },
        "INSTALL_HOOK": {
            "rules": ["INSTALL_HOOK_NPM", "INSTALL_HOOK_PIP", "SETUP_HOOK"],
            "indicators": ["postinstall", "preinstall", "setup.py", "cmdclass"],
            "group_name": "Installation Hooks"
        },
        "DESERIALIZATION": {
            "rules": ["DESERIALIZATION", "PICKLE", "YAML_LOAD", "UNSAFE_UNMARSHAL"],
            "indicators": ["pickle.loads", "yaml.load", "eval(", "unmarshal"],
            "group_name": "Unsafe Deserialization"
        },
        "WEAK_CRYPTO": {
            "rules": ["WEAK_CRYPTO", "WEAK_HASH", "INSECURE_RANDOM", "MD5", "SHA1"],
            "indicators": ["md5", "sha1", "Math.random", "DES", "RC4"],
            "group_name": "Weak Cryptography"
        },
        "MISSING_AUTH": {
            "rules": ["MISSING_AUTH", "NO_AUTHENTICATION", "BYPASS_AUTH"],
            "indicators": ["no auth", "missing authentication", "bypass"],
            "group_name": "Missing Authentication"
        },
        "NETWORK_EXFIL": {
            "rules": ["NETWORK_EXFIL", "DATA_EXFILTRATION", "WEBHOOK", "DNS_TUNNEL"],
            "indicators": ["fetch", "requests.post", "webhook", "dns"],
            "group_name": "Network Exfiltration"
        }
    }

    def group_findings(
        self,
        findings: List[Finding]
    ) -> Dict[str, Dict[str, any]]:
        """
        Group findings by pattern type.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary of pattern groups with findings and metadata
        """
        groups = defaultdict(lambda: {
            "findings": [],
            "pattern_type": None,
            "group_name": None,
            "count": 0,
            "files": set(),
            "severity_distribution": defaultdict(int),
            "common_characteristics": {},
            "root_cause_similarity": 0.0
        })
        
        # Classify each finding
        for finding in findings:
            pattern_type = self._classify_pattern(finding)
            
            if pattern_type:
                group = groups[pattern_type]
                group["findings"].append(finding)
                group["pattern_type"] = pattern_type
                group["group_name"] = self.PATTERN_TYPES[pattern_type]["group_name"]
                group["count"] += 1
                group["files"].add(finding.file_path)
                group["severity_distribution"][finding.severity] += 1
        
        # Analyze each group for common characteristics
        for pattern_type, group in groups.items():
            if group["count"] > 0:
                group["files"] = list(group["files"])  # Convert set to list
                group["common_characteristics"] = self._analyze_common_characteristics(
                    group["findings"]
                )
                group["root_cause_similarity"] = self._calculate_root_cause_similarity(
                    group["findings"]
                )
                
                # Determine if likely same root cause
                group["likely_same_root_cause"] = (
                    group["root_cause_similarity"] > 0.7 and
                    len(group["common_characteristics"].get("common_patterns", [])) > 0
                )
        
        # Convert defaultdict to regular dict
        return dict(groups)

    def _classify_pattern(self, finding: Finding) -> Optional[str]:
        """Classify finding into a pattern type"""
        rule_upper = finding.rule.upper()
        evidence_lower = finding.evidence.lower() if finding.evidence else ""
        description_lower = finding.description.lower()
        
        for pattern_type, config in self.PATTERN_TYPES.items():
            # Check rule match
            for rule in config["rules"]:
                if rule in rule_upper:
                    return pattern_type
            
            # Check indicators in evidence/description
            for indicator in config["indicators"]:
                if (indicator.lower() in evidence_lower or 
                    indicator.lower() in description_lower):
                    return pattern_type
        
        # Default classification by phase
        phase_patterns = {
            "install_hooks": "INSTALL_HOOK",
            "code_patterns": "COMMAND_INJECTION",
            "network": "NETWORK_EXFIL",
            "credentials": "HARDCODED_SECRET",
            "obfuscation": "DESERIALIZATION"
        }
        
        return phase_patterns.get(finding.phase)

    def _analyze_common_characteristics(
        self,
        findings: List[Finding]
    ) -> Dict[str, any]:
        """Analyze common characteristics across findings"""
        characteristics = {
            "common_patterns": [],
            "common_functions": [],
            "common_variables": [],
            "file_proximity": False,
            "code_similarity": 0.0
        }
        
        if len(findings) < 2:
            return characteristics
        
        # Extract patterns from evidence
        all_evidence = [f.evidence for f in findings if f.evidence]
        
        # Find common code patterns
        if all_evidence:
            # Extract function names
            func_pattern = r'\b(\w+)\s*\('
            all_functions = []
            for evidence in all_evidence:
                functions = re.findall(func_pattern, evidence)
                all_functions.extend(functions)
            
            # Find common functions
            func_counts = defaultdict(int)
            for func in all_functions:
                func_counts[func] += 1
            
            characteristics["common_functions"] = [
                func for func, count in func_counts.items()
                if count >= len(findings) * 0.5  # Present in 50%+ of findings
            ]
            
            # Extract variable names
            var_pattern = r'\$(\w+)|\b([a-z_]\w*)\s*='
            all_variables = []
            for evidence in all_evidence:
                matches = re.findall(var_pattern, evidence)
                variables = [m[0] or m[1] for m in matches if m[0] or m[1]]
                all_variables.extend(variables)
            
            # Find common variables
            var_counts = defaultdict(int)
            for var in all_variables:
                var_counts[var] += 1
            
            characteristics["common_variables"] = [
                var for var, count in var_counts.items()
                if count >= len(findings) * 0.5
            ]
            
            # Calculate code similarity
            characteristics["code_similarity"] = self._calculate_code_similarity(
                all_evidence
            )
        
        # Check file proximity
        files = [f.file_path for f in findings]
        characteristics["file_proximity"] = self._check_file_proximity(files)
        
        # Find common patterns in descriptions
        common_words = self._find_common_words(
            [f.description for f in findings]
        )
        characteristics["common_patterns"] = common_words
        
        return characteristics

    def _calculate_root_cause_similarity(
        self,
        findings: List[Finding]
    ) -> float:
        """Calculate likelihood of same root cause"""
        if len(findings) < 2:
            return 0.0
        
        similarity_score = 0.0
        comparisons = 0
        
        # Compare pairs of findings
        for i in range(len(findings)):
            for j in range(i + 1, len(findings)):
                f1, f2 = findings[i], findings[j]
                
                # Same file = high similarity
                if f1.file_path == f2.file_path:
                    similarity_score += 0.3
                
                # Close line numbers = high similarity
                if abs(f1.line_number - f2.line_number) < 50:
                    similarity_score += 0.2
                
                # Same severity = moderate similarity
                if f1.severity == f2.severity:
                    similarity_score += 0.1
                
                # Similar evidence = high similarity
                if f1.evidence and f2.evidence:
                    evidence_sim = self._string_similarity(
                        f1.evidence, f2.evidence
                    )
                    similarity_score += evidence_sim * 0.4
                
                comparisons += 1
        
        # Average similarity across all comparisons
        if comparisons > 0:
            similarity_score = similarity_score / comparisons
        
        return min(1.0, similarity_score)

    def _calculate_code_similarity(self, code_samples: List[str]) -> float:
        """Calculate similarity between code samples"""
        if len(code_samples) < 2:
            return 0.0
        
        # Use simple token-based similarity
        total_similarity = 0.0
        comparisons = 0
        
        for i in range(len(code_samples)):
            for j in range(i + 1, len(code_samples)):
                sim = self._string_similarity(code_samples[i], code_samples[j])
                total_similarity += sim
                comparisons += 1
        
        if comparisons > 0:
            return total_similarity / comparisons
        
        return 0.0

    def _string_similarity(self, s1: str, s2: str) -> float:
        """Calculate similarity between two strings"""
        # Simple token-based Jaccard similarity
        tokens1 = set(re.findall(r'\w+', s1.lower()))
        tokens2 = set(re.findall(r'\w+', s2.lower()))
        
        if not tokens1 or not tokens2:
            return 0.0
        
        intersection = tokens1 & tokens2
        union = tokens1 | tokens2
        
        return len(intersection) / len(union) if union else 0.0

    def _check_file_proximity(self, files: List[str]) -> bool:
        """Check if files are in proximity (same directory or module)"""
        if len(files) < 2:
            return False
        
        # Extract directories
        directories = set()
        for file in files:
            parts = file.split('/')
            if len(parts) > 1:
                directory = '/'.join(parts[:-1])
                directories.add(directory)
        
        # If all in same or adjacent directories
        return len(directories) <= 2

    def _find_common_words(
        self,
        texts: List[str],
        min_length: int = 4
    ) -> List[str]:
        """Find common significant words across texts"""
        # Skip common words
        stop_words = {
            'the', 'and', 'for', 'with', 'from', 'this', 
            'that', 'have', 'been', 'were', 'are', 'was'
        }
        
        word_counts = defaultdict(int)
        
        for text in texts:
            words = set(re.findall(r'\w+', text.lower()))
            for word in words:
                if len(word) >= min_length and word not in stop_words:
                    word_counts[word] += 1
        
        # Words appearing in 50%+ of texts
        threshold = len(texts) * 0.5
        common_words = [
            word for word, count in word_counts.items()
            if count >= threshold
        ]
        
        return common_words

    def suggest_single_fix(
        self,
        pattern_group: Dict[str, any]
    ) -> Optional[Dict[str, str]]:
        """
        Suggest a single fix for multiple similar issues.
        
        Args:
            pattern_group: Group of similar findings
            
        Returns:
            Fix suggestion if applicable
        """
        if not pattern_group.get("likely_same_root_cause"):
            return None
        
        pattern_type = pattern_group["pattern_type"]
        findings = pattern_group["findings"]
        
        # Pattern-specific fix suggestions
        fix_templates = {
            "SQL_INJECTION": {
                "title": "Use Parameterized Queries",
                "description": "Replace all string concatenation with parameterized queries",
                "example": "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
            },
            "XSS": {
                "title": "Implement Output Encoding",
                "description": "Apply context-appropriate encoding to all user inputs",
                "example": "html.escape(user_input) or use template auto-escaping"
            },
            "HARDCODED_SECRET": {
                "title": "Use Environment Variables",
                "description": "Move all secrets to environment variables or secret manager",
                "example": "api_key = os.environ.get('API_KEY')"
            },
            "WEAK_CRYPTO": {
                "title": "Upgrade Cryptographic Functions",
                "description": "Replace weak algorithms with secure alternatives",
                "example": "Use SHA-256 or SHA-3 instead of MD5/SHA-1"
            },
            "PATH_TRAVERSAL": {
                "title": "Implement Path Validation",
                "description": "Validate and sanitize all file paths",
                "example": "safe_path = os.path.normpath(os.path.join(base_dir, user_path))"
            }
        }
        
        fix_template = fix_templates.get(pattern_type)
        
        if not fix_template:
            return None
        
        # Customize based on common characteristics
        common_funcs = pattern_group["common_characteristics"].get("common_functions", [])
        common_vars = pattern_group["common_characteristics"].get("common_variables", [])
        
        suggestion = {
            "title": fix_template["title"],
            "description": fix_template["description"],
            "example": fix_template["example"],
            "scope": f"Affects {len(findings)} instances across {len(pattern_group['files'])} files",
            "confidence": pattern_group["root_cause_similarity"],
            "affected_functions": common_funcs,
            "affected_variables": common_vars,
            "estimated_effort": self._estimate_fix_effort(pattern_group)
        }
        
        return suggestion

    def _estimate_fix_effort(self, pattern_group: Dict) -> str:
        """Estimate effort to fix all instances"""
        count = pattern_group["count"]
        files = len(pattern_group["files"])
        
        if count <= 3 and files == 1:
            return "Low (< 1 hour)"
        elif count <= 10 and files <= 3:
            return "Medium (1-4 hours)"
        elif count <= 20 and files <= 5:
            return "High (4-8 hours)"
        else:
            return "Very High (1+ days)"


# Global grouper instance
pattern_grouper = PatternGrouper()