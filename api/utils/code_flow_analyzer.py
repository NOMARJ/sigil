"""
Code Flow Analyzer Utility
Analyzes data flow and execution paths through code for attack chain tracing
"""

from __future__ import annotations

import ast
import re
from typing import List, Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DataFlow:
    """Represents data flow through code"""
    source: str  # Where data originates
    sink: str    # Where data ends up
    path: List[str]  # Steps between source and sink
    tainted: bool  # Whether data is from untrusted source
    sanitized: bool  # Whether data is sanitized


@dataclass
class ExecutionPath:
    """Represents an execution path through code"""
    entry_point: str
    steps: List[str]
    conditions: List[str]  # Conditions that must be true
    reachable: bool
    complexity: int  # Cyclomatic complexity


class CodeFlowAnalyzer:
    """Analyzes code flow for security implications"""
    
    # Common entry points
    ENTRY_POINTS = {
        'python': [
            'request.', 'input(', 'sys.argv', 'os.environ',
            'flask.request', 'django.http.request', 'fastapi.Request'
        ],
        'javascript': [
            'req.body', 'req.query', 'req.params', 'process.argv',
            'process.env', 'window.location', 'document.cookie'
        ],
        'java': [
            'request.getParameter', 'System.getenv', 'args[',
            'Scanner(System.in)', 'HttpServletRequest'
        ]
    }
    
    # Dangerous sinks
    DANGEROUS_SINKS = {
        'python': [
            'eval(', 'exec(', 'os.system(', 'subprocess.',
            'pickle.loads', '__import__', 'compile(', 'open('
        ],
        'javascript': [
            'eval(', 'Function(', 'setTimeout(', 'setInterval(',
            'innerHTML', 'document.write', 'child_process.exec'
        ],
        'java': [
            'Runtime.exec', 'ProcessBuilder', 'Class.forName',
            'Statement.execute', 'ScriptEngine.eval'
        ]
    }
    
    # Sanitization functions
    SANITIZERS = {
        'python': [
            'escape(', 'quote(', 'sanitize', 'clean', 'validate',
            'parameterized', 'prepared_statement'
        ],
        'javascript': [
            'escape', 'sanitize', 'DOMPurify', 'validator',
            'encodeURIComponent', 'escapeHtml'
        ],
        'java': [
            'PreparedStatement', 'StringEscapeUtils', 'ESAPI.encoder',
            'Jsoup.clean', 'HtmlUtils.htmlEscape'
        ]
    }

    def analyze_data_flow(
        self,
        code: str,
        language: str = 'python',
        entry_point: Optional[str] = None
    ) -> List[DataFlow]:
        """
        Analyze data flow through code.
        
        Args:
            code: Source code to analyze
            language: Programming language
            entry_point: Specific entry point to trace from
            
        Returns:
            List of data flows found
        """
        flows = []
        
        # Get language-specific patterns
        entries = self.ENTRY_POINTS.get(language, [])
        sinks = self.DANGEROUS_SINKS.get(language, [])
        sanitizers = self.SANITIZERS.get(language, [])
        
        # Find all entry points
        found_entries = []
        for entry in entries:
            if entry_point and entry_point not in entry:
                continue
            if entry in code:
                # Find the variable that receives the input
                pattern = rf'(\w+)\s*=.*{re.escape(entry)}'
                matches = re.findall(pattern, code)
                for match in matches:
                    found_entries.append((match, entry))
        
        # Trace each entry point to potential sinks
        for var_name, entry in found_entries:
            # Track variable through code
            flow_path = self._trace_variable(code, var_name)
            
            # Check if it reaches any dangerous sink
            for sink in sinks:
                if sink in code:
                    # Check if our variable reaches this sink
                    sink_pattern = rf'{re.escape(sink)}.*{var_name}'
                    if re.search(sink_pattern, code):
                        # Check if sanitized
                        is_sanitized = any(san in code for san in sanitizers)
                        
                        flows.append(DataFlow(
                            source=entry,
                            sink=sink,
                            path=flow_path,
                            tainted=True,
                            sanitized=is_sanitized
                        ))
        
        return flows

    def find_execution_paths(
        self,
        code: str,
        target_function: str,
        language: str = 'python'
    ) -> List[ExecutionPath]:
        """
        Find all execution paths to a target function.
        
        Args:
            code: Source code to analyze
            target_function: Function to find paths to
            language: Programming language
            
        Returns:
            List of execution paths
        """
        paths = []
        
        if language == 'python':
            paths = self._find_python_paths(code, target_function)
        elif language == 'javascript':
            paths = self._find_javascript_paths(code, target_function)
        else:
            # Generic pattern matching
            paths = self._find_generic_paths(code, target_function)
        
        return paths

    def identify_attack_vectors(
        self,
        code: str,
        vulnerability_type: str,
        language: str = 'python'
    ) -> Dict[str, List[str]]:
        """
        Identify potential attack vectors for a vulnerability.
        
        Args:
            code: Source code context
            vulnerability_type: Type of vulnerability
            language: Programming language
            
        Returns:
            Dictionary of attack vectors and their descriptions
        """
        vectors = {}
        
        # Map vulnerability types to attack patterns
        if 'injection' in vulnerability_type.lower():
            vectors['direct_injection'] = self._find_injection_vectors(code, language)
        
        if 'exec' in vulnerability_type.lower() or 'eval' in vulnerability_type.lower():
            vectors['code_execution'] = self._find_code_exec_vectors(code, language)
        
        if 'traversal' in vulnerability_type.lower():
            vectors['path_traversal'] = self._find_traversal_vectors(code, language)
        
        if 'xxe' in vulnerability_type.lower() or 'xml' in vulnerability_type.lower():
            vectors['xml_attacks'] = self._find_xml_vectors(code, language)
        
        if 'deserial' in vulnerability_type.lower():
            vectors['deserialization'] = self._find_deserial_vectors(code, language)
        
        return vectors

    def _trace_variable(self, code: str, var_name: str) -> List[str]:
        """Trace a variable through code"""
        path = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines):
            if var_name in line:
                # Strip comments and whitespace
                clean_line = line.split('#')[0].strip()
                if clean_line:
                    path.append(f"Line {i+1}: {clean_line[:100]}")
        
        return path

    def _find_python_paths(self, code: str, target: str) -> List[ExecutionPath]:
        """Find execution paths in Python code"""
        paths = []
        
        try:
            # Parse Python AST
            tree = ast.parse(code)
            
            # Find all function definitions
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Check if this function calls our target
                    if self._calls_target(node, target):
                        path = ExecutionPath(
                            entry_point=node.name,
                            steps=self._extract_steps(node),
                            conditions=self._extract_conditions(node),
                            reachable=True,
                            complexity=self._calculate_complexity(node)
                        )
                        paths.append(path)
        except SyntaxError:
            # Fallback to pattern matching if AST fails
            pass
        
        return paths

    def _find_javascript_paths(self, code: str, target: str) -> List[ExecutionPath]:
        """Find execution paths in JavaScript code"""
        paths = []
        
        # Use regex patterns for JavaScript
        func_pattern = r'function\s+(\w+)|(\w+)\s*=\s*function|\b(\w+)\s*=\s*\([^)]*\)\s*=>'
        matches = re.finditer(func_pattern, code)
        
        for match in matches:
            func_name = match.group(1) or match.group(2) or match.group(3)
            if func_name and target in code[match.end():]:
                # Simple check if target is called after this function
                path = ExecutionPath(
                    entry_point=func_name,
                    steps=[f"Function {func_name}", f"Calls {target}"],
                    conditions=[],
                    reachable=True,
                    complexity=1
                )
                paths.append(path)
        
        return paths

    def _find_generic_paths(self, code: str, target: str) -> List[ExecutionPath]:
        """Find execution paths using generic patterns"""
        paths = []
        
        # Look for any function-like definitions
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if 'def ' in line or 'function' in line or 'func ' in line:
                # Extract function name
                match = re.search(r'(?:def|function|func)\s+(\w+)', line)
                if match:
                    func_name = match.group(1)
                    # Check if target appears later
                    remaining = '\n'.join(lines[i:])
                    if target in remaining:
                        path = ExecutionPath(
                            entry_point=func_name,
                            steps=[f"Line {i+1}: {func_name}"],
                            conditions=[],
                            reachable=True,
                            complexity=1
                        )
                        paths.append(path)
        
        return paths

    def _calls_target(self, node: ast.FunctionDef, target: str) -> bool:
        """Check if a function node calls the target"""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                if hasattr(child.func, 'id') and child.func.id == target:
                    return True
                if hasattr(child.func, 'attr') and child.func.attr == target:
                    return True
        return False

    def _extract_steps(self, node: ast.FunctionDef) -> List[str]:
        """Extract execution steps from function"""
        steps = []
        for child in node.body:
            if isinstance(child, ast.Expr):
                steps.append(ast.unparse(child)[:100] if hasattr(ast, 'unparse') else str(child))
            elif isinstance(child, ast.Assign):
                steps.append(f"Assignment: {child.targets[0]}")
            elif isinstance(child, ast.Return):
                steps.append("Return statement")
        return steps

    def _extract_conditions(self, node: ast.FunctionDef) -> List[str]:
        """Extract conditions from function"""
        conditions = []
        for child in ast.walk(node):
            if isinstance(child, ast.If):
                # Try to get condition text
                if hasattr(ast, 'unparse'):
                    conditions.append(ast.unparse(child.test)[:100])
                else:
                    conditions.append("Conditional check")
        return conditions

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity"""
        complexity = 1  # Base complexity
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
        return complexity

    def _find_injection_vectors(self, code: str, language: str) -> List[str]:
        """Find SQL/Command injection vectors"""
        vectors = []
        
        patterns = {
            'python': [
                (r'f["\'].*SELECT.*{', "SQL injection via f-string"),
                (r'%.*SELECT', "SQL injection via % formatting"),
                (r'\.format.*SELECT', "SQL injection via .format()"),
                (r'os\.system.*\+', "Command injection via os.system"),
                (r'subprocess.*shell=True', "Command injection via subprocess")
            ],
            'javascript': [
                (r'query.*\+.*req\.', "SQL injection via concatenation"),
                (r'exec.*\+.*req\.', "Command injection via exec"),
                (r'innerHTML.*=.*req\.', "XSS via innerHTML")
            ]
        }
        
        lang_patterns = patterns.get(language, [])
        for pattern, description in lang_patterns:
            if re.search(pattern, code, re.IGNORECASE):
                vectors.append(description)
        
        return vectors

    def _find_code_exec_vectors(self, code: str, language: str) -> List[str]:
        """Find code execution vectors"""
        vectors = []
        
        if language == 'python':
            if 'eval(' in code:
                vectors.append("Direct eval() execution")
            if 'exec(' in code:
                vectors.append("Direct exec() execution")
            if '__import__' in code:
                vectors.append("Dynamic import execution")
            if 'compile(' in code:
                vectors.append("Code compilation and execution")
        
        elif language == 'javascript':
            if 'eval(' in code:
                vectors.append("JavaScript eval() execution")
            if 'Function(' in code:
                vectors.append("Function constructor execution")
            if 'setTimeout(' in code and '+' in code:
                vectors.append("Dynamic setTimeout execution")
        
        return vectors

    def _find_traversal_vectors(self, code: str, language: str) -> List[str]:
        """Find path traversal vectors"""
        vectors = []
        
        if '../' in code or '..\\' in code:
            vectors.append("Direct path traversal attempt")
        
        if 'os.path.join' in code and 'os.path.normpath' not in code:
            vectors.append("Unsafe path joining without normalization")
        
        if 'open(' in code or 'File(' in code:
            vectors.append("File access with user input")
        
        return vectors

    def _find_xml_vectors(self, code: str, language: str) -> List[str]:
        """Find XML attack vectors"""
        vectors = []
        
        if 'XMLParser' in code or 'etree' in code:
            if 'resolve_entities' not in code:
                vectors.append("XXE via entity resolution")
        
        if 'parseXML' in code or 'DOMParser' in code:
            vectors.append("XML parsing without validation")
        
        return vectors

    def _find_deserial_vectors(self, code: str, language: str) -> List[str]:
        """Find deserialization vectors"""
        vectors = []
        
        if language == 'python':
            if 'pickle.loads' in code:
                vectors.append("Unsafe pickle deserialization")
            if 'yaml.load(' in code and 'SafeLoader' not in code:
                vectors.append("Unsafe YAML deserialization")
            if 'eval(' in code and 'json' in code:
                vectors.append("Eval-based JSON parsing")
        
        elif language == 'javascript':
            if 'JSON.parse' in code and 'eval' in code:
                vectors.append("Unsafe JSON parsing")
            if 'unserialize' in code:
                vectors.append("PHP-style unserialization")
        
        return vectors


# Global analyzer instance
code_flow_analyzer = CodeFlowAnalyzer()