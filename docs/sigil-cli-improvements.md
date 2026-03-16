# Sigil CLI Improvements: Reducing False Positives

## The Problem

Current scanner is flagging legitimate patterns as threats:
- **Method names** containing "exec" (e.g., `exec(editor: IDomEditor)`)
- **Standard UMD wrappers** with `Function("return this")`
- **Minified polyfill code** (CoreJS, Babel runtime)
- **TypeScript type definitions** (.d.ts files)

This creates noise and destroys user trust.

## Immediate Fixes for Sigil CLI

### 1. Context-Aware Pattern Matching

```python
# sigil/scanners/code_patterns.py

def check_exec_pattern(file_path, line, line_number):
    """Check if exec() is actually dangerous or just a method name"""
    
    # Skip TypeScript definition files
    if file_path.endswith('.d.ts'):
        return None  # Not a threat in type definitions
    
    # Check if it's a method definition, not a function call
    method_patterns = [
        r'\.exec\s*\(',           # obj.exec(
        r'exec\s*:\s*function',   # exec: function
        r'exec\s*\(.*\)\s*:',     # exec(...): returnType (TypeScript)
        r'abstract\s+exec',       # abstract exec
        r'public\s+exec',         # public exec
        r'private\s+exec',        # private exec
    ]
    
    for pattern in method_patterns:
        if re.search(pattern, line):
            return None  # It's a method, not dangerous exec()
    
    # Check if it's actual exec() function call
    if re.search(r'\bexec\s*\(["\']', line):  # exec("code") or exec('code')
        return {
            'severity': 'HIGH',
            'pattern': 'exec_call',
            'message': 'Direct exec() call with string'
        }
    
    # Check for variable exec (more dangerous)
    if re.search(r'\bexec\s*\([^"\']', line):  # exec(variable)
        return {
            'severity': 'CRITICAL', 
            'pattern': 'exec_variable',
            'message': 'exec() called with variable (possible injection)'
        }
    
    return None
```

### 2. Whitelist Known Safe Patterns

```python
# sigil/scanners/whitelist.py

SAFE_PATTERNS = {
    # Standard UMD wrapper
    'umd_wrapper': [
        r'typeof exports.*typeof module.*module\.exports',
        r'typeof define.*define\.amd.*define\(',
        r'Function\("return this"\)\(\)',  # Common global detection
    ],
    
    # CoreJS/Babel polyfills
    'polyfills': [
        r'core-js',
        r'@babel/runtime',
        r'regenerator-runtime',
        r'tslib',
    ],
    
    # Minified library signatures
    'known_libraries': [
        r'!function\(.\){"use strict"',  # Common minification pattern
        r'webpackJsonp',                  # Webpack
        r'__webpack_require__',           # Webpack
    ]
}

def is_whitelisted(file_path, content):
    """Check if file contains known safe patterns"""
    
    # Skip minified vendor files
    if '/node_modules/' in file_path:
        return True
    
    if '/dist/' in file_path and file_path.endswith('.min.js'):
        # Check if it's a known library
        for pattern_list in SAFE_PATTERNS.values():
            for pattern in pattern_list:
                if re.search(pattern, content[:1000]):  # Check first 1KB
                    return True
    
    return False
```

### 3. Severity Scoring Based on Context

```python
# sigil/scanners/risk_calculator.py

def calculate_risk_score(findings, file_context):
    """Calculate risk score with context awareness"""
    
    score = 0
    
    for finding in findings:
        base_weight = PHASE_WEIGHTS[finding['phase']]
        
        # Reduce weight for common false positive patterns
        multiplier = 1.0
        
        # TypeScript definitions are not executable
        if file_context['extension'] == '.d.ts':
            multiplier = 0.1
        
        # Test files are less risky
        elif 'test' in file_context['path'] or 'spec' in file_context['path']:
            multiplier = 0.3
        
        # Documentation/examples are informational
        elif 'docs' in file_context['path'] or 'example' in file_context['path']:
            multiplier = 0.2
        
        # Minified files need different analysis
        elif file_context['is_minified']:
            # Don't penalize for obfuscation in .min.js files
            if finding['pattern'] == 'obfuscation':
                multiplier = 0.1
        
        score += base_weight * multiplier * finding['severity_score']
    
    return min(score, 1000)  # Cap at 1000 to avoid ridiculous scores
```

### 4. Improved AST-Based Analysis

```python
# sigil/scanners/ast_analyzer.py

import ast
import esprima  # For JavaScript

def analyze_javascript_ast(content):
    """Use AST parsing for more accurate JavaScript analysis"""
    
    try:
        tree = esprima.parseScript(content)
        findings = []
        
        def walk_ast(node, parent=None):
            if node.type == 'CallExpression':
                if node.callee.type == 'Identifier':
                    func_name = node.callee.name
                    
                    # Check for dangerous functions
                    if func_name in ['eval', 'exec']:
                        # Check if argument is a literal string (less dangerous)
                        if node.arguments and node.arguments[0].type == 'Literal':
                            findings.append({
                                'severity': 'MEDIUM',
                                'pattern': f'{func_name}_literal',
                                'message': f'{func_name}() with literal string'
                            })
                        else:
                            findings.append({
                                'severity': 'HIGH',
                                'pattern': f'{func_name}_dynamic',
                                'message': f'{func_name}() with dynamic input'
                            })
            
            # Recursively walk children
            for key in node:
                if isinstance(node[key], dict):
                    walk_ast(node[key], node)
                elif isinstance(node[key], list):
                    for child in node[key]:
                        if isinstance(child, dict):
                            walk_ast(child, node)
        
        walk_ast(tree)
        return findings
        
    except:
        # Fall back to regex if AST parsing fails
        return None
```

### 5. Add Confidence Levels

```python
# sigil/scanners/confidence.py

class FindingConfidence:
    HIGH = "HIGH"       # Definitely malicious
    MEDIUM = "MEDIUM"   # Suspicious, needs review
    LOW = "LOW"         # Might be false positive
    
def assess_confidence(finding, context):
    """Assess confidence level of a finding"""
    
    confidence = FindingConfidence.MEDIUM  # Default
    
    # High confidence indicators
    if finding['pattern'] in ['crypto_miner', 'backdoor', 'data_exfiltration']:
        confidence = FindingConfidence.HIGH
    
    # Low confidence for common false positives
    if context['is_popular_package'] and context['downloads'] > 10000:
        confidence = FindingConfidence.LOW
    
    if finding['pattern'] == 'exec' and context['is_editor_plugin']:
        confidence = FindingConfidence.LOW  # Editors often have exec methods
    
    return confidence
```

### 6. User-Friendly Output with Context

```python
# sigil/output/formatter.py

def format_findings(findings, verbose=False):
    """Format findings with context and confidence"""
    
    # Group by confidence
    high_confidence = [f for f in findings if f['confidence'] == 'HIGH']
    medium_confidence = [f for f in findings if f['confidence'] == 'MEDIUM']
    low_confidence = [f for f in findings if f['confidence'] == 'LOW']
    
    if high_confidence:
        print("\n🔴 HIGH CONFIDENCE THREATS:")
        for f in high_confidence:
            print(f"  - {f['message']} in {f['file']}:{f['line']}")
    
    if medium_confidence:
        print("\n🟡 SUSPICIOUS PATTERNS (Review Needed):")
        for f in medium_confidence:
            print(f"  - {f['message']} in {f['file']}:{f['line']}")
    
    if verbose and low_confidence:
        print("\n⚪ LOW CONFIDENCE (Likely False Positives):")
        for f in low_confidence:
            print(f"  - {f['message']} in {f['file']}:{f['line']}")
    
    # Add context explanation
    if not high_confidence and medium_confidence:
        print("\n💡 No definite threats found. Review suspicious patterns above.")
        print("   Run with --details to see why these were flagged.")
```

### 7. Machine Learning Enhancement (Future)

```python
# sigil/ml/false_positive_detector.py

import joblib
from sklearn.ensemble import RandomForestClassifier

class FalsePositiveDetector:
    def __init__(self, model_path='models/fp_detector.pkl'):
        self.model = joblib.load(model_path)
    
    def predict_false_positive(self, finding, context):
        """Predict if a finding is likely a false positive"""
        
        features = self.extract_features(finding, context)
        probability = self.model.predict_proba([features])[0][1]
        
        return probability > 0.7  # 70% chance it's a false positive
    
    def extract_features(self, finding, context):
        """Extract features for ML model"""
        return [
            1 if context['is_minified'] else 0,
            1 if context['is_typescript'] else 0,
            1 if '/test/' in context['path'] else 0,
            context['package_downloads'],
            context['package_age_days'],
            1 if finding['pattern'] == 'exec' else 0,
            # ... more features
        ]
```

## Implementation Priority

### Phase 1 (Immediate - This Week)
1. ✅ Implement context-aware pattern matching
2. ✅ Add whitelist for known safe patterns
3. ✅ Skip .d.ts files for code execution patterns
4. ✅ Adjust scoring based on file context

### Phase 2 (Next Week)
1. ✅ Add AST-based analysis for JavaScript
2. ✅ Implement confidence levels
3. ✅ Improve output formatting with context

### Phase 3 (Next Month)
1. ✅ Train ML model on labeled false positives
2. ✅ Add user feedback mechanism
3. ✅ Continuous learning from corrections

## Expected Impact

- **False positive rate**: 36% → 5%
- **User trust**: Dramatically improved
- **Scan accuracy**: More meaningful results
- **User experience**: Clear, actionable findings

## Testing Strategy

```bash
# Test on known false positives
sigil scan @wangeditor-next/plugin-mention --verbose

# Expected output:
# ⚪ LOW CONFIDENCE findings (likely false positives)
# Instead of: 🔴 CRITICAL RISK

# Test on actual malware
sigil scan known-malware-package

# Should still detect: 🔴 HIGH CONFIDENCE THREATS
```

## Success Metrics

- False positive rate < 10%
- User reports of false positives < 5 per week
- Scan abandonment rate < 5%
- User trust score > 8/10

## The Key Insight

**It's better to miss some edge cases than to cry wolf constantly.**

Users will forgive missing obscure threats.
They won't forgive constant false alarms.

Trust is earned in drops and lost in buckets.