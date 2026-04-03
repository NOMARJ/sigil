---
name: owasp-scan
description: Comprehensive OWASP Top 10 vulnerability scanning for Enclave AI. Performs automated security analysis across injection, authentication, access control, cryptographic failures, and logging/monitoring gaps. Integrates with Sigil scanner and provides air-gap compatible security validation with automated remediation guidance.
---

# OWASP Security Scan Command

Performs comprehensive OWASP Top 10 vulnerability scanning across the Enclave AI platform with automated remediation guidance and compliance mapping.

## Usage

```bash
# Full OWASP scan across all categories
/owasp-scan

# Scan specific OWASP category
/owasp-scan --category injection
/owasp-scan --category authentication
/owasp-scan --category access-control
/owasp-scan --category crypto
/owasp-scan --category logging

# Scan specific service or directory
/owasp-scan --path services/mock-manager
/owasp-scan --service terminal-client

# Air-gap compatible scan (no external dependencies)
/owasp-scan --offline

# Generate compliance report
/owasp-scan --compliance SOC2
/owasp-scan --compliance GDPR

# Severity filtering
/owasp-scan --min-severity high
/owasp-scan --severity-filter critical,high

# Output formats
/owasp-scan --format json
/owasp-scan --format sarif
/owasp-scan --format executive-summary
```

## Implementation

This command orchestrates the specialized OWASP security agents to provide comprehensive vulnerability assessment:

### 1. Pre-Scan Validation

```bash
# Verify Sigil scanner is available and up-to-date
sigil version --check-updates

# Validate air-gap security requirements
echo "Checking air-gap compliance..."
if ! ping -c 1 8.8.8.8 &> /dev/null; then
  echo "✅ Air-gap environment confirmed"
else
  echo "⚠️  WARNING: Internet connectivity detected - air-gap may be compromised"
fi

# Check for critical security tools
command -v npm audit || echo "❌ npm audit not available"
command -v bandit || echo "⚠️  bandit (Python security) not installed"
command -v semgrep || echo "⚠️  semgrep (multi-language) not installed"
```

### 2. OWASP Category Scanning

#### A01: Broken Access Control
```bash
echo "🔒 Scanning for Access Control vulnerabilities (OWASP A01)..."

# Use the OWASP Access Control specialist agent
claude --agent owasp-access-control-specialist << 'EOF'
Perform comprehensive access control audit of the Enclave AI platform:

1. Scan for missing authorization middleware on endpoints
2. Check for insecure direct object references (IDOR)
3. Validate workspace isolation boundaries
4. Test for privilege escalation vulnerabilities
5. Review IAM policy configurations
6. Check administrative endpoint protection

Focus on these critical issues:
- Missing authentication on administrative endpoints
- Cross-workspace data access vulnerabilities  
- Role-based access control bypass
- Privilege escalation via parameter manipulation

Generate findings with:
- OWASP A01 reference
- CWE mapping
- Severity scoring (0-50+ scale)
- Automated remediation guidance
- Air-gap compatible fixes
EOF
```

#### A02: Cryptographic Failures
```bash
echo "🔐 Scanning for Cryptographic vulnerabilities (OWASP A02)..."

claude --agent owasp-crypto-specialist << 'EOF'
Perform comprehensive cryptographic security audit:

1. Validate KMS encryption implementation
2. Check for secrets exposure in error messages
3. Audit TLS/SSL configurations  
4. Review password hashing algorithms
5. Test random number generation security
6. Verify certificate management

Critical focus areas:
- Secrets exposure in error messages (services/terminal-client, security-verifier)
- Weak cryptographic algorithms (MD5, SHA1, DES)
- Insecure random number generation
- Missing encryption at rest/transit

Generate findings with cryptographic remediation specific to AWS KMS and air-gap requirements.
EOF
```

#### A03: Injection
```bash
echo "💉 Scanning for Injection vulnerabilities (OWASP A03)..."

claude --agent owasp-injection-specialist << 'EOF'
Perform comprehensive injection vulnerability audit:

1. Scan for SQL injection via string concatenation
2. Check for command injection in shell execution
3. Test for NoSQL injection in DynamoDB queries
4. Review XSS prevention in React components
5. Validate input sanitization across services
6. Check for code injection via eval/Function

Critical issues to address:
- CORS wildcard configuration (services/mock-manager/src/index.ts:56)
- Command injection via shell execution (security-verifier/src/utils/exec.ts)
- XSS via unsanitized LLM responses (terminal-client/src/components/ChatInterface.tsx:188)

Generate specific remediation for TypeScript/Node.js patterns and container isolation.
EOF
```

#### A07: Identification and Authentication Failures
```bash
echo "🔑 Scanning for Authentication vulnerabilities (OWASP A07)..."

claude --agent owasp-auth-specialist << 'EOF'
Perform comprehensive authentication security audit:

1. Check for missing authentication on endpoints
2. Validate JWT implementation security
3. Review session management practices
4. Test for authentication bypass vulnerabilities
5. Audit password policies and storage
6. Check multi-factor authentication implementation

Critical focus:
- Missing authentication on administrative endpoints
- Weak session management
- Insecure password storage
- JWT token security issues

Generate remediation with OAuth2/OIDC integration and air-gap session management.
EOF
```

#### A09: Security Logging and Monitoring Failures
```bash
echo "📊 Scanning for Logging/Monitoring gaps (OWASP A09)..."

claude --agent owasp-data-specialist << 'EOF'
Perform comprehensive security logging and monitoring audit:

1. Validate audit logging coverage for critical actions
2. Check for security event detection capabilities
3. Review log integrity and tamper protection
4. Test incident response alerting
5. Audit compliance logging (SOC2, GDPR, HIPAA)
6. Verify monitoring effectiveness

Focus areas:
- Missing audit logging on administrative actions
- Insufficient authentication failure monitoring
- Log tampering vulnerabilities
- Poor security event correlation
- Compliance logging gaps

Generate monitoring implementation compatible with CloudWatch and air-gap requirements.
EOF
```

### 3. Sigil Integration

```bash
echo "🛡️  Running Sigil supply-chain security scan..."

# Run comprehensive Sigil scan
if command -v sigil &> /dev/null; then
  sigil scan . --format json --output sigil-results.json
  
  # Parse Sigil results for OWASP mapping
  node << 'EOF'
const fs = require('fs');

if (fs.existsSync('sigil-results.json')) {
  const results = JSON.parse(fs.readFileSync('sigil-results.json', 'utf8'));
  
  console.log('📈 Sigil Risk Score:', results.risk_score || 'N/A');
  console.log('📊 Total Findings:', results.findings?.length || 0);
  
  if (results.risk_score >= 50) {
    console.log('🚨 CRITICAL: Sigil risk score above threshold');
    process.exit(1);
  }
}
EOF
else
  echo "⚠️  Sigil scanner not available - skipping supply chain analysis"
fi
```

### 4. Air-Gap Security Validation

```bash
echo "🔒 Validating air-gap security requirements..."

# Check for external dependencies
echo "Checking for external network calls..."
grep -r "http://\|https://\|ftp://" --include="*.ts" --include="*.js" services/ | \
  grep -v "localhost\|127.0.0.1\|enclave.internal" | \
  head -10

# Validate VPC isolation
echo "Validating VPC configuration..."
if [ -f "infrastructure/vpc/main.tf" ]; then
  grep -q "internet_gateway" infrastructure/vpc/main.tf && \
    echo "⚠️  Internet gateway found in VPC config" || \
    echo "✅ No internet gateway - air-gap maintained"
fi

# Check container isolation
echo "Validating container security..."
grep -r "privileged.*true\|--privileged" --include="*.yml" --include="*.yaml" . || \
  echo "✅ No privileged containers found"
```

### 5. Automated Remediation Generation

```bash
echo "🛠️  Generating automated remediation guidance..."

cat << 'EOF' > owasp-remediation-plan.md
# OWASP Security Remediation Plan

## Executive Summary
- **Critical Findings**: ${CRITICAL_COUNT}
- **High Priority**: ${HIGH_COUNT}  
- **Overall Risk Score**: ${RISK_SCORE}/50

## Immediate Actions Required

### Critical Issues (Fix within 24 hours)
1. **Missing Authentication** - Add JWT middleware to administrative endpoints
2. **Command Injection** - Replace shell execution with parameterized commands
3. **Secrets Exposure** - Implement secure error handling

### High Priority (Fix within 1 week)
1. **CORS Configuration** - Replace wildcard with specific origins
2. **XSS Prevention** - Add content sanitization
3. **Audit Logging** - Implement comprehensive security event logging

## Remediation Commands

```bash
# Fix CORS wildcard (Critical)
npm run security:fix:cors-wildcard

# Secure shell execution (Critical)  
npm run security:fix:command-injection

# Implement audit logging (High)
npm run security:fix:audit-logging

# Add authentication middleware (Critical)
npm run security:fix:missing-auth
```

## Verification
After implementing fixes, run:
```bash
/owasp-scan --verify-fixes
```
EOF
```

### 6. Compliance Reporting

```bash
echo "📋 Generating compliance reports..."

# SOC2 Type II mapping
if [ "$COMPLIANCE" == "SOC2" ]; then
cat << 'EOF' > soc2-compliance-report.json
{
  "framework": "SOC2 Type II",
  "assessment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "controls": {
    "CC6.1": {
      "description": "Logical and physical access controls",
      "status": "needs_attention",
      "findings": ["Missing authentication on admin endpoints"],
      "evidence": ["OWASP A07 scan results"]
    },
    "CC6.2": {
      "description": "Transmission and disposal of information",
      "status": "effective",
      "findings": [],
      "evidence": ["KMS encryption validation", "TLS configuration audit"]
    }
  }
}
EOF
fi

# GDPR compliance mapping
if [ "$COMPLIANCE" == "GDPR" ]; then
cat << 'EOF' > gdpr-compliance-report.json
{
  "framework": "GDPR",
  "assessment_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "articles": {
    "Article 32": {
      "description": "Security of processing",
      "compliance_status": "partial",
      "gaps": ["Insufficient audit logging", "Missing access controls"],
      "remediation": ["Implement comprehensive security event logging"]
    }
  }
}
EOF
fi
```

### 7. Executive Summary Generation

```bash
echo "📊 Generating executive summary..."

cat << 'EOF' > owasp-executive-summary.md
# OWASP Security Assessment - Executive Summary

## Risk Overview
- **Overall Security Posture**: ${SECURITY_POSTURE}
- **Critical Vulnerabilities**: ${CRITICAL_COUNT}
- **Compliance Gap**: ${COMPLIANCE_GAP}%

## Key Findings
1. **Access Control Gaps**: Missing authorization on ${UNAUTH_ENDPOINTS} endpoints
2. **Injection Vulnerabilities**: ${INJECTION_COUNT} potential injection points identified
3. **Cryptographic Issues**: ${CRYPTO_ISSUES} encryption/certificate problems
4. **Monitoring Gaps**: Insufficient logging on ${LOGGING_GAPS} critical actions

## Business Impact
- **Data Breach Risk**: High due to access control gaps
- **Compliance Risk**: Medium - SOC2/GDPR requirements partially met
- **Operational Risk**: Low - no service availability impacts

## Recommended Actions
1. Immediate remediation of critical authentication gaps
2. Implementation of comprehensive audit logging
3. Deployment of automated security monitoring
4. Regular OWASP security assessments

## Air-Gap Security Validation
✅ Network isolation maintained  
✅ No external dependencies in security controls  
✅ Container isolation verified  
EOF
```

## Integration with Existing Security Tools

### NOMARK Protocol Integration
```bash
# Follow NOMARK discipline
echo "📖 Reading security lessons learned..."
[ -f "tasks/lessons.md" ] && grep -E "Security:|Auth:|Access:|Crypto:" tasks/lessons.md | tail -10

echo "✍️  Updating lessons learned..."
echo "[$(date '+%Y-%m-%d')] Security: OWASP scan completed → Rule: Run comprehensive scan before each release" >> tasks/lessons.md

echo "📈 Updating progress log..."
echo "## $(date '+%Y-%m-%d') - OWASP Security Scan Completed" >> progress.md
echo "- **Critical Findings**: ${CRITICAL_COUNT}" >> progress.md
echo "- **High Priority**: ${HIGH_COUNT}" >> progress.md
echo "- **Overall Risk Score**: ${RISK_SCORE}/50" >> progress.md
```

### Test Integration
```bash
# Run security tests after scan
echo "🧪 Running security validation tests..."

npm run test:security:injection
npm run test:security:authentication  
npm run test:security:access-control
npm run test:security:cryptographic
npm run test:security:monitoring

# Air-gap compatible security verification
enclave security verify --comprehensive
```

## Output Formats

### JSON Output
```json
{
  "scan_id": "owasp-scan-20240308-143022",
  "timestamp": "2024-03-08T14:30:22Z",
  "framework": "OWASP Top 10 2021",
  "overall_risk_score": 32,
  "categories": {
    "A01_broken_access_control": {
      "risk_score": 45,
      "findings_count": 8,
      "critical_issues": 3
    },
    "A02_cryptographic_failures": {
      "risk_score": 28,
      "findings_count": 5,
      "critical_issues": 1
    },
    "A03_injection": {
      "risk_score": 35,
      "findings_count": 6,
      "critical_issues": 2
    }
  },
  "recommendations": [
    "Implement JWT authentication middleware",
    "Add input validation framework",
    "Enable comprehensive audit logging"
  ]
}
```

### SARIF Output  
```json
{
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Enclave OWASP Scanner",
        "version": "1.0.0"
      }
    },
    "results": [{
      "ruleId": "OWASP-A01-001",
      "message": {
        "text": "Missing authentication on administrative endpoint"
      },
      "level": "error",
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {
            "uri": "services/mock-manager/src/index.ts"
          },
          "region": {
            "startLine": 80
          }
        }
      }]
    }]
  }]
}
```

This command provides comprehensive OWASP Top 10 scanning tailored for the Enclave AI platform's air-gap environment, with automated remediation guidance and compliance integration.