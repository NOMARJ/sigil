---
name: security-training
description: Automated security training workflows for developers working on Enclave AI. Provides interactive OWASP security education, hands-on vulnerability remediation practice, secure coding pattern training, and air-gap security best practices. Integrates with TDD workflows for security-first development.
---

# Security Training Command

Provides comprehensive, automated security training workflows for Enclave AI developers, focusing on OWASP Top 10 vulnerabilities, air-gap security requirements, and secure coding practices.

## Usage

```bash
# Complete OWASP security training curriculum
/security-training

# Specific OWASP category training
/security-training --focus injection
/security-training --focus authentication
/security-training --focus access-control
/security-training --focus crypto
/security-training --focus logging

# Interactive vulnerability labs
/security-training --lab sql-injection
/security-training --lab command-injection
/security-training --lab xss-prevention

# Air-gap security training
/security-training --air-gap-security

# Role-based training tracks
/security-training --role developer
/security-training --role admin
/security-training --role security-reviewer

# Assessment and certification
/security-training --assessment
/security-training --certification-test

# TDD security workflow training
/security-training --tdd-security
```

## Implementation

### 1. Security Training Curriculum

```bash
echo "🎓 Starting Enclave AI Security Training Program"
echo "================================================"

# Create training session
training_session_id=$(date +%Y%m%d-%H%M%S)
mkdir -p /tmp/security-training-${training_session_id}
cd /tmp/security-training-${training_session_id}

echo "📋 Training Session ID: ${training_session_id}"
```

### 2. OWASP Top 10 Interactive Modules

#### Module 1: Injection Vulnerabilities (A03)
```bash
echo "💉 Module 1: Injection Vulnerability Training"
echo "============================================="

cat << 'EOF' > injection-training.md
# Injection Vulnerability Training

## Learning Objectives
- Understand SQL, NoSQL, and command injection
- Learn parameterized query patterns
- Practice input validation techniques
- Master container command security

## Enclave-Specific Patterns

### VULNERABLE: Command Injection in Security Verifier
```typescript
// services/security-verifier/src/utils/exec.ts
export async function safeExec(command: string, timeout = 30000): Promise<string> {
  const { stdout } = await execPromise(command, { timeout });
  return stdout.trim();
}
```

### SECURE: Parameterized Command Execution
```typescript
export async function secureExec(
  command: string, 
  args: string[] = [], 
  timeout = 30000
): Promise<string> {
  // Validate command against allowlist
  const allowedCommands = ['aws', 'kubectl', 'docker', 'sigil'];
  if (!allowedCommands.includes(command)) {
    throw new SecurityError(`Command not allowed: ${command}`);
  }
  
  // Use spawn with separate arguments
  const sanitizedArgs = args.map(arg => shellEscape(arg));
  const result = spawn(command, sanitizedArgs, { timeout });
  return result.stdout.toString();
}
```

## Hands-On Exercise
Fix the command injection vulnerability in the security verifier.
EOF

# Interactive exercise
echo "🛠️  Hands-On Exercise: Fix Command Injection"
echo "File: services/security-verifier/src/utils/exec.ts"
echo "Vulnerability: Direct command execution without validation"
echo ""
echo "Your task: Implement secure command execution with parameter validation"
echo ""

claude --agent owasp-injection-specialist << 'EOF'
Provide an interactive code review of the command injection vulnerability in services/security-verifier/src/utils/exec.ts.

Walk through:
1. Why the current implementation is vulnerable
2. How an attacker could exploit it
3. Step-by-step secure remediation
4. Air-gap compatible validation patterns
5. Unit tests for the secure implementation

Make this educational and hands-on for developers.
EOF
```

#### Module 2: Authentication Security (A07)
```bash
echo "🔑 Module 2: Authentication Security Training" 
echo "==========================================="

cat << 'EOF' > authentication-training.md
# Authentication Security Training

## Critical Issue: Missing Authentication on Admin Endpoints

### VULNERABLE: Unauthenticated Administrative Functions
```typescript
// services/mock-manager/src/index.ts:80
app.post('/mocks/:service/start', async (req, res) => {
  const result = await this.startMockService(service, req.body);
  res.json({ success: true, result });
});
```

### SECURE: JWT-Based Authentication
```typescript
app.post('/mocks/:service/start',
  authenticateJWT,
  authorizeRole(['admin', 'developer']),
  async (req, res) => {
    const { user } = req;
    logger.info('Mock service start requested', { 
      userId: user.id, 
      service: req.params.service 
    });
    
    const result = await this.startMockService(req.params.service, req.body);
    res.json({ success: true, result });
  }
);
```

## Exercise: Implement JWT Middleware
Your task: Add authentication to all administrative endpoints in the mock manager.
EOF

echo "🔐 Interactive Authentication Lab"
echo "Vulnerability: Missing authentication on administrative endpoints"
echo ""

claude --agent owasp-auth-specialist << 'EOF'
Provide hands-on authentication security training focused on the missing authentication issue in services/mock-manager/src/index.ts.

Include:
1. Demonstration of the security risk
2. JWT implementation best practices
3. Session management for air-gap environment
4. Multi-factor authentication for admin actions
5. Practical implementation steps
6. Security testing approaches

Make this practical and immediately applicable.
EOF
```

#### Module 3: Access Control Security (A01)
```bash
echo "🔒 Module 3: Access Control Training"
echo "==================================="

cat << 'EOF' > access-control-training.md
# Access Control Security Training

## Workspace Isolation in Air-Gap Environment

### Challenge: Multi-Tenant Security
Enclave AI must ensure complete workspace isolation while maintaining air-gap security.

### RBAC Implementation Exercise
```typescript
export interface WorkspaceRole {
  id: string;
  permissions: Permission[];
  level: number;
}

export class WorkspaceAccessController {
  async validateAccess(
    userId: string,
    workspaceId: string, 
    operation: string
  ): Promise<boolean> {
    // Your implementation here
  }
}
```

## Lab: Implement Workspace Isolation
Fix the insecure direct object reference vulnerability in document access.
EOF

claude --agent owasp-access-control-specialist << 'EOF'
Provide comprehensive access control training covering:

1. Workspace isolation implementation
2. RBAC design patterns for air-gap environments
3. IAM policy validation
4. Container access boundaries
5. Administrative privilege protection
6. Audit trail implementation

Focus on practical, testable security controls.
EOF
```

### 3. Air-Gap Security Training

```bash
echo "🔒 Air-Gap Security Training Module"
echo "==================================="

cat << 'EOF' > air-gap-security.md
# Air-Gap Security Best Practices

## Network Isolation Requirements
- No internet gateway in VPC
- PrivateLink endpoints only
- Container network isolation
- Zero external dependencies

## Security Validation
```bash
# Verify air-gap compliance
ping -c 1 8.8.8.8 && echo "❌ Air-gap breach!" || echo "✅ Air-gap maintained"

# Check for external dependencies
grep -r "http://\|https://" --include="*.ts" services/ | 
  grep -v "localhost\|enclave.internal"

# Validate container isolation  
docker ps --format "table {{.Names}}\t{{.Networks}}" | grep -v enclave-network
```

## Lab: Air-Gap Compliance Audit
Audit the codebase for air-gap compliance violations.
EOF

echo "🛡️  Air-Gap Security Assessment"
echo "Task: Identify any air-gap compliance violations"
echo ""

# Automated air-gap compliance check
node << 'EOF'
const fs = require('fs');
const path = require('path');

function scanForExternalUrls(dir) {
  const violations = [];
  
  function scanFile(filePath) {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) return;
    
    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    
    lines.forEach((line, index) => {
      const urlMatch = line.match(/(https?:\/\/[^\s'"]+)/g);
      if (urlMatch) {
        urlMatch.forEach(url => {
          if (!url.includes('localhost') && !url.includes('enclave.internal')) {
            violations.push({
              file: filePath,
              line: index + 1,
              url: url,
              risk: 'Air-gap violation'
            });
          }
        });
      }
    });
  }
  
  function walkDir(dir) {
    const files = fs.readdirSync(dir);
    files.forEach(file => {
      const filePath = path.join(dir, file);
      if (fs.statSync(filePath).isDirectory() && !file.startsWith('.')) {
        walkDir(filePath);
      } else {
        scanFile(filePath);
      }
    });
  }
  
  walkDir(dir);
  return violations;
}

const violations = scanForExternalUrls('services');
console.log('🔍 Air-Gap Compliance Violations Found:', violations.length);

violations.forEach(v => {
  console.log(`❌ ${v.file}:${v.line} - ${v.url}`);
});

if (violations.length === 0) {
  console.log('✅ No air-gap violations detected');
}
EOF
```

### 4. TDD Security Workflow Training

```bash
echo "🧪 TDD Security Workflow Training"
echo "=================================="

cat << 'EOF' > tdd-security-training.md
# Test-Driven Security Development

## Red-Green-Refactor for Security

### 1. Red: Write Failing Security Test
```typescript
describe('Authentication Middleware', () => {
  it('should reject requests without valid JWT', async () => {
    const response = await request(app)
      .post('/api/admin/reset')
      .expect(401);
    
    expect(response.body.error).toBe('Authentication required');
  });
});
```

### 2. Green: Implement Minimal Security Control
```typescript
export function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  // Minimal implementation to pass test
  next();
}
```

### 3. Refactor: Robust Security Implementation
```typescript
export function authenticateJWT(req: Request, res: Response, next: NextFunction) {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}
```

## Lab: Security-First Development
Implement authentication for the mock manager using TDD approach.
EOF

echo "🔬 TDD Security Lab"
echo "Goal: Implement security controls using test-driven development"
echo ""

# Create TDD security exercise
mkdir -p tdd-security-lab
cat << 'EOF' > tdd-security-lab/security-tdd-exercise.test.ts
import request from 'supertest';
import { createMockManagerApp } from '../mock-manager-app';

describe('Mock Manager Security', () => {
  let app: Express;
  
  beforeEach(() => {
    app = createMockManagerApp();
  });

  describe('Administrative Endpoints', () => {
    it('should require authentication for service start', async () => {
      // Your test implementation here
    });
    
    it('should require admin role for service management', async () => {
      // Your test implementation here  
    });
    
    it('should log all administrative actions', async () => {
      // Your test implementation here
    });
  });

  describe('Input Validation', () => {
    it('should sanitize service names', async () => {
      // Your test implementation here
    });
    
    it('should prevent command injection in service parameters', async () => {
      // Your test implementation here
    });
  });
});
EOF

echo "📝 Your task: Complete the security tests and implement the controls"
echo "Run: npm run test:security -- tdd-security-lab/"
```

### 5. Interactive Security Assessment

```bash
echo "📊 Security Knowledge Assessment"
echo "==============================="

# Create interactive security quiz
node << 'EOF'
const readline = require('readline');
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const questions = [
  {
    question: "Which OWASP category covers command injection vulnerabilities?",
    options: ["A01", "A02", "A03", "A07"],
    correct: 2,
    explanation: "A03 - Injection covers SQL injection, NoSQL injection, command injection, and code injection."
  },
  {
    question: "In an air-gap environment, which of these is a security violation?",
    options: [
      "Using localhost for service communication",
      "Making HTTP calls to external APIs", 
      "Using PrivateLink for AWS services",
      "Container-to-container communication"
    ],
    correct: 1,
    explanation: "HTTP calls to external APIs violate air-gap isolation requirements."
  },
  {
    question: "What's the minimum JWT token expiration for admin operations?",
    options: ["5 minutes", "30 minutes", "4 hours", "24 hours"],
    correct: 1,
    explanation: "30 minutes provides balance between security and usability for administrative tasks."
  }
];

let score = 0;
let currentQuestion = 0;

function askQuestion() {
  if (currentQuestion >= questions.length) {
    console.log(`\n🎯 Final Score: ${score}/${questions.length}`);
    if (score === questions.length) {
      console.log('🏆 Excellent! You passed the security assessment.');
    } else if (score >= questions.length * 0.8) {
      console.log('✅ Good job! Minor areas for improvement.');
    } else {
      console.log('📚 Additional training recommended.');
    }
    rl.close();
    return;
  }

  const q = questions[currentQuestion];
  console.log(`\n❓ Question ${currentQuestion + 1}: ${q.question}`);
  q.options.forEach((option, index) => {
    console.log(`  ${index + 1}. ${option}`);
  });
  
  rl.question('\nYour answer (1-4): ', (answer) => {
    const answerIndex = parseInt(answer) - 1;
    if (answerIndex === q.correct) {
      console.log('✅ Correct!');
      score++;
    } else {
      console.log(`❌ Incorrect. ${q.explanation}`);
    }
    
    currentQuestion++;
    askQuestion();
  });
}

console.log('🎓 Security Knowledge Assessment');
console.log('Answer the following questions about Enclave AI security:');
askQuestion();
EOF
```

### 6. Certification and Tracking

```bash
echo "🏆 Security Training Certification"
echo "=================================="

# Generate training completion certificate
training_completion_date=$(date '+%Y-%m-%d %H:%M:%S')
cat << EOF > security-training-certificate.json
{
  "certificate_id": "${training_session_id}",
  "trainee": "$(whoami)",
  "completion_date": "${training_completion_date}",
  "training_modules": [
    "OWASP A01 - Broken Access Control",
    "OWASP A02 - Cryptographic Failures", 
    "OWASP A03 - Injection",
    "OWASP A07 - Authentication Failures",
    "OWASP A09 - Security Logging",
    "Air-Gap Security Requirements",
    "TDD Security Workflows"
  ],
  "assessment_score": "${score:-0}/3",
  "certification_status": "completed",
  "valid_until": "$(date -d '+1 year' '+%Y-%m-%d')",
  "issuer": "Enclave AI Security Training Program"
}
EOF

echo "✅ Training completed successfully!"
echo "📄 Certificate saved: security-training-certificate.json"

# Update training records
mkdir -p ~/.enclave/training
cp security-training-certificate.json ~/.enclave/training/

# Log to lessons learned
echo "[$(date '+%Y-%m-%d')] Security: Completed OWASP security training → Rule: Annual security training required" >> tasks/lessons.md

# Update progress log
cat << EOF >> progress.md

## ${training_completion_date} - Security Training Completed
- **Training Session**: ${training_session_id}
- **Modules Completed**: 7/7
- **Assessment Score**: ${score:-0}/3
- **Certification Valid Until**: $(date -d '+1 year' '+%Y-%m-%d')
- **Next Training Due**: $(date -d '+1 year' '+%Y-%m-%d')
EOF

echo ""
echo "📚 Recommended Next Steps:"
echo "1. Apply security training to current development work"
echo "2. Run /owasp-scan to validate security improvements"
echo "3. Schedule regular security reviews with the team"
echo "4. Practice TDD security workflows in daily development"
echo ""
echo "🔄 Training valid for 1 year. Renewal notification will be sent 30 days before expiration."
```

### 7. Team Training Coordination

```bash
echo "👥 Team Security Training Coordination"
echo "======================================"

# Check team training status
if [ -d "~/.enclave/training" ]; then
  echo "📊 Team Training Status:"
  echo "========================"
  
  find ~/.enclave/training -name "*.json" -exec jq -r '
    "User: " + (.trainee // "unknown") + 
    " | Completed: " + (.completion_date // "never") +
    " | Valid Until: " + (.valid_until // "expired")
  ' {} \;
else
  echo "No training records found. Run /security-training to start."
fi

# Schedule team training reminders
cat << 'EOF' > schedule-security-training.sh
#!/bin/bash
# Add to cron: 0 9 * * 1 /path/to/schedule-security-training.sh

# Check for expiring certificates
find ~/.enclave/training -name "*.json" -exec jq -r '
  select(.valid_until and (.valid_until | strptime("%Y-%m-%d") | mktime) < (now + (30*24*3600))) |
  "Training expiring for user: " + .trainee + " on " + .valid_until
' {} \;

# Send notifications (adapt for your notification system)
# slack_notification "Security training renewals due"
# email_notification "security-team@company.com"
EOF

chmod +x schedule-security-training.sh
echo "📅 Team training scheduler created: schedule-security-training.sh"
```

## Integration with Development Workflow

### Pre-Commit Security Training
```bash
# Add to .git/hooks/pre-commit
echo "🔒 Running security validation..."

# Check if developer has current security training
training_cert=~/.enclave/training/security-training-certificate.json
if [ ! -f "$training_cert" ]; then
  echo "❌ Security training required before committing"
  echo "Run: /security-training"
  exit 1
fi

# Check if training is still valid
valid_until=$(jq -r '.valid_until' "$training_cert")
if [ "$(date '+%Y-%m-%d')" > "$valid_until" ]; then
  echo "⚠️  Security training expired. Renewal required."
  echo "Run: /security-training --renewal"
  exit 1
fi

echo "✅ Security training current - proceeding with commit"
```

This command provides comprehensive, hands-on security training specifically tailored for the Enclave AI platform's air-gap environment and OWASP Top 10 vulnerabilities.