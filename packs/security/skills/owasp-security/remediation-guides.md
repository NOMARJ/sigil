# OWASP Security Remediation Guides for Enclave AI

## Overview

Step-by-step security vulnerability remediation guides specifically tailored for the Enclave AI platform's air-gap environment and OWASP Top 10 compliance requirements.

## Critical Issues Remediation

### 1. CORS Wildcard Configuration (OWASP A05 - Security Misconfiguration)

#### Issue Description
**File**: `services/mock-manager/src/index.ts:56`
**Risk Level**: CRITICAL (Sigil Score: 50+)
**Impact**: Allows any domain to make cross-origin requests, enabling CSRF attacks and data exfiltration

#### Vulnerable Code
```typescript
// VULNERABLE: Allows any origin
res.header('Access-Control-Allow-Origin', '*');
```

#### Step-by-Step Remediation

**Step 1: Identify Allowed Origins**
```typescript
// Define allowed origins based on environment
const allowedOrigins = {
  development: ['http://localhost:3000', 'http://localhost:3001'],
  staging: ['https://staging.enclave.internal'],
  production: ['https://enclave.internal', 'https://admin.enclave.internal']
};

const currentOrigins = allowedOrigins[process.env.NODE_ENV || 'development'];
```

**Step 2: Implement Origin Validation**
```typescript
// SECURE: Validate origins against allowlist
private setupCORSMiddleware(): void {
  this.app.use((req, res, next) => {
    const origin = req.get('Origin');
    const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || 
                          ['https://enclave.internal'];
    
    if (origin && allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    
    // Set other CORS headers securely
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 
              'Origin, X-Requested-With, Content-Type, Accept, Authorization');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    
    next();
  });
}
```

**Step 3: Environment Configuration**
```bash
# .env.production
ALLOWED_ORIGINS=https://enclave.internal,https://admin.enclave.internal

# .env.staging  
ALLOWED_ORIGINS=https://staging.enclave.internal

# .env.development
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:3001
```

**Step 4: Validation Testing**
```typescript
// Security test for CORS configuration
describe('CORS Security', () => {
  it('should reject unauthorized origins', async () => {
    const response = await request(app)
      .options('/api/test')
      .set('Origin', 'https://malicious-site.com')
      .expect(200);
    
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });
  
  it('should allow authorized origins', async () => {
    const response = await request(app)
      .options('/api/test')  
      .set('Origin', 'https://enclave.internal')
      .expect(200);
    
    expect(response.headers['access-control-allow-origin'])
      .toBe('https://enclave.internal');
  });
});
```

**Step 5: Monitoring and Alerting**
```typescript
// Add CORS violation monitoring
private logCORSViolation(origin: string, ip: string): void {
  logger.warn('CORS policy violation', {
    origin,
    ip,
    timestamp: new Date(),
    severity: 'high',
    action_required: true
  });
  
  // Alert security team for repeated violations
  if (this.corsViolationCount.get(ip) > 5) {
    this.alertSecurityTeam('Repeated CORS violations', { origin, ip });
  }
}
```

### 2. Command Injection (OWASP A03 - Injection)

#### Issue Description
**File**: `services/security-verifier/src/utils/exec.ts`
**Risk Level**: CRITICAL (Sigil Score: 50+)
**Impact**: Remote code execution via crafted command parameters

#### Vulnerable Code
```typescript
// VULNERABLE: Direct shell execution
export async function safeExec(command: string, timeout = 30000): Promise<string> {
  const { stdout } = await execPromise(command, { timeout });
  return stdout.trim();
}
```

#### Step-by-Step Remediation

**Step 1: Command Allowlisting**
```typescript
export class SecureCommandExecutor {
  private static readonly ALLOWED_COMMANDS = new Map([
    ['aws', { maxArgs: 10, argValidation: /^[a-zA-Z0-9_\-\.\/]+$/ }],
    ['kubectl', { maxArgs: 8, argValidation: /^[a-zA-Z0-9_\-\.\/]+$/ }],
    ['docker', { maxArgs: 15, argValidation: /^[a-zA-Z0-9_\-\.\/\:]+$/ }],
    ['terraform', { maxArgs: 6, argValidation: /^[a-zA-Z0-9_\-\.\/]+$/ }],
    ['sigil', { maxArgs: 5, argValidation: /^[a-zA-Z0-9_\-\.\/]+$/ }]
  ]);

  static validateCommand(command: string): boolean {
    return this.ALLOWED_COMMANDS.has(command);
  }

  static validateArguments(command: string, args: string[]): boolean {
    const config = this.ALLOWED_COMMANDS.get(command);
    if (!config) return false;

    if (args.length > config.maxArgs) return false;

    return args.every(arg => config.argValidation.test(arg));
  }
}
```

**Step 2: Argument Sanitization**
```typescript
private static sanitizeArgument(arg: string): string {
  // Remove dangerous shell metacharacters
  const dangerous = /[;&|`$(){}[\]<>'"\\*?]/g;
  const sanitized = arg.replace(dangerous, '');
  
  // Additional validation
  if (sanitized.length === 0 || sanitized.length > 1000) {
    throw new SecurityError('Invalid argument after sanitization');
  }
  
  return sanitized;
}
```

**Step 3: Secure Execution Implementation**
```typescript
static async execute(
  command: string,
  args: string[] = [],
  options: ExecOptions = {}
): Promise<ExecutionResult> {
  // Validate command
  if (!this.validateCommand(command)) {
    throw new SecurityError(`Command not allowed: ${command}`);
  }

  // Validate and sanitize arguments
  if (!this.validateArguments(command, args)) {
    throw new SecurityError(`Invalid arguments for command: ${command}`);
  }

  const sanitizedArgs = args.map(arg => this.sanitizeArgument(arg));

  // Secure execution environment
  const execOptions = {
    timeout: Math.min(options.timeout || 30000, 300000), // Max 5 minutes
    uid: 1000, // Non-root execution
    gid: 1000,
    env: this.createSecureEnvironment(),
    cwd: options.cwd || '/tmp',
    stdio: 'pipe' as const
  };

  try {
    const result = await this.spawnSecure(command, sanitizedArgs, execOptions);
    
    // Audit successful execution
    logger.info('Command executed securely', {
      command,
      args: sanitizedArgs,
      executionTime: result.executionTime,
      exitCode: result.exitCode
    });

    return result;
  } catch (error) {
    // Audit failed execution
    logger.error('Command execution failed', {
      command,
      args: sanitizedArgs,
      error: error instanceof Error ? error.message : 'Unknown error'
    });
    throw error;
  }
}
```

**Step 4: Testing and Validation**
```typescript
describe('Secure Command Execution', () => {
  describe('Command Validation', () => {
    it('should allow whitelisted commands', () => {
      expect(SecureCommandExecutor.validateCommand('aws')).toBe(true);
      expect(SecureCommandExecutor.validateCommand('kubectl')).toBe(true);
    });

    it('should reject non-whitelisted commands', () => {
      expect(SecureCommandExecutor.validateCommand('rm')).toBe(false);
      expect(SecureCommandExecutor.validateCommand('curl')).toBe(false);
    });
  });

  describe('Injection Prevention', () => {
    it('should prevent command injection via arguments', async () => {
      await expect(
        SecureCommandExecutor.execute('echo', ['test; rm -rf /'])
      ).rejects.toThrow(SecurityError);
    });

    it('should sanitize dangerous characters', () => {
      const sanitized = SecureCommandExecutor['sanitizeArgument']('test$(rm -rf /)');
      expect(sanitized).not.toContain('$');
      expect(sanitized).not.toContain('(');
      expect(sanitized).not.toContain(')');
    });
  });
});
```

### 3. XSS via Unsanitized LLM Responses (OWASP A03 - Injection)

#### Issue Description
**File**: `services/terminal-client/src/components/ChatInterface.tsx:188`
**Risk Level**: HIGH (Sigil Score: 35-45)
**Impact**: Cross-site scripting via malicious AI responses

#### Vulnerable Code
```typescript
// VULNERABLE: Direct content assignment without sanitization
assistantMessage.content += data.content;
```

#### Step-by-Step Remediation

**Step 1: Install Sanitization Library**
```bash
cd services/terminal-client
npm install dompurify
npm install --save-dev @types/dompurify
```

**Step 2: Implement Content Sanitization**
```typescript
import DOMPurify from 'dompurify';

// SECURE: Content sanitization configuration
const sanitizerConfig = {
  ALLOWED_TAGS: [
    'p', 'br', 'strong', 'em', 'code', 'pre', 
    'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'blockquote', 'div', 'span'
  ],
  ALLOWED_ATTR: ['class'],
  FORBID_TAGS: ['script', 'style', 'iframe', 'object', 'embed'],
  FORBID_ATTR: ['onclick', 'onload', 'onerror', 'onmouseover'],
  ALLOW_DATA_ATTR: false,
  FORBID_SCRIPTS: true,
  SAFE_FOR_TEMPLATES: true
};

// Sanitization function
const sanitizeContent = (content: string): string => {
  try {
    return DOMPurify.sanitize(content, sanitizerConfig);
  } catch (error) {
    logger.error('Content sanitization failed', { error, content });
    return 'Content could not be displayed safely';
  }
};
```

**Step 3: Apply Sanitization to LLM Responses**
```typescript
// Stream processing with sanitization
const processStreamChunk = (chunk: string): void => {
  const lines = chunk.split('\n');
  
  for (const line of lines) {
    if (line.startsWith('data: ')) {
      try {
        const data = JSON.parse(line.slice(6));
        
        if (data.content) {
          // SECURE: Sanitize content before state update
          const sanitizedContent = sanitizeContent(data.content);
          
          assistantMessage.content += sanitizedContent;
          setStreaming(prev => ({
            ...prev,
            currentMessage: assistantMessage.content
          }));
        }
        
        if (data.cost !== undefined) {
          assistantMessage.cost = data.cost;
        }
      } catch (error) {
        logger.error('Failed to parse streaming response', { error, line });
      }
    }
  }
};
```

**Step 4: Content Security Policy Implementation**
```typescript
// CSP headers for additional XSS protection
export const securityHeaders = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'", // Required for styled-components
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self' wss://enclave.internal",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'"
  ].join('; '),
  
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin'
};
```

**Step 5: Testing XSS Prevention**
```typescript
describe('XSS Prevention', () => {
  describe('Content Sanitization', () => {
    it('should remove script tags', () => {
      const maliciousContent = '<script>alert("xss")</script>Hello';
      const sanitized = sanitizeContent(maliciousContent);
      expect(sanitized).toBe('Hello');
    });

    it('should remove event handlers', () => {
      const maliciousContent = '<div onclick="alert(1)">Click me</div>';
      const sanitized = sanitizeContent(maliciousContent);
      expect(sanitized).toBe('<div>Click me</div>');
    });

    it('should preserve safe HTML', () => {
      const safeContent = '<p>This is <strong>safe</strong> content</p>';
      const sanitized = sanitizeContent(safeContent);
      expect(sanitized).toBe(safeContent);
    });
  });

  describe('Real-world XSS Payloads', () => {
    const xssPayloads = [
      '<img src=x onerror=alert(1)>',
      'javascript:alert(1)',
      '<svg onload=alert(1)>',
      '<iframe src="javascript:alert(1)"></iframe>',
      '<object data="javascript:alert(1)"></object>'
    ];

    xssPayloads.forEach((payload, index) => {
      it(`should neutralize XSS payload ${index + 1}`, () => {
        const sanitized = sanitizeContent(payload);
        expect(sanitized).not.toContain('alert');
        expect(sanitized).not.toContain('javascript:');
      });
    });
  });
});
```

### 4. Missing Authentication on Administrative Endpoints (OWASP A07)

#### Issue Description
**File**: `services/mock-manager/src/index.ts`
**Risk Level**: CRITICAL (Sigil Score: 50+)
**Impact**: Unauthorized access to administrative functions

#### Vulnerable Code
```typescript
// VULNERABLE: No authentication required
this.app.post('/mocks/:service/start', async (req, res) => {
  const result = await this.startMockService(service, req.body);
  res.json({ success: true, result });
});
```

#### Step-by-Step Remediation

**Step 1: JWT Authentication Middleware**
```typescript
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    roles: string[];
    workspaces: string[];
  };
}

export const authenticateJWT = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      return void res.status(401).json({
        error: 'Authentication required',
        code: 'MISSING_TOKEN'
      });
    }

    const token = authHeader.substring(7);
    const secret = process.env.JWT_SECRET;
    
    if (!secret) {
      logger.error('JWT_SECRET not configured');
      return void res.status(500).json({
        error: 'Authentication service unavailable'
      });
    }

    const decoded = jwt.verify(token, secret) as any;
    
    req.user = {
      id: decoded.sub,
      email: decoded.email,
      roles: decoded.roles || [],
      workspaces: decoded.workspaces || []
    };

    next();
  } catch (error) {
    logger.warn('JWT authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      ip: req.ip
    });

    return void res.status(401).json({
      error: 'Invalid or expired token',
      code: 'INVALID_TOKEN'
    });
  }
};
```

**Step 2: Role-Based Authorization**
```typescript
export const authorizeRole = (requiredRoles: string[]) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      return void res.status(401).json({
        error: 'Authentication required'
      });
    }

    const hasRequiredRole = requiredRoles.some(role =>
      req.user!.roles.includes(role)
    );

    if (!hasRequiredRole) {
      logger.warn('Authorization failed', {
        userId: req.user.id,
        userRoles: req.user.roles,
        requiredRoles,
        endpoint: `${req.method} ${req.path}`,
        ip: req.ip
      });

      return void res.status(403).json({
        error: 'Insufficient permissions',
        required: requiredRoles,
        code: 'INSUFFICIENT_PERMISSIONS'
      });
    }

    next();
  };
};
```

**Step 3: Apply Authentication to Endpoints**
```typescript
// SECURE: Protected administrative endpoints
this.app.post('/mocks/:service/start',
  authenticateJWT,
  authorizeRole(['admin', 'developer']),
  async (req: AuthenticatedRequest, res) => {
    try {
      const { service } = req.params;
      const { user } = req;

      // Audit administrative action
      logger.info('Mock service start requested', {
        userId: user!.id,
        service,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      const result = await this.startMockService(service, req.body);
      
      // Audit successful action
      logger.info('Mock service started successfully', {
        userId: user!.id,
        service,
        result: result.id
      });

      res.json({ success: true, result });
    } catch (error) {
      logger.error('Mock service start failed', {
        userId: req.user!.id,
        service: req.params.service,
        error: error instanceof Error ? error.message : 'Unknown error'
      });

      res.status(500).json({
        error: 'Failed to start mock service',
        message: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  }
);
```

**Step 4: Multi-Factor Authentication for Sensitive Operations**
```typescript
export const requireMFA = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): void => {
  if (!req.user) {
    return void res.status(401).json({
      error: 'Authentication required'
    });
  }

  const mfaToken = req.headers['x-mfa-token'] as string;
  
  if (!mfaToken) {
    logger.warn('MFA token required but not provided', {
      userId: req.user.id,
      endpoint: `${req.method} ${req.path}`,
      ip: req.ip
    });

    return void res.status(403).json({
      error: 'Multi-factor authentication required',
      code: 'MFA_REQUIRED'
    });
  }

  try {
    // Validate TOTP token
    const isValidMFA = authenticator.verify({
      token: mfaToken,
      secret: process.env.MFA_SECRET || ''
    });

    if (!isValidMFA) {
      throw new Error('Invalid MFA token');
    }

    logger.info('MFA validation successful', {
      userId: req.user.id,
      endpoint: `${req.method} ${req.path}`
    });

    next();
  } catch (error) {
    logger.warn('MFA validation failed', {
      userId: req.user.id,
      error: error instanceof Error ? error.message : 'Unknown error',
      ip: req.ip
    });

    return void res.status(403).json({
      error: 'Invalid multi-factor authentication token',
      code: 'INVALID_MFA'
    });
  }
};
```

**Step 5: Comprehensive Authentication Testing**
```typescript
describe('Authentication Security', () => {
  describe('JWT Authentication', () => {
    it('should reject requests without Bearer token', async () => {
      const response = await request(app)
        .post('/mocks/test/start')
        .expect(401);

      expect(response.body.code).toBe('MISSING_TOKEN');
    });

    it('should reject invalid tokens', async () => {
      const response = await request(app)
        .post('/mocks/test/start')
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.code).toBe('INVALID_TOKEN');
    });

    it('should accept valid tokens', async () => {
      const validToken = generateTestToken({ roles: ['developer'] });
      
      const response = await request(app)
        .post('/mocks/test/start')
        .set('Authorization', `Bearer ${validToken}`)
        .expect(200);

      expect(response.body.success).toBe(true);
    });
  });

  describe('Role-Based Authorization', () => {
    it('should allow users with appropriate roles', async () => {
      const token = generateTestToken({ roles: ['admin'] });
      
      await request(app)
        .post('/mocks/test/start')
        .set('Authorization', `Bearer ${token}`)
        .expect(200);
    });

    it('should reject users without appropriate roles', async () => {
      const token = generateTestToken({ roles: ['viewer'] });
      
      const response = await request(app)
        .post('/mocks/test/start')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);

      expect(response.body.code).toBe('INSUFFICIENT_PERMISSIONS');
    });
  });

  describe('Multi-Factor Authentication', () => {
    it('should require MFA for sensitive operations', async () => {
      const token = generateTestToken({ roles: ['admin'] });
      
      const response = await request(app)
        .delete('/mocks/all/reset')
        .set('Authorization', `Bearer ${token}`)
        .expect(403);

      expect(response.body.code).toBe('MFA_REQUIRED');
    });

    it('should accept valid MFA tokens', async () => {
      const token = generateTestToken({ roles: ['admin'] });
      const mfaToken = generateTestMFAToken();
      
      await request(app)
        .delete('/mocks/all/reset')
        .set('Authorization', `Bearer ${token}`)
        .set('X-MFA-Token', mfaToken)
        .expect(200);
    });
  });
});
```

## Air-Gap Specific Security Considerations

### Network Isolation Validation
```bash
#!/bin/bash
# Air-gap security validation script

validate_air_gap_compliance() {
  echo "🔒 Validating air-gap compliance..."
  
  # Check for internet gateway
  if aws ec2 describe-internet-gateways --query 'InternetGateways[?Attachments[0].VpcId==`'$VPC_ID'`]' --output text | grep -q 'igw-'; then
    echo "❌ Internet gateway found - air-gap compromised"
    return 1
  fi
  
  # Check for external DNS
  if nslookup google.com &>/dev/null; then
    echo "❌ External DNS resolution possible - air-gap compromised"  
    return 1
  fi
  
  # Validate PrivateLink endpoints
  aws ec2 describe-vpc-endpoints --vpc-ids $VPC_ID --query 'VpcEndpoints[].ServiceName' --output text | while read service; do
    echo "✅ PrivateLink endpoint configured: $service"
  done
  
  echo "✅ Air-gap compliance validated"
  return 0
}
```

### Container Security Hardening
```dockerfile
# Secure container configuration
FROM node:18-alpine AS base

# Create non-root user
RUN addgroup -g 1001 -S enclave && \
    adduser -S -D -h /app -s /sbin/nologin -u 1001 -G enclave enclave

# Security hardening
RUN apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/* && \
    rm -rf /tmp/*

WORKDIR /app

# Install dependencies as root, run as user
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Switch to non-root user
USER enclave:enclave

# Security metadata
LABEL security.scan="required" \
      security.user="non-root" \
      security.network="isolated"

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node healthcheck.js

ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "dist/index.js"]
```

This comprehensive remediation guide provides step-by-step instructions for fixing critical security vulnerabilities in the Enclave AI platform while maintaining air-gap compliance and implementing defense-in-depth security controls.