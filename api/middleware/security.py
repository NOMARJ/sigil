"""
Sigil API — Security Middleware

Comprehensive security middleware for input validation, sanitization,
and protection against common web vulnerabilities.
"""

from __future__ import annotations

import html
import logging
import re
import urllib.parse
from typing import Any, Optional

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator, ConfigDict
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Security constants
MAX_URL_LENGTH = 2048
MAX_PARAM_LENGTH = 512
MAX_JSON_DEPTH = 10
MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB

# Dangerous patterns for command injection
COMMAND_INJECTION_PATTERNS = [
    r'[;&|`$()]',  # Shell metacharacters
    r'\.\.',  # Directory traversal
    r'--',  # Command flags that could be injected
    r'\x00',  # Null bytes
    r'[\n\r]',  # Newlines that could break commands
]

# XSS dangerous patterns
XSS_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'javascript:',
    r'on\w+\s*=',  # Event handlers
    r'<iframe',
    r'<embed',
    r'<object',
    r'vbscript:',
    r'data:text/html',
]

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"('\s*(OR|AND)\s*')|('\s*--)",  # Basic SQL injection
    r'(UNION\s+SELECT)|(INSERT\s+INTO)|(DELETE\s+FROM)|(UPDATE\s+\w+\s+SET)',
    r'(DROP\s+TABLE)|(CREATE\s+TABLE)|(ALTER\s+TABLE)',
    r'(EXEC\s*\()|(EXECUTE\s*\()',
]


class SecurityValidationError(HTTPException):
    """Custom exception for security validation failures."""
    
    def __init__(self, detail: str, status_code: int = status.HTTP_400_BAD_REQUEST):
        super().__init__(status_code=status_code, detail=detail)


class URLValidator:
    """Validate and sanitize URLs."""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if URL is valid and safe."""
        if not url or len(url) > MAX_URL_LENGTH:
            return False
            
        # Parse URL
        try:
            parsed = urllib.parse.urlparse(url)
        except Exception:
            return False
            
        # Check protocol
        if parsed.scheme not in ('http', 'https', 'git'):
            return False
            
        # Check for localhost/private IPs (prevent SSRF)
        hostname = parsed.hostname
        if hostname:
            hostname_lower = hostname.lower()
            if any(blocked in hostname_lower for blocked in [
                'localhost', '127.0.0.1', '0.0.0.0', '::1',
                '169.254',  # Link-local
                '10.',  # Private network
                '192.168',  # Private network
                '172.16', '172.17', '172.18', '172.19',  # Private networks
                '172.20', '172.21', '172.22', '172.23',
                '172.24', '172.25', '172.26', '172.27',
                '172.28', '172.29', '172.30', '172.31',
            ]):
                return False
                
        # Check for command injection in URL
        if any(re.search(pattern, url) for pattern in COMMAND_INJECTION_PATTERNS):
            return False
            
        return True
    
    @staticmethod
    def sanitize_url(url: str) -> str:
        """Sanitize URL for safe usage."""
        if not URLValidator.is_valid_url(url):
            raise SecurityValidationError(f"Invalid or unsafe URL: {url[:100]}")
            
        # Remove any trailing spaces and encode special characters
        url = url.strip()
        
        # Ensure GitHub URLs are HTTPS
        if 'github.com' in url and url.startswith('http://'):
            url = url.replace('http://', 'https://', 1)
            
        return url


class InputSanitizer:
    """Sanitize user inputs to prevent injection attacks."""
    
    @staticmethod
    def sanitize_for_shell(value: str) -> str:
        """Sanitize input for shell command usage."""
        if not value:
            return ""
            
        # Check for command injection patterns
        for pattern in COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, value):
                raise SecurityValidationError(
                    "Input contains potentially dangerous characters for shell execution"
                )
        
        # Use shlex.quote for additional safety (when used in actual commands)
        import shlex
        return shlex.quote(value)
    
    @staticmethod
    def sanitize_for_html(value: str) -> str:
        """Escape HTML to prevent XSS."""
        if not value:
            return ""
            
        # HTML escape
        escaped = html.escape(value, quote=True)
        
        # Additional XSS prevention
        for pattern in XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning("Potential XSS attempt detected and blocked: %s", value[:100])
                raise SecurityValidationError("Input contains potentially dangerous HTML/JavaScript")
                
        return escaped
    
    @staticmethod
    def sanitize_for_sql(value: str) -> str:
        """Basic SQL injection prevention (use parameterized queries instead!)."""
        if not value:
            return ""
            
        # Check for SQL injection patterns
        for pattern in SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning("Potential SQL injection attempt detected: %s", value[:100])
                raise SecurityValidationError("Input contains potentially dangerous SQL patterns")
                
        # Escape single quotes (basic protection, parameterized queries are better)
        return value.replace("'", "''")
    
    @staticmethod
    def sanitize_ecosystem(ecosystem: str) -> str:
        """Validate and sanitize ecosystem parameter."""
        valid_ecosystems = ['pypi', 'npm', 'clawhub', 'github', 'mcp', 'crates', 'gem']
        ecosystem_lower = ecosystem.lower().strip()
        
        if ecosystem_lower not in valid_ecosystems:
            raise SecurityValidationError(
                f"Invalid ecosystem: {ecosystem}. Must be one of: {', '.join(valid_ecosystems)}"
            )
            
        return ecosystem_lower
    
    @staticmethod
    def sanitize_verdict(verdict: str) -> str:
        """Validate and sanitize verdict parameter."""
        valid_verdicts = [
            'LOW_RISK', 'MEDIUM_RISK', 'HIGH_RISK', 'CRITICAL_RISK',
            'ERROR', 'UNKNOWN', 'TIMEOUT'
        ]
        
        verdict_upper = verdict.upper().strip()
        
        # Handle comma-separated verdicts
        if ',' in verdict:
            verdicts = [v.strip().upper() for v in verdict.split(',')]
            for v in verdicts:
                if v not in valid_verdicts:
                    raise SecurityValidationError(f"Invalid verdict: {v}")
            return ','.join(verdicts)
        
        if verdict_upper not in valid_verdicts:
            raise SecurityValidationError(
                f"Invalid verdict: {verdict}. Must be one of: {', '.join(valid_verdicts)}"
            )
            
        return verdict_upper


class SecurityHeaders:
    """Add comprehensive security headers to responses."""
    
    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://api.sigilsec.ai; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        ),
    }
    
    HEADERS_PRODUCTION = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }
    
    @classmethod
    def apply(cls, response: Any, is_production: bool = True) -> None:
        """Apply security headers to response."""
        for header, value in cls.HEADERS.items():
            response.headers[header] = value
            
        if is_production:
            for header, value in cls.HEADERS_PRODUCTION.items():
                response.headers[header] = value


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Middleware for request validation and sanitization."""
    
    async def dispatch(self, request: Request, call_next):
        # Check request size
        if request.headers.get("content-length"):
            content_length = int(request.headers["content-length"])
            if content_length > MAX_REQUEST_SIZE:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={"detail": "Request too large"}
                )
        
        # Validate query parameters
        for key, value in request.query_params.items():
            if len(value) > MAX_PARAM_LENGTH:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": f"Query parameter '{key}' too long"}
                )
            
            # Check for common injection patterns in query params
            if any(re.search(pattern, value) for pattern in COMMAND_INJECTION_PATTERNS):
                logger.warning(
                    "Potential command injection in query param '%s': %s",
                    key, value[:100]
                )
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Invalid characters in query parameters"}
                )
        
        response = await call_next(request)
        return response


# Pydantic models for input validation
class PackageScanRequest(BaseModel):
    """Validated package scan request."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    ecosystem: str = Field(..., min_length=1, max_length=20)
    package_name: str = Field(..., min_length=1, max_length=200)
    package_version: Optional[str] = Field(None, max_length=50)
    
    @field_validator('ecosystem')
    @classmethod
    def validate_ecosystem(cls, v: str) -> str:
        return InputSanitizer.sanitize_ecosystem(v)
    
    @field_validator('package_name')
    @classmethod
    def validate_package_name(cls, v: str) -> str:
        # Check for path traversal
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError("Invalid characters in package name")
        # Check for command injection
        if any(char in v for char in ';|&`$()'):
            raise ValueError("Invalid characters in package name")
        return v


class URLScanRequest(BaseModel):
    """Validated URL scan request."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    url: str = Field(..., min_length=1, max_length=MAX_URL_LENGTH)
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        return URLValidator.sanitize_url(v)


class FeedQueryParams(BaseModel):
    """Validated feed query parameters."""
    model_config = ConfigDict(str_strip_whitespace=True)
    
    ecosystem: Optional[str] = Field(None, max_length=20)
    verdict: Optional[str] = Field(None, max_length=200)
    limit: int = Field(50, ge=1, le=200)
    since: Optional[str] = Field(None, max_length=50)
    
    @field_validator('ecosystem')
    @classmethod
    def validate_ecosystem(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return InputSanitizer.sanitize_ecosystem(v)
        return v
    
    @field_validator('verdict')
    @classmethod
    def validate_verdict(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return InputSanitizer.sanitize_verdict(v)
        return v
    
    @field_validator('since')
    @classmethod
    def validate_since(cls, v: Optional[str]) -> Optional[str]:
        if v:
            # Basic ISO datetime validation
            import re
            if not re.match(r'^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2})?', v):
                raise ValueError("Invalid datetime format")
        return v


def sanitize_json_for_output(data: Any, max_depth: int = MAX_JSON_DEPTH) -> Any:
    """Recursively sanitize JSON data for safe output."""
    if max_depth <= 0:
        return "[DEPTH_LIMIT_EXCEEDED]"
        
    if isinstance(data, dict):
        return {
            html.escape(str(k)): sanitize_json_for_output(v, max_depth - 1)
            for k, v in data.items()
        }
    elif isinstance(data, list):
        return [sanitize_json_for_output(item, max_depth - 1) for item in data]
    elif isinstance(data, str):
        return html.escape(data)
    else:
        return data