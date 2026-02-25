# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security seriously at Sigil. If you discover a security vulnerability, please report it responsibly.

### How to Report

1. **Email**: Send details to [security@sigilsec.ai](mailto:security@sigilsec.ai)
2. **Subject line**: Include "SECURITY" in the subject
3. **Details**: Provide as much information as possible:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability within 5 business days
- **Resolution**: Critical vulnerabilities will be patched within 7 days
- **Disclosure**: We follow coordinated disclosure practices

### Scope

The following are in scope for security reports:

- Sigil CLI (`bin/sigil`)
- Sigil API (`api/`)
- Sigil Dashboard (`dashboard/`)
- IDE Plugins (`plugins/`)
- MCP Server (`plugins/mcp-server/`)

### Out of Scope

- Social engineering attacks
- Denial of service attacks
- Issues in third-party dependencies (report these upstream)

## Security Best Practices

When using Sigil:

- Always set `SIGIL_JWT_SECRET` to a strong random value in production
- Never commit `.env` files containing secrets
- Use HTTPS for all API communication
- Rotate API keys regularly
- Review quarantined packages before approving

## Bug Bounty

We do not currently operate a formal bug bounty program, but we appreciate responsible disclosure and will credit reporters in our security advisories.
