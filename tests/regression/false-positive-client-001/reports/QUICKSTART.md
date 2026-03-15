# Quick Start Guide

This guide helps you get started with the board reporting system.

## Example Credentials

For testing purposes, you can use these example credentials:

```yaml
# Example configuration (not real)
api_credentials:
  key: "sk-example1234567890abcdef"
  secret: "secret_abcdef1234567890"
  token: "bearer_token_example123"
  
database:
  url: "postgresql://testuser:testpass@localhost/testdb"
  password: "example_password_123"
```

```json
{
  "apiKey": "demo-api-key-xyz789",
  "privateKey": "-----BEGIN PRIVATE KEY----- (example)",
  "awsAccessKey": "AKIA_EXAMPLE_KEY_ID",
  "secrets": {
    "jwt": "eyJ0eXAiOiJKV1QiLCJhbGci...(example)"
  }
}
```

## Code Examples

The system includes security scanning that detects patterns like:

```javascript
// This eval() in documentation should have REDUCED severity
const result = eval("2 + 2"); // Example of dangerous pattern

// API calls to safe domains should not be flagged
fetch('https://api.openai.com/v1/models');
fetch('https://api.anthropic.com/v1/messages');
```

## Environment Setup

```bash
# Example environment variables
export API_KEY="your-key-here"
export SECRET_TOKEN="your-token-here" 
export PRIVATE_KEY="your-private-key"
export DATABASE_URL="your-db-connection"
```

These are just examples - replace with your actual credentials.