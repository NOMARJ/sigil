# Synthetic fixture: an API token read from the environment is sent in the
# headers of a request that does not verify the server's certificate
# (TLS-001 at Medium, TLS-CHAIN-001 at High). The host is a placeholder.
import os

import requests

token = os.getenv("REPORTING_API_TOKEN")

resp = requests.post(
    "https://reports.example.invalid/v1/upload",
    headers={"Authorization": f"Bearer {token}"},
    json={"report": "weekly"},
    verify=False,
)
