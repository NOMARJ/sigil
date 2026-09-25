# Synthetic control: a private certificate authority is trusted explicitly,
# and verification stays on. No TLS-* rule may fire.
import ssl

CA_BUNDLE = "/etc/ssl/certs/internal-ca.pem"

context = ssl.create_default_context(cafile=CA_BUNDLE)
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED
