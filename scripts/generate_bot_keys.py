#!/usr/bin/env python3
"""
Generate Ed25519 keypair for Sigil bot attestation signing.

Usage:
    python scripts/generate_bot_keys.py
    python scripts/generate_bot_keys.py --output-env
    python scripts/generate_bot_keys.py --save-to-files keys/
"""

import argparse
import base64
import os
from pathlib import Path

# Add parent directory to path for bot imports
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from bot.attestation import generate_keypair


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Ed25519 keypair for bot attestation")
    parser.add_argument("--output-env", action="store_true", help="Output as environment variables")
    parser.add_argument("--save-to-files", metavar="DIR", help="Save keys to files in specified directory")
    parser.add_argument("--key-id", default="sha256:sigil-bot-signing-key-2026", help="Key identifier")
    
    args = parser.parse_args()
    
    # Generate the keypair
    print("🔑 Generating Ed25519 keypair for Sigil bot attestation...")
    private_key_bytes, public_key_pem = generate_keypair()
    
    # Base64 encode for environment variables
    private_key_b64 = base64.b64encode(private_key_bytes).decode()
    public_key_b64 = base64.b64encode(public_key_pem).decode()
    
    if args.output_env:
        # Output as environment variables ready to copy-paste
        print("\n# Add these to your .env file:")
        print(f"SIGIL_BOT_PRIVATE_KEY={private_key_b64}")
        print(f"SIGIL_BOT_PUBLIC_KEY={public_key_b64}")
        print(f"SIGIL_BOT_SIGNING_KEY_ID={args.key_id}")
        
    elif args.save_to_files:
        # Save to files
        key_dir = Path(args.save_to_files)
        key_dir.mkdir(parents=True, exist_ok=True)
        
        private_key_file = key_dir / "bot-private.key"
        public_key_file = key_dir / "bot-public.pem"
        
        # Save private key as raw bytes
        with open(private_key_file, "wb") as f:
            f.write(private_key_bytes)
        
        # Save public key as PEM
        with open(public_key_file, "wb") as f:
            f.write(public_key_pem)
        
        # Set restrictive permissions
        os.chmod(private_key_file, 0o600)
        os.chmod(public_key_file, 0o644)
        
        print("✅ Keys saved:")
        print(f"   Private key: {private_key_file}")
        print(f"   Public key:  {public_key_file}")
        print("\n# Add these to your .env file:")
        print(f"SIGIL_BOT_PUBLIC_KEY_FILE={public_key_file.absolute()}")
        print(f"SIGIL_BOT_SIGNING_KEY_ID={args.key_id}")
        
    else:
        # Default: show both formats
        print(f"\n📋 Generated keypair (Key ID: {args.key_id})")
        print("=" * 60)
        print(f"Private Key (32 bytes): {len(private_key_bytes)} bytes")
        print(f"Public Key PEM: {len(public_key_pem)} bytes")
        
        print("\n🔐 Base64-encoded (for environment variables):")
        print(f"Private: {private_key_b64}")
        print(f"Public:  {public_key_b64}")
        
        print("\n📝 Environment variables:")
        print(f"SIGIL_BOT_PRIVATE_KEY={private_key_b64}")
        print(f"SIGIL_BOT_PUBLIC_KEY={public_key_b64}")
        print(f"SIGIL_BOT_SIGNING_KEY_ID={args.key_id}")


if __name__ == "__main__":
    main()