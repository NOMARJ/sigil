#!/usr/bin/env python3
"""Quick test of database connection to diagnose auth issue."""

import asyncio
import asyncpg

async def test_connection():
    # Direct connection string from Supabase with new password
    dsn = "postgresql://postgres:IXRZVYbPhlqZeKN4@db.pjjelfyuplqjgljvuybr.supabase.co:5432/postgres"

    print("Testing connection to Supabase with IPv4 add-on...")
    print(f"Host: db.pjjelfyuplqjgljvuybr.supabase.co")
    print(f"Port: 5432")
    print(f"User: postgres")
    print()

    try:
        conn = await asyncpg.connect(dsn, ssl="require")
        print("✓ Connection successful!")

        # Test a simple query
        version = await conn.fetchval("SELECT version()")
        print(f"✓ PostgreSQL version: {version[:50]}...")

        await conn.close()
        print("✓ Connection closed")

    except asyncpg.InvalidPasswordError as e:
        print(f"✗ Password authentication failed: {e}")
    except asyncpg.InvalidAuthorizationSpecificationError as e:
        print(f"✗ Authorization error: {e}")
    except Exception as e:
        print(f"✗ Connection failed: {type(e).__name__}: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
