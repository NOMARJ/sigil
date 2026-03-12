#!/usr/bin/env python3
"""
Batch classification script to populate forge tables from existing public_scans data.
Analyzes packages and classifies them for forge intelligence.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.database import MssqlClient


class ForgeClassifier:
    """Classifies packages for forge intelligence."""

    def __init__(self, db: MssqlClient):
        self.db = db
        self.stats = {"processed": 0, "classified": 0, "errors": 0, "skipped": 0}

    def classify_package(self, scan: Dict[str, Any]) -> Dict[str, Any]:
        """Classify a single package based on scan results."""

        package_name = scan.get("package_name", "").lower()
        ecosystem = scan.get("ecosystem", "unknown")
        severity = scan.get("severity", 0)
        threats = scan.get("threats_found", 0)

        # Determine category based on package patterns
        category = self.determine_category(package_name, ecosystem)

        # Calculate trust score (0-100)
        trust_score = self.calculate_trust_score(scan)

        # Determine tool type
        tool_type = self.determine_tool_type(package_name, ecosystem)

        # Extract capabilities
        capabilities = self.extract_capabilities(scan)

        return {
            "scan_id": scan.get("id"),
            "package_name": package_name,
            "ecosystem": ecosystem,
            "category": category,
            "tool_type": tool_type,
            "trust_score": trust_score,
            "capabilities": capabilities,
            "severity_level": self.severity_to_level(severity),
            "threats_found": threats,
            "classification_date": datetime.utcnow().isoformat(),
        }

    def determine_category(self, name: str, ecosystem: str) -> str:
        """Determine package category based on name patterns."""

        categories = {
            "mcp": ["mcp-", "-mcp", "model-context"],
            "skills": ["skill-", "-skill", "skills-", "clawbot", "clawhub"],
            "agent": ["agent", "assistant", "bot", "ai-"],
            "llm": ["llm", "openai", "anthropic", "gemini", "gpt", "claude"],
            "security": ["security", "auth", "encrypt", "secure"],
            "data": ["data", "database", "sql", "mongo", "redis"],
            "web": ["http", "express", "flask", "fastapi", "server"],
            "dev-tools": ["webpack", "babel", "eslint", "prettier", "test"],
            "crypto": ["crypto", "blockchain", "bitcoin", "ethereum"],
            "ml": ["tensorflow", "pytorch", "scikit", "pandas", "numpy"],
        }

        name_lower = name.lower()
        for category, keywords in categories.items():
            if any(keyword in name_lower for keyword in keywords):
                return category

        return "general"

    def determine_tool_type(self, name: str, ecosystem: str) -> str:
        """Determine if package is a specific tool type."""

        if "mcp" in name.lower():
            return "mcp-server"
        elif "skill" in name.lower() or "clawbot" in name.lower():
            return "skill"
        elif ecosystem == "npm":
            return "npm-package"
        elif ecosystem == "pypi":
            return "python-package"
        else:
            return "other"

    def calculate_trust_score(self, scan: Dict[str, Any]) -> int:
        """Calculate trust score based on scan results (0-100)."""

        base_score = 100

        # Deduct based on severity
        severity = scan.get("severity", 0)
        if severity >= 9:
            base_score -= 70  # Critical
        elif severity >= 7:
            base_score -= 50  # High
        elif severity >= 4:
            base_score -= 30  # Medium
        elif severity >= 1:
            base_score -= 10  # Low

        # Deduct for threats
        threats = scan.get("threats_found", 0)
        base_score -= min(threats * 5, 30)  # Max 30 point deduction for threats

        # Ensure score is within bounds
        return max(0, min(100, base_score))

    def severity_to_level(self, severity: int) -> str:
        """Convert numeric severity to level."""
        if severity >= 9:
            return "critical"
        elif severity >= 7:
            return "high"
        elif severity >= 4:
            return "medium"
        elif severity >= 1:
            return "low"
        return "safe"

    def extract_capabilities(self, scan: Dict[str, Any]) -> List[str]:
        """Extract capabilities from scan results."""

        capabilities = []
        findings = scan.get("findings", {})

        # Parse findings if it's a JSON string
        if isinstance(findings, str):
            try:
                findings = json.loads(findings)
            except Exception:
                findings = {}

        # Check for common capabilities
        if findings.get("network_access"):
            capabilities.append("network")
        if findings.get("file_system"):
            capabilities.append("filesystem")
        if findings.get("process_spawn"):
            capabilities.append("process")
        if findings.get("crypto_mining"):
            capabilities.append("crypto")
        if findings.get("data_exfiltration"):
            capabilities.append("exfiltration")

        return capabilities

    async def process_batch(self, batch: List[Dict[str, Any]]):
        """Process a batch of scans."""

        for scan in batch:
            try:
                # Skip if already classified
                existing = await self.db.select_one(
                    "forge_classification", {"scan_id": scan["id"]}
                )

                if existing:
                    self.stats["skipped"] += 1
                    continue

                # Classify the package
                classification = self.classify_package(scan)

                # Store classification
                await self.db.insert(
                    "forge_classification",
                    {
                        "public_scan_id": classification["scan_id"],
                        "package_name": classification["package_name"],
                        "ecosystem": classification["ecosystem"],
                        "category": classification["category"],
                        "tool_type": classification["tool_type"],
                        "trust_score": classification["trust_score"],
                        "severity_level": classification["severity_level"],
                        "threats_detected": classification["threats_found"],
                        "capabilities": json.dumps(classification["capabilities"]),
                        "classified_at": datetime.utcnow().isoformat(),
                    },
                )

                self.stats["classified"] += 1

            except Exception as e:
                print(f"Error processing {scan.get('package_name')}: {e}")
                self.stats["errors"] += 1

            self.stats["processed"] += 1

            # Progress update every 100 items
            if self.stats["processed"] % 100 == 0:
                print(
                    f"Progress: {self.stats['processed']} processed, "
                    f"{self.stats['classified']} classified, "
                    f"{self.stats['skipped']} skipped, "
                    f"{self.stats['errors']} errors"
                )

    async def run(self, limit: Optional[int] = None):
        """Run the batch classification."""

        print("Starting batch classification...")
        print(f"Limit: {limit if limit else 'No limit'}")

        # Get total count
        count_result = await self.db.execute_raw_sql(
            "SELECT COUNT(*) as count FROM public_scans"
        )
        total = count_result[0]["count"] if count_result else 0
        print(f"Total scans to process: {total}")

        # Process in batches
        batch_size = 100
        offset = 0

        while True:
            # Fetch batch
            sql = f"""
                SELECT TOP {batch_size} 
                    id, package_name, ecosystem, severity, 
                    threats_found, findings, created_at
                FROM public_scans
                ORDER BY created_at DESC
                OFFSET {offset} ROWS
            """

            if limit and offset >= limit:
                break

            batch = await self.db.execute_raw_sql(sql)

            if not batch:
                break

            await self.process_batch(batch)
            offset += batch_size

            if limit and self.stats["processed"] >= limit:
                break

        print("\n" + "=" * 50)
        print("Batch classification complete!")
        print(f"Total processed: {self.stats['processed']}")
        print(f"Successfully classified: {self.stats['classified']}")
        print(f"Skipped (already classified): {self.stats['skipped']}")
        print(f"Errors: {self.stats['errors']}")
        print("=" * 50)


async def main():
    """Main entry point."""

    # Parse arguments
    limit = None
    if len(sys.argv) > 1:
        if sys.argv[1] == "--limit" and len(sys.argv) > 2:
            limit = int(sys.argv[2])

    # Database connection string
    db_url = (
        os.environ.get("SIGIL_DATABASE_URL")
        or "Driver={ODBC Driver 18 for SQL Server};Server=tcp:sigil-sql-w2-46iy6y.database.windows.net,1433;Database=sigil;Uid=sigil_admin;Pwd=hUkVA6s1G7z4Smqf!;Encrypt=yes;TrustServerCertificate=no;"
    )

    # Initialize database
    db = MssqlClient(db_url)
    await db.connect()

    try:
        # Create forge_classification table if it doesn't exist
        await db.execute_raw_sql("""
            IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'forge_classification')
            CREATE TABLE forge_classification (
                id UNIQUEIDENTIFIER DEFAULT NEWID() PRIMARY KEY,
                public_scan_id UNIQUEIDENTIFIER,
                package_name NVARCHAR(255) NOT NULL,
                ecosystem NVARCHAR(50) NOT NULL,
                category NVARCHAR(100),
                tool_type NVARCHAR(50),
                trust_score INT,
                severity_level NVARCHAR(20),
                threats_detected INT DEFAULT 0,
                capabilities NVARCHAR(MAX),
                classified_at DATETIME DEFAULT GETDATE(),
                FOREIGN KEY (public_scan_id) REFERENCES public_scans(id) ON DELETE CASCADE
            )
        """)

        # Create indexes
        await db.execute_raw_sql("""
            IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_class_scan')
            CREATE INDEX idx_forge_class_scan ON forge_classification(public_scan_id)
        """)

        await db.execute_raw_sql("""
            IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'idx_forge_class_package')
            CREATE INDEX idx_forge_class_package ON forge_classification(package_name, ecosystem)
        """)

        # Run classifier
        classifier = ForgeClassifier(db)
        await classifier.run(limit)

    finally:
        await db.close()


if __name__ == "__main__":
    asyncio.run(main())
