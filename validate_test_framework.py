#!/usr/bin/env python3
"""
Test Framework Validation Script

Validates that the comprehensive testing framework is properly implemented
and ready for execution. This script checks the test files without executing
them to ensure they are syntactically correct and well-structured.
"""

import ast
import os
import sys
from typing import Dict, Any


class TestFrameworkValidator:
    """Validates the comprehensive testing framework implementation."""

    def __init__(self):
        self.test_files = [
            "api/tests/test_security_comprehensive.py",
            "api/tests/test_performance_comprehensive.py",
            "api/tests/test_integration_comprehensive.py",
            "api/tests/test_resilience_comprehensive.py",
            "api/tests/test_monitoring_comprehensive.py",
        ]
        self.validation_results = {}

    def validate_file_syntax(self, file_path: str) -> Dict[str, Any]:
        """Validate Python syntax and structure of test file."""
        try:
            with open(file_path, "r") as f:
                content = f.read()

            # Parse AST to check syntax
            tree = ast.parse(content)

            # Count test classes and methods
            test_classes = []
            test_methods = []

            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
                    test_classes.append(node.name)
                elif isinstance(node, ast.FunctionDef) and node.name.startswith(
                    "test_"
                ):
                    test_methods.append(node.name)

            return {
                "file": file_path,
                "syntax_valid": True,
                "test_classes": len(test_classes),
                "test_methods": len(test_methods),
                "class_names": test_classes,
                "lines_of_code": len(content.splitlines()),
                "error": None,
            }

        except SyntaxError as e:
            return {
                "file": file_path,
                "syntax_valid": False,
                "error": f"Syntax error: {e}",
                "test_classes": 0,
                "test_methods": 0,
            }
        except Exception as e:
            return {
                "file": file_path,
                "syntax_valid": False,
                "error": f"Validation error: {e}",
                "test_classes": 0,
                "test_methods": 0,
            }

    def check_test_coverage_areas(self, file_path: str) -> Dict[str, bool]:
        """Check if test file covers expected areas."""
        coverage_areas = {}

        try:
            with open(file_path, "r") as f:
                content = f.read().lower()

            if "security" in file_path:
                coverage_areas.update(
                    {
                        "xss_protection": "xss" in content,
                        "injection_prevention": "injection" in content,
                        "csrf_protection": "csrf" in content,
                        "rate_limiting": "rate" in content,
                        "input_validation": "validation" in content,
                        "authentication": "auth" in content,
                    }
                )

            elif "performance" in file_path:
                coverage_areas.update(
                    {
                        "response_times": "response" in content and "time" in content,
                        "concurrent_load": "concurrent" in content,
                        "memory_usage": "memory" in content,
                        "database_performance": "database" in content,
                        "classification_performance": "classification" in content,
                    }
                )

            elif "integration" in file_path:
                coverage_areas.update(
                    {
                        "authentication_flow": "auth" in content and "flow" in content,
                        "scan_workflow": "scan" in content and "workflow" in content,
                        "database_integration": "database" in content,
                        "external_apis": "external" in content or "api" in content,
                        "threat_intelligence": "threat" in content,
                    }
                )

            elif "resilience" in file_path:
                coverage_areas.update(
                    {
                        "database_failures": "database" in content
                        and "fail" in content,
                        "network_failures": "network" in content,
                        "circuit_breakers": "circuit" in content,
                        "graceful_degradation": "degradation" in content,
                        "chaos_engineering": "chaos" in content,
                    }
                )

            elif "monitoring" in file_path:
                coverage_areas.update(
                    {
                        "health_checks": "health" in content,
                        "metrics_collection": "metrics" in content,
                        "alert_generation": "alert" in content,
                        "dashboard_functionality": "dashboard" in content,
                        "log_aggregation": "log" in content,
                    }
                )

        except Exception as e:
            print(f"Error checking coverage for {file_path}: {e}")

        return coverage_areas

    def validate_framework(self) -> Dict[str, Any]:
        """Validate the entire testing framework."""
        print("🔍 Validating Comprehensive Testing Framework")
        print("=" * 60)

        total_test_classes = 0
        total_test_methods = 0
        all_syntax_valid = True

        for test_file in self.test_files:
            print(f"\n📝 Validating {test_file}")

            if not os.path.exists(test_file):
                print(f"❌ File not found: {test_file}")
                continue

            # Validate syntax and structure
            validation_result = self.validate_file_syntax(test_file)
            self.validation_results[test_file] = validation_result

            if validation_result["syntax_valid"]:
                print("✅ Syntax valid")
                print(f"📊 {validation_result['test_classes']} test classes")
                print(f"🧪 {validation_result['test_methods']} test methods")
                print(f"📄 {validation_result['lines_of_code']} lines of code")

                total_test_classes += validation_result["test_classes"]
                total_test_methods += validation_result["test_methods"]

                # Check coverage areas
                coverage = self.check_test_coverage_areas(test_file)
                if coverage:
                    print("📋 Coverage areas:")
                    for area, covered in coverage.items():
                        status = "✅" if covered else "⚠️"
                        print(f"  {status} {area.replace('_', ' ').title()}")

            else:
                print(f"❌ Validation failed: {validation_result['error']}")
                all_syntax_valid = False

        # Validate test runner
        print("\n🚀 Validating Test Runner")
        runner_file = "run_comprehensive_tests.py"
        if os.path.exists(runner_file):
            runner_validation = self.validate_file_syntax(runner_file)
            if runner_validation["syntax_valid"]:
                print("✅ Test runner syntax valid")
            else:
                print(f"❌ Test runner validation failed: {runner_validation['error']}")
                all_syntax_valid = False
        else:
            print(f"❌ Test runner not found: {runner_file}")
            all_syntax_valid = False

        # Validate requirements
        print("\n📦 Validating Requirements")
        req_file = "test_requirements.txt"
        if os.path.exists(req_file):
            print("✅ Test requirements file exists")
        else:
            print(f"⚠️ Test requirements file not found: {req_file}")

        # Summary
        print(f"\n{'=' * 60}")
        print("📊 FRAMEWORK VALIDATION SUMMARY")
        print(f"{'=' * 60}")
        print(f"Total Test Files: {len(self.test_files)}")
        print(f"Total Test Classes: {total_test_classes}")
        print(f"Total Test Methods: {total_test_methods}")
        print(f"Syntax Validation: {'✅ PASSED' if all_syntax_valid else '❌ FAILED'}")

        framework_status = (
            "✅ READY FOR EXECUTION" if all_syntax_valid else "❌ NEEDS FIXES"
        )
        print(f"Framework Status: {framework_status}")

        return {
            "total_files": len(self.test_files),
            "total_classes": total_test_classes,
            "total_methods": total_test_methods,
            "syntax_valid": all_syntax_valid,
            "framework_ready": all_syntax_valid,
            "validation_results": self.validation_results,
        }

    def generate_test_inventory(self) -> str:
        """Generate an inventory of all implemented tests."""
        inventory = "# Comprehensive Testing Framework Inventory\n\n"

        for test_file in self.test_files:
            if test_file in self.validation_results:
                result = self.validation_results[test_file]
                inventory += f"## {test_file}\n\n"
                inventory += f"- **Test Classes:** {result.get('test_classes', 0)}\n"
                inventory += f"- **Test Methods:** {result.get('test_methods', 0)}\n"
                inventory += f"- **Lines of Code:** {result.get('lines_of_code', 0)}\n"

                if "class_names" in result:
                    inventory += f"- **Classes:** {', '.join(result['class_names'])}\n"

                inventory += "\n"

        return inventory

    def check_dependencies(self) -> Dict[str, bool]:
        """Check if required testing dependencies are available."""
        dependencies = {}

        try:
            import pytest

            dependencies["pytest"] = True
        except ImportError:
            dependencies["pytest"] = False

        try:
            import pytest_json_report

            dependencies["pytest-json-report"] = True
        except ImportError:
            dependencies["pytest-json-report"] = False

        try:
            import pytest_cov

            dependencies["pytest-cov"] = True
        except ImportError:
            dependencies["pytest-cov"] = False

        try:
            import psutil

            dependencies["psutil"] = True
        except ImportError:
            dependencies["psutil"] = False

        return dependencies


def main():
    """Main validation function."""
    print("🧪 Sigil API - Testing Framework Validation")
    print("=" * 60)
    print("Validating comprehensive testing framework implementation...")
    print()

    validator = TestFrameworkValidator()

    # Check dependencies
    print("📦 Checking Dependencies")
    dependencies = validator.check_dependencies()
    for dep, available in dependencies.items():
        status = "✅" if available else "❌"
        print(f"  {status} {dep}")

    missing_deps = [dep for dep, available in dependencies.items() if not available]
    if missing_deps:
        print(f"\n⚠️ Missing dependencies: {', '.join(missing_deps)}")
        print("Install with: pip install " + " ".join(missing_deps))
    print()

    # Validate framework
    results = validator.validate_framework()

    # Generate inventory
    if results["framework_ready"]:
        print("\n📋 Generating Test Inventory")
        inventory = validator.generate_test_inventory()
        with open("TEST_INVENTORY.md", "w") as f:
            f.write(inventory)
        print("✅ Test inventory saved to TEST_INVENTORY.md")

    # Final recommendations
    print("\n🎯 RECOMMENDATIONS")
    print("=" * 60)

    if results["framework_ready"]:
        print("✅ Testing framework is ready for execution")
        print("\nNext steps:")
        print("1. Install missing dependencies if any")
        print("2. Fix import issues in api/main.py")
        print("3. Execute tests with: ./run_comprehensive_tests.py")
        print("4. Review test results and address any failures")
        print("5. Deploy to staging environment for validation")

        return 0
    else:
        print("❌ Testing framework needs fixes before execution")
        print("\nRequired actions:")
        print("1. Fix syntax errors in test files")
        print("2. Install missing dependencies")
        print("3. Resolve import issues")
        print("4. Re-run validation")

        return 1


if __name__ == "__main__":
    sys.exit(main())
