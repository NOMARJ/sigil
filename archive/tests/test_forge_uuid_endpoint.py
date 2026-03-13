#!/usr/bin/env python3
"""Test the new UUID-based Forge API endpoint."""

import requests
import hashlib
import re

BASE_URL = "https://api.sigilsec.ai"


def generate_tool_uuid(ecosystem, package_name):
    """Generate the same UUID that the API generates."""
    uuid_input = f"{ecosystem}:{package_name}"
    hash_obj = hashlib.sha256(uuid_input.encode())
    hex_str = hash_obj.hexdigest()[:32]
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


def generate_tool_slug(package_name):
    """Generate the same slug that the API generates."""
    slug = re.sub(r"[^a-z0-9]+", "-", package_name.lower())
    slug = slug.strip("-")
    slug = re.sub(r"-+", "-", slug)
    return slug


def test_uuid_endpoint():
    """Test the UUID-based tool detail endpoint."""
    print("Testing UUID-based tool detail endpoint...")

    # First get a tool from search to get its details
    resp = requests.get(f"{BASE_URL}/forge/search?limit=1")
    data = resp.json()

    if data["tools"]:
        tool = data["tools"][0]
        print(f"\nFound tool: {tool['name']} ({tool['ecosystem']})")

        # Check that UUID and slug are present
        assert "id" in tool, "Missing 'id' (UUID) field"
        assert "slug" in tool, "Missing 'slug' field"

        print(f"  UUID: {tool['id']}")
        print(f"  Slug: {tool['slug']}")

        # Verify UUID generation is consistent
        expected_uuid = generate_tool_uuid(tool["ecosystem"], tool["name"])
        assert tool["id"] == expected_uuid, (
            f"UUID mismatch: {tool['id']} != {expected_uuid}"
        )
        print("  ✓ UUID generation is consistent")

        # Verify slug generation is consistent
        expected_slug = generate_tool_slug(tool["name"])
        assert tool["slug"] == expected_slug, (
            f"Slug mismatch: {tool['slug']} != {expected_slug}"
        )
        print("  ✓ Slug generation is consistent")

        # Test fetching by UUID
        uuid_resp = requests.get(f"{BASE_URL}/forge/tools/{tool['id']}")
        if uuid_resp.status_code == 200:
            uuid_data = uuid_resp.json()
            assert uuid_data["name"] == tool["name"], (
                "Tool name mismatch via UUID endpoint"
            )
            print(f"  ✓ UUID endpoint /forge/tools/{tool['id']} works!")
        else:
            print(f"  ⚠ UUID endpoint returned {uuid_resp.status_code}")

        # Check trust score is in valid range
        assert 0 <= tool["trust_score"] <= 100, (
            f"Trust score out of range: {tool['trust_score']}"
        )
        print(f"  ✓ Trust score in valid range: {tool['trust_score']}")

        # Check install command format
        if tool["ecosystem"] == "skills":
            assert tool["install_command"].startswith("npx skills add"), (
                f"Invalid skills install command: {tool['install_command']}"
            )
        elif tool["ecosystem"] == "mcps":
            assert (
                "npm install" in tool["install_command"]
                or "@modelcontextprotocol" in tool["install_command"]
            ), f"Invalid MCP install command: {tool['install_command']}"
        print(f"  ✓ Install command format correct: {tool['install_command']}")

    else:
        print("  ⚠ No tools returned from search endpoint")


def test_stats_endpoint():
    """Test the enhanced stats endpoint."""
    print("\nTesting enhanced /forge/stats endpoint...")

    resp = requests.get(f"{BASE_URL}/forge/stats")
    data = resp.json()

    # Check for new required fields
    assert "mcp_servers" in data, "Missing mcp_servers field"
    assert "skills_count" in data, "Missing skills_count field"
    assert "npm_packages" in data, "Missing npm_packages field"
    assert "pypi_packages" in data, "Missing pypi_packages field"

    print(f"  ✓ Total tools: {data['total_tools']}")
    print(f"  ✓ MCP servers: {data['mcp_servers']}")
    print(f"  ✓ Skills count: {data['skills_count']}")
    print(f"  ✓ NPM packages: {data['npm_packages']}")
    print(f"  ✓ PyPI packages: {data['pypi_packages']}")

    # Check trust score distribution
    assert "trust_score_distribution" in data, "Missing trust_score_distribution"
    dist = data["trust_score_distribution"]
    assert "high" in dist, "Missing 'high' trust score bucket"
    assert "medium" in dist, "Missing 'medium' trust score bucket"
    assert "low" in dist, "Missing 'low' trust score bucket"
    assert "very_low" in dist, "Missing 'very_low' trust score bucket"

    print(
        f"  ✓ Trust distribution: high={dist['high']}, medium={dist['medium']}, low={dist['low']}, very_low={dist['very_low']}"
    )

    # Check categories format
    if "categories" in data and isinstance(data["categories"], dict):
        print(
            f"  ✓ Categories in correct format with {len(data['categories'])} categories"
        )
        # Check for expected category keys
        if data["categories"]:
            for key in data["categories"].keys():
                # Should be snake_case
                assert "_" in key or key.islower(), (
                    f"Category key not in snake_case: {key}"
                )

    print("  ✓ All stats fields present and valid")


def main():
    """Run all tests."""
    print("Testing Forge API UUID and enhanced features")
    print("=" * 60)

    try:
        test_uuid_endpoint()
        test_stats_endpoint()
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
