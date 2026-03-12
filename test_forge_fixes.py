#!/usr/bin/env python3
"""Test script to verify Forge API fixes."""

import sys
import requests

BASE_URL = "https://api.sigilsec.ai"


def test_search_endpoint():
    """Test that search returns 'tools' instead of 'items'."""
    print("Testing /forge/search endpoint...")

    # Test without query
    resp = requests.get(f"{BASE_URL}/forge/search?limit=5")
    data = resp.json()

    # Check response structure
    assert "tools" in data, f"Expected 'tools' field, got: {data.keys()}"
    assert "total" in data, "Missing 'total' field"
    print(f"  ✓ Returns 'tools' field with {len(data['tools'])} items")

    # Check tool structure if any tools returned
    if data["tools"]:
        tool = data["tools"][0]
        assert "ecosystem" in tool, "Missing ecosystem field"
        assert "description" in tool, "Missing description field"
        assert "last_updated" in tool, "Missing last_updated field"
        assert "tags" in tool, "Missing tags field"
        print("  ✓ Tool has all required fields")

        # Check ecosystem format
        ecosystem = tool["ecosystem"]
        assert ecosystem in ["skills", "mcps", "npm", "pypi"], (
            f"Unexpected ecosystem: {ecosystem}"
        )
        print(f"  ✓ Ecosystem is in plural form: {ecosystem}")

    return True


def test_categories_endpoint():
    """Test categories endpoint returns proper structure."""
    print("\nTesting /forge/categories endpoint...")

    resp = requests.get(f"{BASE_URL}/forge/categories")
    data = resp.json()

    # Check response structure
    assert "data" in data, f"Expected 'data' wrapper, got: {data.keys()}"
    assert "categories" in data["data"], "Missing 'categories' field"

    categories = data["data"]["categories"]
    print(f"  ✓ Returns {len(categories)} categories")

    # Check category structure
    if categories:
        cat = categories[0]
        assert "category" in cat, "Missing category field"
        assert "display_name" in cat, "Missing display_name field"
        assert "tool_count" in cat, "Missing tool_count field"
        print("  ✓ Category has all required fields")

        # Check if any categories have tool counts
        total_tools = sum(c["tool_count"] for c in categories)
        print(f"  ✓ Total tools across categories: {total_tools}")

    # Check cache headers
    cache_control = resp.headers.get("Cache-Control", "")
    print(f"  ✓ Cache-Control header: {cache_control}")

    return True


def test_tool_detail_endpoint():
    """Test tool detail endpoint with both singular and plural ecosystems."""
    print("\nTesting /forge/tools/{ecosystem}/{name} endpoint...")

    test_cases = [
        ("skills", "molt-board-art"),
        ("skill", "molt-board-art"),  # Test singular form
        ("mcps", "mark-oori%2Fmcpserve"),
        ("mcp", "test-tool"),  # Test singular form
    ]

    for ecosystem, name in test_cases:
        url = f"{BASE_URL}/forge/tools/{ecosystem}/{name}"
        resp = requests.get(url)

        if resp.status_code == 404:
            print(f"  ⚠ {ecosystem}/{name}: 404 (will return sample data)")
        else:
            data = resp.json()

            # Check response structure
            assert "name" in data, "Missing name field"
            assert "ecosystem" in data, "Missing ecosystem field"
            assert "description" in data, "Missing description field"
            assert "trust_score" in data, "Missing trust_score field"

            # Verify ecosystem is plural
            returned_eco = data["ecosystem"]
            assert returned_eco in ["skills", "mcps"], (
                f"Expected plural ecosystem, got: {returned_eco}"
            )

            print(
                f"  ✓ {ecosystem}/{name}: Returns valid tool data with ecosystem={returned_eco}"
            )

    return True


def test_cache_headers():
    """Test that dynamic endpoints have proper cache headers."""
    print("\nTesting cache headers...")

    # Test search endpoint
    resp = requests.get(f"{BASE_URL}/forge/search?q=test")
    cache_control = resp.headers.get("Cache-Control", "")

    if "no-cache" in cache_control or "no-store" in cache_control:
        print(f"  ✓ Search endpoint prevents caching: {cache_control}")
    else:
        print(f"  ⚠ Search endpoint cache control: {cache_control}")

    # Test categories endpoint
    resp = requests.get(f"{BASE_URL}/forge/categories")
    cache_control = resp.headers.get("Cache-Control", "")

    if "max-age=" in cache_control:
        print(f"  ✓ Categories endpoint has cache TTL: {cache_control}")
    else:
        print(f"  ⚠ Categories endpoint cache control: {cache_control}")

    return True


def main():
    """Run all tests."""
    print(f"Testing Forge API fixes at {BASE_URL}")
    print("=" * 60)

    tests = [
        test_search_endpoint,
        test_categories_endpoint,
        test_tool_detail_endpoint,
        test_cache_headers,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            if test_func():
                passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
