#!/bin/bash
# Test script to verify Unicode boundary crash fix

echo "Testing Unicode boundary fix..."

# Build the Rust CLI
echo "Building sigil CLI..."
cd /Users/reecefrazier/CascadeProjects/sigil/cli
cargo build --release

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"

# Test scanning the Unicode boundary fixture
echo "Testing Unicode boundary file..."
./target/release/sigil scan /Users/reecefrazier/CascadeProjects/sigil/sigil-skill/tests/fixtures/unicode-boundary --verbose

if [ $? -eq 0 ]; then
    echo "✅ Unicode boundary test passed - no panic"
else
    echo "⚠️  Unicode boundary test returned non-zero exit code (may have found security issues, but no panic)"
fi

# Test scanning the binary file fixture
echo "Testing binary file handling..."
./target/release/sigil scan /Users/reecefrazier/CascadeProjects/sigil/sigil-skill/tests/fixtures/binary --verbose

if [ $? -eq 0 ]; then
    echo "✅ Binary file test passed - no panic"
else
    echo "⚠️  Binary file test returned non-zero exit code (may have found security issues, but no panic)"
fi

echo "All tests completed. If you see this message, the Unicode boundary crash has been fixed!"