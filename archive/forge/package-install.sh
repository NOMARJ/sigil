#!/bin/bash

# Sigil Forge Frontend Installation Script
set -e

echo "🔧 Installing Sigil Forge Frontend..."

# Check Node.js version
NODE_VERSION=$(node --version | cut -d'.' -f1 | sed 's/v//')
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js 18.0.0 or later is required. Current version: $(node --version)"
    echo "Please upgrade Node.js and try again."
    exit 1
fi

echo "✅ Node.js version check passed: $(node --version)"

# Install dependencies
echo "📦 Installing dependencies..."
npm install

# Install additional Tailwind plugins
echo "🎨 Installing Tailwind CSS plugins..."
npm install @tailwindcss/forms @tailwindcss/typography

# Copy environment file if it doesn't exist
if [ ! -f ".env.local" ]; then
    echo "📝 Creating environment configuration..."
    cp .env.example .env.local
    echo "⚠️  Please update .env.local with your API configuration"
fi

echo "🧪 Running type check..."
npm run type-check

echo "🎉 Installation complete!"
echo ""
echo "Next steps:"
echo "1. Update .env.local with your API configuration"
echo "2. Start the development server: npm run dev"
echo "3. Open http://localhost:3001 in your browser"
echo ""
echo "For more information, see README.md"