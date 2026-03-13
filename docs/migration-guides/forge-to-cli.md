# Migration Guide: Forge Web UI to CLI Discovery

This guide helps you transition from the Forge web interface to CLI-based tool discovery commands.

## Quick Reference

| Forge Web Action | CLI Command | Example |
|------------------|-------------|---------|
| Search tools | `sigil search <query>` | `sigil search "nlp processing"` |
| Get tool details | `sigil info <ecosystem>/<name>` | `sigil info pypi/spacy` |
| Get recommendations | `sigil discover <use-case>` | `sigil discover "chatbot development"` |
| Browse categories | `sigil search <category>` | `sigil search "machine learning"` |
| Find trending | `sigil search trending` | `sigil search trending` |

## Detailed Migration Examples

### Tool Discovery Workflows

#### Example 1: Finding NLP Tools

**Before (Forge Web UI)**:
1. Open browser to Forge interface
2. Click "Categories" → "Natural Language Processing"
3. Browse through tool cards
4. Click on "spaCy" for details
5. Copy pip install command

**After (CLI)**:
```bash
# Search for NLP tools
sigil search "natural language processing"

# Output:
# Search Results for: natural language processing
# 
# • spacy (pypi) - Trust: 94%
#   Industrial-strength NLP with Python and Cython
#   Install: pip install spacy
# 
# • nltk (pypi) - Trust: 91%
#   Natural Language Toolkit for Python
#   Install: pip install nltk

# Get detailed info about a specific tool
sigil info pypi/spacy

# Output:
# # spacy (pypi)
# 
# **Trust Score**: 94%
# **Category**: Natural Language Processing
# **Last Updated**: 2026-03-10
# 
# ## Description
# Industrial-strength NLP with Python and Cython
# 
# ## Installation
# pip install spacy
# 
# ## Security Assessment
# Well-maintained package with strong security practices
```

#### Example 2: Building a Chatbot Stack

**Before (Forge Web UI)**:
1. Navigate to "Stack Builder"
2. Select "Chatbot Development" template
3. Review recommended tools
4. Customize stack with alternatives
5. Export installation script

**After (CLI)**:
```bash
# Get curated recommendations for chatbot development
sigil discover "chatbot development"

# Output:
# Recommended Stack for: chatbot development
# 
# ## Natural Language Processing
# • transformers (pypi) - Trust: 96%
#   State-of-the-art transformer models
#   Install: pip install transformers
#   Security: Well-maintained by Hugging Face team
# 
# ## Chat Interface
# • streamlit (pypi) - Trust: 89%
#   Create web apps for ML models
#   Install: pip install streamlit
#   Security: Active security monitoring
# 
# ## Vector Database
# • chromadb (pypi) - Trust: 85%
#   AI-native open-source embedding database
#   Install: pip install chromadb
#   Security: Regular security updates
# 
# Installation Summary:
# pip install transformers
# pip install streamlit  
# pip install chromadb
```

#### Example 3: Researching a Specific Tool

**Before (Forge Web UI)**:
1. Search for "langchain"
2. Click on LangChain result
3. Review trust score and metrics
4. Check security assessment
5. View dependencies and compatibility

**After (CLI)**:
```bash
# Get comprehensive information about LangChain
sigil info pypi/langchain

# Output:
# # langchain (pypi)
# 
# **Trust Score**: 87%
# **Category**: LLM Framework
# **Last Updated**: 2026-03-12
# 
# ## Description
# Building applications with LLMs through composability
# 
# ## Installation
# pip install langchain
# 
# ## Security Assessment
# Popular framework with active security monitoring.
# Large dependency tree requires careful vetting.
# 
# ## Security Findings
# • High number of dependencies (50+) increases attack surface
# • Some transitive dependencies lack recent security updates
# • Core package has good security practices
```

### Integration Workflows

#### Example 4: Scripted Tool Discovery

**Before (Forge Web UI)**:
Not easily scriptable - manual browsing only

**After (CLI)**:
```bash
#!/bin/bash
# Script to find and audit data science tools

echo "Finding data science tools..."
sigil search "data science" > ds_tools.txt

echo "Getting detailed info for pandas..."  
sigil info pypi/pandas > pandas_analysis.txt

echo "Getting ML stack recommendations..."
sigil discover "machine learning pipeline" > ml_stack.txt

echo "Discovery complete! Check output files."
```

#### Example 5: Team Tool Standardization

**Before (Forge Web UI)**:
Share links to specific tool pages

**After (CLI)**:
```bash
# team_tools.sh - Standard tool discovery for team
# Run this to get approved tools for different use cases

echo "=== APPROVED FRONTEND TOOLS ==="
sigil discover "react development"

echo "=== APPROVED BACKEND TOOLS ==="  
sigil discover "api development"

echo "=== APPROVED ML TOOLS ==="
sigil discover "machine learning"

echo "=== SECURITY SCANNING ==="
echo "All tools must be audited before use:"
echo "sigil scan <package> before installation"
```

## Advanced CLI Features

### Caching and Performance

The CLI includes intelligent caching for better performance:

```bash
# First search - hits API
sigil search "web scraping"

# Subsequent searches within 24h - uses cache
sigil search "web scraping"  # (cached result)
```

### Authentication for Enhanced Features

```bash
# Login for Pro features and personalized results
sigil login

# After authentication, get enhanced recommendations
sigil discover "enterprise chatbot"  # More detailed results
sigil info pypi/langchain           # Enhanced security analysis
```

### Integration with Existing Workflow

```bash
# Combine discovery with security auditing
discover_and_audit() {
    local use_case="$1"
    echo "Finding tools for: $use_case"
    sigil discover "$use_case"
    
    echo "Select a tool to audit:"
    read -p "Package name: " package
    
    echo "Downloading and auditing $package..."
    sigil pip "$package"
}

# Usage
discover_and_audit "web scraping"
```

## Feature Mapping

### Complete Feature Comparison

| Forge Web Feature | CLI Equivalent | Enhanced in CLI? |
|-------------------|----------------|------------------|
| Text search | `sigil search <query>` | ✅ Faster, cacheable |
| Category browsing | `sigil search <category>` | ✅ More flexible queries |
| Tool details | `sigil info <eco>/<name>` | ✅ Richer security data |
| Stack recommendations | `sigil discover <use-case>` | ✅ Context-aware suggestions |
| Trending tools | `sigil search trending` | ✅ Real-time data |
| User favorites | Shell aliases / scripts | ✅ More customizable |
| Tool comparison | Multiple `sigil info` calls | ⚠️ Manual comparison |
| Visual interface | Text output | ❌ No visual elements |
| Interactive filtering | Grep/awk commands | ✅ More powerful filtering |
| Export functionality | Shell redirection | ✅ Standard Unix tools |

### Limitations and Workarounds

1. **No Visual Interface**
   - *Workaround*: Use CLI output formatting and terminal colors
   - *Example*: `sigil search "ml" | less -R` for paged, colored output

2. **No Interactive Filtering**  
   - *Workaround*: Combine with standard Unix tools
   - *Example*: `sigil search "ml" | grep -i tensorflow`

3. **No Side-by-Side Comparison**
   - *Workaround*: Use multiple terminal windows/tabs
   - *Example*: `sigil info pypi/tensorflow & sigil info pypi/pytorch`

4. **No User Accounts/Preferences**
   - *Workaround*: Use shell aliases and scripts for personalization
   - *Example*: `alias mytools='sigil discover "my favorite stack"'`

## Shell Integration Tips

### Useful Aliases

Add to your `.bashrc` or `.zshrc`:

```bash
# Quick tool discovery aliases
alias findtools='sigil search'
alias toolinfo='sigil info'
alias getstack='sigil discover'
alias auditpkg='sigil pip'

# Common use case shortcuts
alias webtools='sigil discover "web development"'
alias mltools='sigil discover "machine learning"'
alias devtools='sigil discover "developer tools"'

# Combined discovery + audit workflow
discaud() { 
    sigil discover "$1" 
    echo "Use 'auditpkg <name>' to scan before installing"
}
```

### Output Processing

```bash
# Extract just package names
sigil search "ml" | grep "Install:" | awk '{print $3}'

# Get trust scores only  
sigil search "ml" | grep "Trust:" | awk '{print $3}'

# Format for requirements.txt
sigil discover "web scraping" | grep "pip install" | sed 's/pip install //' > requirements.txt
```

## Troubleshooting

### Common Migration Issues

1. **Missing authentication**
   ```bash
   # Error: "Failed to search tools"
   # Solution: Login for enhanced features
   sigil login
   ```

2. **No results for queries**
   ```bash
   # Try broader terms
   sigil search "ml" instead of "machine learning frameworks"
   ```

3. **Slow performance**
   ```bash
   # Check cache status
   ls ~/.sigil/cache/
   
   # Clear cache if needed
   rm ~/.sigil/cache/search_cache.json
   ```

4. **Missing tool information**
   ```bash
   # Use exact ecosystem/name format
   sigil info pypi/requests  # NOT just "requests"
   ```

## Support and Resources

- **CLI Reference**: `sigil help` for all available commands
- **Examples**: `sigil search --help` for command-specific help  
- **Feature Requests**: Submit issues for CLI enhancements
- **Archive Documentation**: [Forge Archive README](../archive/forge/README.md)
- **Technical Analysis**: [CLI Discovery Sunset Requirements](../build/features/cli-discovery-sunset-forge.prd.json)

## Feedback

The CLI discovery commands are actively improved based on user feedback. If you find workflows that were easier in the Forge web UI, please submit enhancement requests for CLI improvements.

---

*This migration guide will be updated as new CLI features are added to match or exceed Forge web functionality.*