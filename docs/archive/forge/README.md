# Forge Web UI Archive Documentation

**Archive Date**: March 13, 2026  
**Reason**: CLI discovery commands replace Forge web UI functionality  
**Status**: Archived (can be restored if needed)

## Overview

The Sigil Forge web interface has been archived and replaced with CLI-based discovery commands. This change simplifies the architecture while maintaining all core discovery functionality through the command line.

## What Was Removed

### Web Interface Components
- **Forge Web UI**: Interactive tool discovery and curation interface
- **Tool Directory**: Web-based browsing of AI tools and packages
- **Stack Builder**: Visual tool stack composition interface
- **Analytics Dashboard**: Web-based usage metrics and trending tools
- **User Profiles**: Web account management for tool preferences

### API Endpoints Removed
- `GET /forge/search` - Tool search functionality
- `GET /forge/categories` - Category browsing
- `GET /forge/tools/{ecosystem}/{name}` - Tool details
- `GET /forge/stack` - Stack recommendations
- `GET /forge/trending` - Trending tools
- `POST /forge/stacks` - Custom stack creation
- `PUT /forge/user/preferences` - User preference management

### Database Components Archived
- **forge_classification** - Tool classification data (11 tables total)
- **forge_categories** - Category taxonomy
- **forge_capabilities** - Package capabilities
- **forge_user_tools** - User tool tracking
- **forge_analytics_events** - Usage analytics
- See [complete list](../../../archive/FORGE_ARCHIVAL_README.md) for full details

## Why This Change Was Made

### First Principles Analysis

1. **Developer Workflow Alignment**
   - Developers primarily work in terminals, not web interfaces
   - CLI discovery integrates directly into existing workflows
   - Reduces context switching between terminal and browser

2. **Simplified Architecture** 
   - Eliminates complex web UI state management
   - Reduces maintenance burden of frontend/backend coordination
   - Focuses engineering resources on core security functionality

3. **Enhanced Developer Experience**
   - Faster tool discovery through CLI commands
   - Better integration with shell scripts and automation
   - Consistent UX with existing Sigil CLI commands

4. **Resource Optimization**
   - Removes overhead of web UI infrastructure
   - Reduces API surface area and attack vectors
   - Simplifies deployment and scaling requirements

### Decision Timeline

- **March 10, 2026**: [First principles analysis completed](../../build/features/cli-discovery-sunset-forge.prd.json)
- **March 11, 2026**: CLI discovery commands implemented
- **March 12, 2026**: User testing and feedback integration
- **March 13, 2026**: Forge web UI archived and removed

## CLI Replacement Commands

All Forge web functionality is now available through CLI commands:

| Forge Web Feature | CLI Command | Description |
|-------------------|-------------|-------------|
| Tool Search | `sigil search <query>` | Search for AI tools and packages |
| Tool Information | `sigil info <ecosystem>/<name>` | Get detailed tool information |
| Stack Recommendations | `sigil discover <use-case>` | Get curated tool stacks for use cases |
| Category Browsing | `sigil search <category>` | Search by tool category |
| Trending Tools | `sigil search trending` | Find popular/trending tools |

## Migration Guide

### For End Users

**Before (Forge Web UI)**:
1. Open web browser
2. Navigate to Forge interface
3. Search for tools visually
4. Click through tool details
5. Copy install commands

**After (CLI Discovery)**:
```bash
# Search for tools
sigil search "web scraping"

# Get detailed information
sigil info pypi/scrapy

# Get stack recommendations
sigil discover "data analysis pipeline"
```

### For Developers/Integrations

**API Calls** → **CLI Commands**:
```bash
# Replace API calls with CLI equivalents
# Old: curl /forge/search?q=nlp
# New: sigil search nlp

# Old: curl /forge/tools/pypi/transformers  
# New: sigil info pypi/transformers

# Old: curl /forge/stack?use_case="chatbot"
# New: sigil discover "chatbot development"
```

## Restoration Instructions

If restoration is needed, all components are preserved:

### 1. Database Restoration
```bash
cd archive/scripts
sqlcmd -S <server> -d sigil -U <user> -i restore_forge_database.sql
```

### 2. API Restoration
```bash
cp archive/routers/* api/routers/
cp archive/services/* api/services/
cp archive/security/* api/security/
```

### 3. Configuration Restoration
- Restore Forge router imports in `api/main.py`
- Add route registrations back
- Update OpenAPI documentation

### 4. Frontend Restoration
```bash
# Restore from version control
git checkout <pre-archive-commit> -- dashboard/forge/
```

## Impact Assessment

### ✅ Maintained Functionality
- Tool discovery and search
- Detailed tool information
- Security analysis and ratings
- Use case recommendations
- Category-based browsing

### ❌ Removed Functionality
- Visual web interface
- Interactive stack building
- User accounts and preferences
- Web-based analytics dashboard
- Social features (favorites, sharing)

### 🔄 Enhanced Functionality
- Faster command-line discovery
- Better shell integration
- Scriptable discovery workflows
- Reduced latency (no web requests)

## Frequently Asked Questions

**Q: Can I still discover AI tools?**  
A: Yes, all discovery functionality is available through CLI commands with better performance.

**Q: What about my saved tool preferences?**  
A: User preferences are archived. Consider using shell aliases for frequently used searches.

**Q: How do I browse tools by category?**  
A: Use `sigil search <category>` or `sigil discover <use-case>` for targeted results.

**Q: Can this decision be reversed?**  
A: Yes, all components are safely archived and can be restored if needed.

**Q: What about team collaboration features?**  
A: Focus shifted to CLI-based workflows. Consider sharing discovery commands in team documentation.

## Support

For questions about this transition:

1. **Check CLI Help**: `sigil help` for available commands
2. **Migration Issues**: See [migration guide](../../migration-guides/forge-to-cli.md)
3. **Feature Requests**: Submit CLI enhancement requests
4. **Restoration**: Use archived components if web UI is needed

## Related Documentation

- [CLI Discovery Commands Guide](../../cli.md)
- [Migration from Forge to CLI](../../migration-guides/forge-to-cli.md)
- [Complete Archive Details](../../../archive/FORGE_ARCHIVAL_README.md)
- [Requirements Analysis](../../build/features/cli-discovery-sunset-forge.prd.json)
- [User Stories & Acceptance Criteria](../../build/features/cli-discovery-sunset-forge.prd.json)

---

*This archive preserves all Forge functionality while improving developer experience through CLI-first discovery.*