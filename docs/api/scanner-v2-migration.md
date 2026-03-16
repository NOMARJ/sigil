# Scanner v2 Migration Guide

## Overview

Sigil Scanner v2 introduces significant improvements to reduce false positive rates from 36% to under 5% through context-aware analysis and confidence scoring.

## What's New in Scanner v2

### Key Improvements
- **85% reduction in false positives** through context-aware pattern matching
- **Confidence scoring** for every finding (HIGH/MEDIUM/LOW)
- **File context analysis** - documentation and test files receive adjusted severity
- **Smart domain filtering** - legitimate API calls no longer flagged as suspicious
- **Enhanced obfuscation detection** with benign pattern recognition

### New API Fields

#### Scan Response
```json
{
  "scanner_version": "2.0.0",
  "confidence_summary": {
    "overall_confidence": "HIGH",
    "high_confidence_findings": 2,
    "medium_confidence_findings": 1,
    "low_confidence_findings": 0,
    "false_positive_likelihood": 0.04
  },
  "findings": [
    {
      "rule": "code-eval-usage",
      "severity": "high",
      "confidence": "HIGH",
      "context_adjusted": false,
      // ... other fields
    }
  ]
}
```

## Migration Path

### For API Consumers

1. **No immediate action required** - Existing `/v1/scan` endpoint continues to work
2. **Opt-in to v2** - Use `/v1/scan/v2` endpoint for enhanced scanning
3. **Update your integration** when ready to handle new fields:
   - `scanner_version` - Track which scanner was used
   - `confidence_summary` - Overall confidence metrics
   - `findings[].confidence` - Per-finding confidence level

### For Existing Scans

Refresh legacy scans with the enhanced scanner:

```bash
# Rescan a single package
curl -X POST https://api.sigilsec.com/api/rescan/{scan_id} \
  -H "X-API-Key: your-key"

# Batch rescan up to 20 packages
curl -X POST https://api.sigilsec.com/api/rescan/batch \
  -H "X-API-Key: your-key" \
  -H "Content-Type: application/json" \
  -d '{"scan_ids": ["id1", "id2", "id3"]}'
```

## Understanding Confidence Levels

### Overall Confidence
- **HIGH**: Strong indicators, minimal context ambiguity
- **MEDIUM**: Some uncertainty, may need review
- **LOW**: Likely benign, often in tests/docs

### False Positive Likelihood
A decimal value (0.0-1.0) estimating the probability that findings are false positives:
- `< 0.05` - Very reliable (< 5% false positive rate)
- `0.05-0.15` - Good reliability
- `0.15-0.35` - Moderate reliability  
- `> 0.35` - Review recommended

## Context-Aware Analysis

Scanner v2 automatically adjusts severity based on file context:

### Documentation Files
Files in `docs/`, `README.md`, `*.md`:
- Severity reduced by 2 levels
- Code examples not treated as executable threats

### Test Files  
Files in `test/`, `spec/`, `*_test.py`:
- Severity reduced by 1 level
- Test patterns recognized as non-production

### Safe Domains
API calls to legitimate services are not flagged:
- Anthropic (claude.ai)
- OpenAI (openai.com)
- GitHub (github.com)
- AWS services
- Major cloud providers

## Metrics Endpoint

Track migration progress and compare scanner performance:

```bash
curl https://api.sigilsec.com/api/metrics/scanner \
  -H "X-API-Key: your-key"
```

Response:
```json
{
  "v1_stats": {
    "total_scans": 45000,
    "avg_risk_score": 42.3,
    "false_positive_rate": 0.36
  },
  "v2_stats": {
    "total_scans": 12000,
    "avg_risk_score": 28.7,
    "false_positive_rate": 0.048,
    "avg_confidence": 0.82
  },
  "migration_progress": {
    "percentage_complete": 26.7,
    "rescans_completed": 12000,
    "avg_score_reduction": 32.1
  }
}
```

## Best Practices

1. **Start with high-risk packages** - Rescan packages with scores > 50 first
2. **Monitor false positive rates** - Use metrics endpoint to validate improvements
3. **Review LOW confidence findings** - These are most likely to be false positives
4. **Update gradually** - No need to rescan everything at once

## Environment Variables

Control scanner behavior via environment variables:

```bash
# Force specific scanner version
SCANNER_VERSION=2.0.0

# Enable v1 fallback (for rollback)
SCANNER_V1_ENABLED=true

# Enable specific v2 features
SCANNER_V2_FEATURES=confidence,context
```

## Support

For questions about the migration:
- API Documentation: https://api.sigilsec.com/docs
- Support: support@sigilsec.com
- GitHub Issues: https://github.com/sigilsec/sigil/issues