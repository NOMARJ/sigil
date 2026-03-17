"""
Scanner Selector Service

Provides version-aware scanner selection and fallback logic
for progressive migration from Scanner v1 to v2.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Dict, Any

from api.config import settings
from api.models import Finding

logger = logging.getLogger(__name__)


def get_active_scanner_version() -> str:
    """Get the currently active scanner version from configuration."""
    return settings.scanner_version


def is_scanner_v1_enabled() -> bool:
    """Check if Scanner v1 fallback is enabled."""
    return settings.scanner_v1_enabled


def is_scanner_v2_enabled() -> bool:
    """Check if Scanner v2 is enabled."""
    return settings.scanner_version.startswith("2.") and settings.scanner_v2_features


def should_use_v2_features() -> bool:
    """Check if v2 enhanced features should be used."""
    return is_scanner_v2_enabled() and settings.scanner_v2_features


async def scan_with_version(directory: str, version: Optional[str] = None) -> List[Finding]:
    """
    Scan a directory with the specified scanner version.
    
    Args:
        directory: Directory to scan
        version: Scanner version to use (None for auto-detection)
    
    Returns:
        List of findings from the scan
    """
    effective_version = version or get_active_scanner_version()
    
    logger.debug("Scanning %s with scanner version %s", directory, effective_version)
    
    if effective_version.startswith("2."):
        return await _scan_with_v2(directory)
    else:
        return await _scan_with_v1(directory)


async def _scan_with_v2(directory: str) -> List[Finding]:
    """Scan directory with Scanner v2 (enhanced false positive reduction)."""
    try:
        from api.services.scanner import scan_directory
        
        # Use the enhanced scanner that already includes v2 improvements
        findings = scan_directory(directory)
        
        logger.debug("Scanner v2 produced %d findings for %s", len(findings), directory)
        return findings
        
    except Exception as e:
        logger.warning("Scanner v2 failed for %s: %s", directory, e)
        
        # Fallback to v1 if enabled
        if is_scanner_v1_enabled():
            logger.info("Falling back to Scanner v1 for %s", directory)
            return await _scan_with_v1(directory)
        else:
            raise


async def _scan_with_v1(directory: str) -> List[Finding]:
    """Scan directory with Scanner v1 (legacy scanner)."""
    try:
        # Use the v1 scanner implementation
        from api.services.scanner_v1 import scan_directory_v1
        
        findings = scan_directory_v1(directory)
        
        logger.debug("Scanner v1 produced %d findings for %s", len(findings), directory)
        return findings
        
    except ImportError:
        # v1 scanner not available, try fallback to current scanner
        logger.warning("Scanner v1 not available, using current scanner")
        from api.services.scanner import scan_directory
        return scan_directory(directory)
    except Exception as e:
        logger.error("Scanner v1 failed for %s: %s", directory, e)
        raise


def get_scanner_capabilities() -> Dict[str, Any]:
    """Get current scanner capabilities and configuration."""
    active_version = get_active_scanner_version()
    
    capabilities = {
        "active_version": active_version,
        "v1_enabled": is_scanner_v1_enabled(),
        "v2_enabled": is_scanner_v2_enabled(),
        "v2_features": should_use_v2_features(),
        "features": {
            "basic_scanning": True,
            "threat_intelligence": True,
            "scoring": True,
        }
    }
    
    if should_use_v2_features():
        capabilities["features"].update({
            "confidence_scoring": True,
            "false_positive_reduction": True,
            "context_aware_analysis": True,
            "domain_allowlists": True,
            "file_type_awareness": True,
        })
    
    return capabilities


def validate_scanner_configuration() -> Dict[str, Any]:
    """
    Validate current scanner configuration and return status.
    
    Returns:
        Dictionary with validation results and recommendations
    """
    issues = []
    warnings = []
    
    active_version = get_active_scanner_version()
    
    # Check version format
    if not (active_version.startswith("1.") or active_version.startswith("2.")):
        issues.append(f"Invalid scanner version format: {active_version}")
    
    # Check v2 availability
    if active_version.startswith("2."):
        try:
            from api.services.scanner_v2 import calculate_confidence_summary  # noqa: F401
            # Test v2 features
        except ImportError:
            issues.append("Scanner v2 requested but v2 modules not available")
    
    # Check v1 fallback
    if is_scanner_v1_enabled():
        try:
            from api.services.scanner_v1 import scan_directory_v1  # noqa: F401
        except ImportError:
            warnings.append("Scanner v1 fallback enabled but v1 module not available")
    
    # Check configuration consistency
    if active_version.startswith("1.") and settings.scanner_v2_features:
        warnings.append("Scanner v1 active but v2 features enabled - features will be ignored")
    
    return {
        "valid": len(issues) == 0,
        "active_version": active_version,
        "issues": issues,
        "warnings": warnings,
        "capabilities": get_scanner_capabilities(),
    }