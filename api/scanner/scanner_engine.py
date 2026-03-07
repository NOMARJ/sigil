"""
Enhanced Scanner Engine with Phase 9 LLM Support
Integrates static analysis (Phases 1-8) with AI-powered detection (Phase 9).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from models import Finding
from services.scanner import scan_directory, scan_content
from scanner.phase9_llm_detector import phase9_detector


logger = logging.getLogger(__name__)


class ScannerEngine:
    """Enhanced scanner with LLM-powered Pro features."""
    
    def __init__(self):
        self.include_llm_analysis = False
    
    async def scan_with_pro_features(
        self, 
        path: str | Path | None = None, 
        content: str | None = None,
        filename: str = "<stdin>",
        repository_context: dict[str, Any] | None = None,
        user_tier: str = "FREE"
    ) -> list[Finding]:
        """
        Perform comprehensive scan with optional LLM analysis for Pro users.
        
        Args:
            path: Directory path to scan (mutually exclusive with content)
            content: Raw content to scan (mutually exclusive with path)
            filename: Filename when scanning content directly
            repository_context: Additional context about the repository
            user_tier: User subscription tier (FREE, PRO, TEAM, ENTERPRISE)
        
        Returns:
            List of all findings from static and LLM analysis
        """
        all_findings = []
        
        # Phase 1-8: Static analysis (always performed)
        if path:
            logger.info(f"Starting static analysis on directory: {path}")
            static_findings = scan_directory(path)
        elif content:
            logger.info(f"Starting static analysis on content: {filename}")
            static_findings = scan_content(content, filename)
        else:
            raise ValueError("Either path or content must be provided")
        
        all_findings.extend(static_findings)
        
        logger.info(f"Static analysis completed: {len(static_findings)} findings")
        
        # Phase 9: LLM analysis (Pro tier and above only)
        if user_tier in ("PRO", "TEAM", "ENTERPRISE"):
            try:
                # Collect file contents for LLM analysis
                file_contents = {}
                
                if path:
                    file_contents = await self._collect_file_contents(Path(path))
                elif content:
                    file_contents = {filename: content}
                
                if file_contents:
                    logger.info(f"Starting LLM analysis for {user_tier} user")
                    llm_findings = await phase9_detector.scan_with_llm(
                        file_contents=file_contents,
                        static_findings=static_findings,
                        repository_context=repository_context
                    )
                    
                    all_findings.extend(llm_findings)
                    logger.info(f"LLM analysis completed: {len(llm_findings)} additional findings")
                else:
                    logger.warning("No file contents available for LLM analysis")
                    
            except Exception as e:
                logger.exception(f"LLM analysis failed for {user_tier} user: {e}")
                # Continue without LLM analysis - don't fail the entire scan
        else:
            logger.debug(f"Skipping LLM analysis for {user_tier} user")
        
        logger.info(f"Total scan completed: {len(all_findings)} findings across all phases")
        return all_findings
    
    async def _collect_file_contents(self, root_path: Path, max_files: int = 50) -> dict[str, str]:
        """
        Collect file contents for LLM analysis.
        
        Args:
            root_path: Root directory to scan
            max_files: Maximum number of files to include (cost control)
        
        Returns:
            Dictionary mapping relative file paths to their contents
        """
        file_contents = {}
        files_collected = 0
        
        # Text file extensions that are safe to read
        text_extensions = {
            ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml",
            ".toml", ".cfg", ".ini", ".sh", ".bash", ".md", ".txt", ".html",
            ".css", ".scss", ".xml", ".env", ".lock", ".conf", ".rb", ".go",
            ".rs", ".java", ".c", ".h", ".cpp", ".hpp", ".cs", ".php"
        }
        
        try:
            for file_path in self._walk_files(root_path):
                if files_collected >= max_files:
                    logger.info(f"Reached max file limit ({max_files}) for LLM analysis")
                    break
                
                # Only include text files under reasonable size
                if (file_path.suffix in text_extensions and 
                    file_path.stat().st_size < 100_000):  # 100KB limit per file
                    
                    try:
                        content = file_path.read_text(errors="replace")
                        relative_path = str(file_path.relative_to(root_path))
                        file_contents[relative_path] = content
                        files_collected += 1
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Failed to read {file_path}: {e}")
                        continue
                
                # Also include package.json, setup.py, requirements.txt etc. even if no extension
                elif (file_path.name in {"package.json", "setup.py", "requirements.txt", 
                                       "Makefile", "Dockerfile", "pyproject.toml"} and
                      file_path.stat().st_size < 50_000):
                    try:
                        content = file_path.read_text(errors="replace")
                        relative_path = str(file_path.relative_to(root_path))
                        file_contents[relative_path] = content
                        files_collected += 1
                    except (OSError, PermissionError) as e:
                        logger.warning(f"Failed to read {file_path}: {e}")
                        continue
        
        except Exception as e:
            logger.exception(f"Error collecting file contents: {e}")
        
        logger.info(f"Collected {files_collected} files for LLM analysis")
        return file_contents
    
    def _walk_files(self, root: Path):
        """Walk files, skipping common noise directories."""
        skip_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", "build", "dist", ".next", "coverage"
        }
        
        for child in sorted(root.iterdir()):
            if child.name in skip_dirs:
                continue
            if child.is_file():
                yield child
            elif child.is_dir():
                yield from self._walk_files(child)


# Global scanner engine instance
scanner_engine = ScannerEngine()