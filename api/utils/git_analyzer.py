"""
Git Analyzer Utility
Analyzes git history for security-relevant changes and blame information
"""

from __future__ import annotations

import subprocess
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class GitAnalyzer:
    """Analyzes git repositories for security insights"""

    async def get_blame_for_line(
        self,
        repo_path: str,
        file_path: str,
        line_number: int
    ) -> Optional[Dict[str, Any]]:
        """
        Get git blame information for a specific line.
        
        Args:
            repo_path: Repository root path
            file_path: File path relative to repo
            line_number: Line number to blame
            
        Returns:
            Blame info with author, commit, and timestamp
        """
        try:
            # Ensure we're in the repo directory
            repo = Path(repo_path)
            file = repo / file_path
            
            if not file.exists():
                logger.warning(f"File not found: {file}")
                return None
            
            # Run git blame
            cmd = [
                'git', '-C', str(repo),
                'blame', '-L', f'{line_number},{line_number}',
                '--porcelain', str(file_path)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Git blame failed: {result.stderr}")
                return None
            
            # Parse porcelain output
            lines = result.stdout.strip().split('\n')
            blame_info = {}
            
            for line in lines:
                if line.startswith('author '):
                    blame_info['author'] = line.replace('author ', '')
                elif line.startswith('author-time '):
                    timestamp = int(line.replace('author-time ', ''))
                    blame_info['timestamp'] = datetime.fromtimestamp(timestamp)
                elif line.startswith('summary '):
                    blame_info['commit_message'] = line.replace('summary ', '')
                elif len(line) == 40:  # Commit hash
                    blame_info['commit'] = line[:8]
            
            return blame_info if 'author' in blame_info else None
            
        except subprocess.TimeoutExpired:
            logger.error("Git blame timed out")
            return None
        except Exception as e:
            logger.error(f"Failed to get blame: {e}")
            return None

    async def get_recent_commits(
        self,
        repo_path: str,
        num_commits: int = 10,
        branch: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get recent commits from repository.
        
        Args:
            repo_path: Repository root path
            num_commits: Number of commits to retrieve
            branch: Optional branch name
            
        Returns:
            List of commit information
        """
        try:
            cmd = [
                'git', '-C', repo_path,
                'log', f'-{num_commits}',
                '--pretty=format:%H|%an|%ae|%at|%s'
            ]
            
            if branch:
                cmd.append(branch)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Git log failed: {result.stderr}")
                return []
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('|')
                    if len(parts) >= 5:
                        commits.append({
                            'hash': parts[0],
                            'author': parts[1],
                            'email': parts[2],
                            'date': datetime.fromtimestamp(int(parts[3])).isoformat(),
                            'message': '|'.join(parts[4:])  # Message might contain |
                        })
            
            return commits
            
        except Exception as e:
            logger.error(f"Failed to get commits: {e}")
            return []

    async def get_changed_files(
        self,
        repo_path: str,
        base_ref: str,
        compare_ref: str
    ) -> List[Dict[str, str]]:
        """
        Get files changed between two refs.
        
        Args:
            repo_path: Repository root path
            base_ref: Base commit/branch
            compare_ref: Compare commit/branch
            
        Returns:
            List of changed files with status
        """
        try:
            cmd = [
                'git', '-C', repo_path,
                'diff', '--name-status',
                f'{base_ref}...{compare_ref}'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Git diff failed: {result.stderr}")
                return []
            
            changed_files = []
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        status_map = {
                            'A': 'added',
                            'M': 'modified',
                            'D': 'deleted',
                            'R': 'renamed'
                        }
                        changed_files.append({
                            'status': status_map.get(parts[0], 'unknown'),
                            'file': parts[1]
                        })
            
            return changed_files
            
        except Exception as e:
            logger.error(f"Failed to get changed files: {e}")
            return []

    async def checkout_ref(
        self,
        repo_path: str,
        ref: str,
        create_worktree: bool = True
    ) -> Optional[str]:
        """
        Checkout a specific ref safely.
        
        Args:
            repo_path: Repository root path
            ref: Commit/branch to checkout
            create_worktree: Use git worktree to avoid disrupting main
            
        Returns:
            Path to checked out code
        """
        try:
            if create_worktree:
                # Create temporary worktree
                import tempfile
                worktree_dir = tempfile.mkdtemp(prefix='sigil_compare_')
                
                cmd = [
                    'git', '-C', repo_path,
                    'worktree', 'add', worktree_dir, ref
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode != 0:
                    logger.error(f"Failed to create worktree: {result.stderr}")
                    return None
                
                return worktree_dir
            else:
                # Direct checkout (modifies working directory)
                cmd = ['git', '-C', repo_path, 'checkout', ref]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    logger.error(f"Failed to checkout: {result.stderr}")
                    return None
                
                return repo_path
                
        except Exception as e:
            logger.error(f"Failed to checkout ref: {e}")
            return None

    async def cleanup_worktree(
        self,
        repo_path: str,
        worktree_path: str
    ) -> None:
        """
        Clean up a git worktree.
        
        Args:
            repo_path: Main repository path
            worktree_path: Worktree path to remove
        """
        try:
            # Remove worktree
            cmd = [
                'git', '-C', repo_path,
                'worktree', 'remove', worktree_path, '--force'
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Also try to remove directory if it still exists
            import shutil
            if Path(worktree_path).exists():
                shutil.rmtree(worktree_path, ignore_errors=True)
                
        except Exception as e:
            logger.warning(f"Failed to cleanup worktree: {e}")

    async def get_commit_stats(
        self,
        repo_path: str,
        commit: str
    ) -> Dict[str, Any]:
        """
        Get statistics for a specific commit.
        
        Args:
            repo_path: Repository root path
            commit: Commit hash
            
        Returns:
            Commit statistics
        """
        try:
            # Get commit stats
            cmd = [
                'git', '-C', repo_path,
                'show', '--stat', '--format=', commit
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return {}
            
            # Parse stats
            lines = result.stdout.strip().split('\n')
            stats = {
                'files_changed': 0,
                'insertions': 0,
                'deletions': 0
            }
            
            for line in lines:
                if 'files changed' in line:
                    # Parse summary line
                    import re
                    match = re.search(r'(\d+) files? changed', line)
                    if match:
                        stats['files_changed'] = int(match.group(1))
                    
                    match = re.search(r'(\d+) insertions?\(\+\)', line)
                    if match:
                        stats['insertions'] = int(match.group(1))
                    
                    match = re.search(r'(\d+) deletions?\(-\)', line)
                    if match:
                        stats['deletions'] = int(match.group(1))
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get commit stats: {e}")
            return {}

    async def find_security_commits(
        self,
        repo_path: str,
        keywords: List[str] = None,
        num_commits: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Find commits related to security.
        
        Args:
            repo_path: Repository root path
            keywords: Security-related keywords to search
            num_commits: Number of commits to search
            
        Returns:
            List of security-related commits
        """
        if keywords is None:
            keywords = [
                'security', 'vulnerability', 'fix', 'patch',
                'CVE', 'XSS', 'injection', 'exploit'
            ]
        
        try:
            # Get recent commits
            commits = await self.get_recent_commits(repo_path, num_commits)
            
            security_commits = []
            for commit in commits:
                message_lower = commit['message'].lower()
                if any(keyword.lower() in message_lower for keyword in keywords):
                    # Get additional stats for security commits
                    stats = await self.get_commit_stats(repo_path, commit['hash'])
                    commit.update(stats)
                    security_commits.append(commit)
            
            return security_commits
            
        except Exception as e:
            logger.error(f"Failed to find security commits: {e}")
            return []

    async def analyze_author_contributions(
        self,
        repo_path: str,
        file_patterns: List[str] = None
    ) -> Dict[str, Dict[str, int]]:
        """
        Analyze author contributions to codebase.
        
        Args:
            repo_path: Repository root path
            file_patterns: Optional file patterns to analyze
            
        Returns:
            Author contribution statistics
        """
        try:
            # Build command
            cmd = ['git', '-C', repo_path, 'shortlog', '-sn']
            
            if file_patterns:
                cmd.extend(['--'] + file_patterns)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                return {}
            
            contributions = {}
            for line in result.stdout.strip().split('\n'):
                if line:
                    parts = line.strip().split('\t')
                    if len(parts) >= 2:
                        count = int(parts[0])
                        author = parts[1]
                        contributions[author] = {
                            'commits': count,
                            'percentage': 0  # Will calculate after
                        }
            
            # Calculate percentages
            total = sum(c['commits'] for c in contributions.values())
            if total > 0:
                for author in contributions:
                    contributions[author]['percentage'] = round(
                        (contributions[author]['commits'] / total) * 100, 1
                    )
            
            return contributions
            
        except Exception as e:
            logger.error(f"Failed to analyze contributions: {e}")
            return {}


# Global analyzer instance
git_analyzer = GitAnalyzer()