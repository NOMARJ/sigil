"""
Session Manager Service
Manages interactive session persistence, sharing, and export
"""

from __future__ import annotations

import json
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from uuid import uuid4

from ..models import Finding
from ..database import db
from ..exceptions import UnauthorizedError

logger = logging.getLogger(__name__)


class SessionManager:
    """Manages interactive analysis sessions"""

    async def create_session(
        self,
        user_id: str,
        scan_id: str,
        findings: List[Finding],
        model_preference: str = "claude-3-haiku"
    ) -> Dict[str, Any]:
        """
        Create a new interactive session.
        
        Args:
            user_id: User ID creating the session
            scan_id: Associated scan ID
            findings: Initial findings context
            model_preference: Preferred LLM model
            
        Returns:
            Session information including session_id and share_url
        """
        try:
            # Generate unique session ID and share token
            session_id = str(uuid4())[:16]
            share_token = str(uuid4())
            
            # Prepare findings context
            findings_context = {
                "total": len(findings),
                "by_severity": self._group_by_severity(findings),
                "by_phase": self._group_by_phase(findings),
                "files": list(set(f.file_path for f in findings))
            }
            
            # Create session in database
            await db.execute(
                """
                INSERT INTO interactive_sessions (
                    session_id, user_id, scan_id, status, 
                    findings_context, conversation_history,
                    model_preference, share_token, expires_at,
                    started_at, last_activity
                ) VALUES (
                    :session_id, :user_id, :scan_id, 'active',
                    :findings_context, '[]', :model_preference,
                    :share_token, :expires_at, :now, :now
                )
                """,
                {
                    "session_id": session_id,
                    "user_id": user_id,
                    "scan_id": scan_id,
                    "findings_context": json.dumps(findings_context),
                    "model_preference": model_preference,
                    "share_token": share_token,
                    "expires_at": datetime.utcnow() + timedelta(days=30),
                    "now": datetime.utcnow()
                }
            )
            
            logger.info(f"Created session {session_id} for user {user_id}")
            
            return {
                "session_id": session_id,
                "scan_id": scan_id,
                "status": "active",
                "share_url": f"/session/{share_token}",
                "expires_at": (datetime.utcnow() + timedelta(days=30)).isoformat(),
                "model_preference": model_preference
            }
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise

    async def get_session(
        self,
        session_id: Optional[str] = None,
        share_token: Optional[str] = None,
        user_id: Optional[str] = None,
        require_ownership: bool = True
    ) -> Dict[str, Any]:
        """
        Get session details by ID or share token.
        
        Args:
            session_id: Session ID (for owner access)
            share_token: Share token (for shared access)
            user_id: User ID requesting access
            require_ownership: Whether to require user ownership
            
        Returns:
            Complete session details including conversation history
        """
        try:
            # Build query based on access method
            if share_token:
                # Access via share token (public sharing)
                result = await db.fetch_one(
                    """
                    SELECT 
                        session_id, user_id, scan_id, status,
                        findings_context, conversation_history,
                        model_preference, share_token, expires_at,
                        started_at, last_activity, completed_at,
                        total_credits_used
                    FROM interactive_sessions
                    WHERE share_token = :share_token 
                        AND expires_at > :now
                        AND status != 'deleted'
                    """,
                    {"share_token": share_token, "now": datetime.utcnow()}
                )
            elif session_id:
                # Access via session ID (owner or authorized)
                query = """
                    SELECT 
                        session_id, user_id, scan_id, status,
                        findings_context, conversation_history,
                        model_preference, share_token, expires_at,
                        started_at, last_activity, completed_at,
                        total_credits_used
                    FROM interactive_sessions
                    WHERE session_id = :session_id
                """
                params = {"session_id": session_id}
                
                if require_ownership and user_id:
                    query += " AND user_id = :user_id"
                    params["user_id"] = user_id
                
                result = await db.fetch_one(query, params)
            else:
                raise ValueError("Either session_id or share_token required")
            
            if not result:
                raise ValueError("Session not found or expired")
            
            # Parse JSON fields
            findings_context = json.loads(result["findings_context"] or "{}")
            conversation_history = json.loads(result["conversation_history"] or "[]")
            
            # Build response
            session = {
                "session_id": result["session_id"],
                "scan_id": result["scan_id"],
                "status": result["status"],
                "owner_id": result["user_id"],
                "is_owner": result["user_id"] == user_id if user_id else False,
                "findings_context": findings_context,
                "conversation_history": conversation_history,
                "model_preference": result["model_preference"],
                "share_url": f"/session/{result['share_token']}",
                "expires_at": result["expires_at"].isoformat(),
                "started_at": result["started_at"].isoformat(),
                "last_activity": result["last_activity"].isoformat(),
                "completed_at": result["completed_at"].isoformat() if result["completed_at"] else None,
                "total_credits_used": result["total_credits_used"],
                "statistics": self._calculate_statistics(conversation_history)
            }
            
            return session
            
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            raise

    async def update_conversation(
        self,
        session_id: str,
        user_id: str,
        interaction: Dict[str, Any],
        credits_used: int = 0
    ) -> bool:
        """
        Add an interaction to the conversation history.
        
        Args:
            session_id: Session ID
            user_id: User ID (must be owner)
            interaction: Interaction data to append
            credits_used: Credits consumed by this interaction
            
        Returns:
            Success status
        """
        try:
            # Get current conversation
            result = await db.fetch_one(
                """
                SELECT conversation_history, total_credits_used
                FROM interactive_sessions
                WHERE session_id = :session_id AND user_id = :user_id
                """,
                {"session_id": session_id, "user_id": user_id}
            )
            
            if not result:
                raise UnauthorizedError("Session not found or unauthorized")
            
            # Append interaction
            conversation = json.loads(result["conversation_history"] or "[]")
            interaction["timestamp"] = datetime.utcnow().isoformat()
            interaction["credits_used"] = credits_used
            conversation.append(interaction)
            
            # Update session
            await db.execute(
                """
                UPDATE interactive_sessions
                SET conversation_history = :history,
                    total_credits_used = :total_credits,
                    last_activity = :now
                WHERE session_id = :session_id AND user_id = :user_id
                """,
                {
                    "history": json.dumps(conversation),
                    "total_credits": result["total_credits_used"] + credits_used,
                    "now": datetime.utcnow(),
                    "session_id": session_id,
                    "user_id": user_id
                }
            )
            
            logger.info(f"Updated conversation for session {session_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update conversation: {e}")
            return False

    async def export_session_markdown(
        self,
        session_id: Optional[str] = None,
        share_token: Optional[str] = None
    ) -> str:
        """
        Export session as markdown report.
        
        Args:
            session_id: Session ID
            share_token: Share token
            
        Returns:
            Markdown formatted session report
        """
        try:
            # Get session data
            session = await self.get_session(
                session_id=session_id,
                share_token=share_token,
                require_ownership=False
            )
            
            # Build markdown report
            lines = [
                "# Interactive Security Analysis Session",
                "",
                f"**Session ID**: {session['session_id']}",
                f"**Started**: {session['started_at']}",
                f"**Last Activity**: {session['last_activity']}",
                f"**Status**: {session['status']}",
                f"**Total Credits Used**: {session['total_credits_used']}",
                "",
                "## Findings Context",
                "",
                f"- **Total Findings**: {session['findings_context'].get('total', 0)}",
            ]
            
            # Add severity breakdown
            by_severity = session['findings_context'].get('by_severity', {})
            if by_severity:
                lines.append("- **By Severity**:")
                for severity, count in by_severity.items():
                    lines.append(f"  - {severity}: {count}")
            
            # Add phase breakdown
            by_phase = session['findings_context'].get('by_phase', {})
            if by_phase:
                lines.append("- **By Phase**:")
                for phase, count in by_phase.items():
                    lines.append(f"  - {phase}: {count}")
            
            lines.extend(["", "## Conversation History", ""])
            
            # Add conversation entries
            for i, entry in enumerate(session['conversation_history'], 1):
                lines.extend([
                    f"### {i}. {entry.get('type', 'Interaction')}",
                    f"*{entry.get('timestamp', 'Unknown time')}* | Credits: {entry.get('credits_used', 0)}",
                    ""
                ])
                
                # Add request details
                if 'request' in entry:
                    lines.extend([
                        "**Request**:",
                        "```",
                        json.dumps(entry['request'], indent=2),
                        "```",
                        ""
                    ])
                
                # Add response summary
                if 'response' in entry:
                    response = entry['response']
                    
                    if entry.get('type') == 'investigation':
                        lines.extend([
                            "**Investigation Result**:",
                            f"- Is Real Threat: {response.get('is_real_threat', 'Unknown')}",
                            f"- Confidence: {response.get('confidence', 'Unknown')}%",
                            f"- Priority: {response.get('priority', 'Unknown')}",
                            ""
                        ])
                        
                        if 'analysis' in response:
                            lines.extend([
                                "**Analysis**:",
                                response['analysis'],
                                ""
                            ])
                    
                    elif entry.get('type') == 'false_positive_analysis':
                        lines.extend([
                            "**False Positive Analysis**:",
                            f"- Is False Positive: {response.get('is_false_positive', 'Unknown')}",
                            f"- Confidence: {response.get('confidence', 'Unknown')}%",
                            ""
                        ])
                        
                        if 'explanation' in response:
                            lines.extend([
                                "**Explanation**:",
                                response['explanation'],
                                ""
                            ])
                    
                    elif entry.get('type') == 'remediation':
                        lines.extend([
                            "**Remediation Generated**:",
                            f"- Language: {response.get('language', 'Unknown')}",
                            f"- Fix Type: {response.get('fix_type', 'Unknown')}",
                            ""
                        ])
                        
                        if 'code' in response:
                            lines.extend([
                                "**Fix Code**:",
                                f"```{response.get('language', '')}",
                                response['code'],
                                "```",
                                ""
                            ])
                    
                    elif entry.get('type') == 'chat':
                        if 'message' in response:
                            lines.extend([
                                "**Response**:",
                                response['message'],
                                ""
                            ])
                
                lines.append("---")
                lines.append("")
            
            # Add statistics
            stats = session['statistics']
            lines.extend([
                "## Session Statistics",
                "",
                f"- **Total Interactions**: {stats['total_interactions']}",
                f"- **Investigations**: {stats['investigations']}",
                f"- **False Positive Checks**: {stats['false_positive_checks']}",
                f"- **Remediations Generated**: {stats['remediations']}",
                f"- **Chat Messages**: {stats['chats']}",
                f"- **Average Credits per Interaction**: {stats['avg_credits']:.1f}",
                "",
                "---",
                "",
                f"*Report generated at {datetime.utcnow().isoformat()}*"
            ])
            
            return "\n".join(lines)
            
        except Exception as e:
            logger.error(f"Failed to export session: {e}")
            raise

    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up sessions older than 30 days.
        
        Returns:
            Number of sessions cleaned up
        """
        try:
            result = await db.execute(
                """
                UPDATE interactive_sessions
                SET status = 'expired'
                WHERE expires_at < :now AND status = 'active'
                """,
                {"now": datetime.utcnow()}
            )
            
            count = result.rowcount if hasattr(result, 'rowcount') else 0
            
            if count > 0:
                logger.info(f"Expired {count} sessions")
            
            return count
            
        except Exception as e:
            logger.error(f"Failed to cleanup sessions: {e}")
            return 0

    async def list_user_sessions(
        self,
        user_id: str,
        status: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        List all sessions for a user.
        
        Args:
            user_id: User ID
            status: Optional status filter
            limit: Maximum sessions to return
            
        Returns:
            List of session summaries
        """
        try:
            query = """
                SELECT 
                    session_id, scan_id, status,
                    model_preference, share_token,
                    started_at, last_activity, expires_at,
                    total_credits_used
                FROM interactive_sessions
                WHERE user_id = :user_id
            """
            params = {"user_id": user_id}
            
            if status:
                query += " AND status = :status"
                params["status"] = status
            
            query += " ORDER BY last_activity DESC LIMIT :limit"
            params["limit"] = limit
            
            results = await db.fetch_all(query, params)
            
            sessions = []
            for row in results:
                sessions.append({
                    "session_id": row["session_id"],
                    "scan_id": row["scan_id"],
                    "status": row["status"],
                    "model_preference": row["model_preference"],
                    "share_url": f"/session/{row['share_token']}",
                    "started_at": row["started_at"].isoformat(),
                    "last_activity": row["last_activity"].isoformat(),
                    "expires_at": row["expires_at"].isoformat(),
                    "total_credits_used": row["total_credits_used"]
                })
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to list sessions: {e}")
            return []

    def _group_by_severity(self, findings: List[Finding]) -> Dict[str, int]:
        """Group findings by severity"""
        severity_counts = {}
        for finding in findings:
            severity = finding.severity
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts

    def _group_by_phase(self, findings: List[Finding]) -> Dict[str, int]:
        """Group findings by phase"""
        phase_counts = {}
        for finding in findings:
            phase = finding.phase
            phase_counts[phase] = phase_counts.get(phase, 0) + 1
        return phase_counts

    def _calculate_statistics(self, conversation: List[Dict]) -> Dict[str, Any]:
        """Calculate conversation statistics"""
        stats = {
            "total_interactions": len(conversation),
            "investigations": 0,
            "false_positive_checks": 0,
            "remediations": 0,
            "chats": 0,
            "total_credits": 0,
            "avg_credits": 0
        }
        
        for entry in conversation:
            interaction_type = entry.get("type", "")
            credits = entry.get("credits_used", 0)
            
            stats["total_credits"] += credits
            
            if interaction_type == "investigation":
                stats["investigations"] += 1
            elif interaction_type == "false_positive_analysis":
                stats["false_positive_checks"] += 1
            elif interaction_type == "remediation":
                stats["remediations"] += 1
            elif interaction_type == "chat":
                stats["chats"] += 1
        
        if stats["total_interactions"] > 0:
            stats["avg_credits"] = stats["total_credits"] / stats["total_interactions"]
        
        return stats


# Global session manager instance
session_manager = SessionManager()