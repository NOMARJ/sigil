"use client";

import { useState, useEffect, useCallback } from "react";
import * as api from "@/lib/api";
import type { User, UserRole } from "@/lib/types";

const roleLabels: Record<UserRole, string> = {
  owner: "Owner",
  admin: "Admin",
  member: "Member",
  viewer: "Viewer",
};

const roleStyles: Record<UserRole, string> = {
  owner: "bg-purple-500/10 text-purple-400 border-purple-500/20",
  admin: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  member: "bg-gray-500/10 text-gray-400 border-gray-500/20",
  viewer: "bg-gray-800 text-gray-500 border-gray-700",
};

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function TeamPage() {
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<UserRole>("member");
  const [members, setMembers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteError, setInviteError] = useState<string | null>(null);
  const [inviteSuccess, setInviteSuccess] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const fetchTeam = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const team = await api.getTeam();
      setMembers(team.members);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to load team data.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTeam();
  }, [fetchTeam]);

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    setInviteLoading(true);
    setInviteError(null);
    setInviteSuccess(null);

    try {
      await api.inviteMember(inviteEmail, inviteRole);
      setInviteSuccess(`Invitation sent to ${inviteEmail}.`);
      setInviteEmail("");
      // Refresh the team list
      fetchTeam();
      // Clear success after a while
      setTimeout(() => setInviteSuccess(null), 5000);
    } catch (err) {
      setInviteError(
        err instanceof Error ? err.message : "Failed to send invitation.",
      );
    } finally {
      setInviteLoading(false);
    }
  };

  const handleRemoveMember = async (userId: string, memberName: string) => {
    if (!confirm(`Are you sure you want to remove ${memberName} from the team?`)) {
      return;
    }

    setActionLoading(userId);
    setActionError(null);

    try {
      await api.removeMember(userId);
      setMembers((prev) => prev.filter((m) => m.id !== userId));
    } catch (err) {
      setActionError(
        err instanceof Error ? err.message : "Failed to remove member.",
      );
    } finally {
      setActionLoading(null);
    }
  };

  const handleRoleChange = async (userId: string, newRole: UserRole) => {
    setActionLoading(userId);
    setActionError(null);

    try {
      const updated = await api.updateMemberRole(userId, newRole);
      setMembers((prev) =>
        prev.map((m) => (m.id === userId ? { ...m, role: updated.role } : m)),
      );
    } catch (err) {
      setActionError(
        err instanceof Error ? err.message : "Failed to update role.",
      );
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
          Team Management
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Manage team members and their access roles.
        </p>
      </div>

      {/* Global action error */}
      {actionError && (
        <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
          {actionError}
        </div>
      )}

      {/* Invite form */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Invite Member</h2>
          <p className="section-description">
            Send an invitation to join your team.
          </p>
        </div>
        <div className="card-body">
          {inviteSuccess && (
            <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400 mb-4">
              {inviteSuccess}
            </div>
          )}
          {inviteError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 mb-4">
              {inviteError}
            </div>
          )}
          <form onSubmit={handleInvite} className="flex items-end gap-4">
            <div className="flex-1">
              <label htmlFor="invite-email" className="input-label">
                Email address
              </label>
              <input
                id="invite-email"
                type="email"
                placeholder="colleague@company.com"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                className="input"
                required
              />
            </div>
            <div className="w-40">
              <label htmlFor="invite-role" className="input-label">
                Role
              </label>
              <select
                id="invite-role"
                value={inviteRole}
                onChange={(e) => setInviteRole(e.target.value as UserRole)}
                className="input"
              >
                <option value="admin">Admin</option>
                <option value="member">Member</option>
                <option value="viewer">Viewer</option>
              </select>
            </div>
            <button type="submit" className="btn-primary" disabled={inviteLoading}>
              {inviteLoading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                  Sending...
                </span>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
                  </svg>
                  Send Invite
                </>
              )}
            </button>
          </form>
        </div>
      </div>

      {/* Members list */}
      <div className="card">
        <div className="card-header flex items-center justify-between">
          <div>
            <h2 className="section-header">
              Members{" "}
              <span className="text-gray-500 font-normal">
                ({members.length})
              </span>
            </h2>
            <p className="section-description">
              Current team members and their roles.
            </p>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="px-5 py-4">
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center justify-between">
              <span>{error}</span>
              <button
                onClick={fetchTeam}
                className="text-red-400 hover:text-red-300 text-xs font-medium underline"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        {/* Loading */}
        {loading ? (
          <div className="divide-y divide-gray-800/50">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="px-5 py-4 flex items-center justify-between animate-pulse">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-gray-800" />
                  <div>
                    <div className="h-4 w-28 bg-gray-800 rounded mb-1.5" />
                    <div className="h-3 w-36 bg-gray-800 rounded" />
                  </div>
                </div>
                <div className="flex items-center gap-6">
                  <div className="h-3 w-20 bg-gray-800 rounded" />
                  <div className="h-6 w-16 bg-gray-800 rounded-full" />
                </div>
              </div>
            ))}
          </div>
        ) : members.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <p className="text-sm">No team members found.</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-800/50">
            {members.map((member) => (
              <div
                key={member.id}
                className="px-5 py-4 flex items-center justify-between hover:bg-gray-800/20 transition-colors"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-gray-700 flex items-center justify-center text-sm font-semibold text-gray-300">
                    {getInitials(member.name)}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-gray-100">
                      {member.name}
                    </p>
                    <p className="text-xs text-gray-500">{member.email}</p>
                  </div>
                </div>

                <div className="flex items-center gap-6">
                  <div className="text-right text-xs text-gray-500">
                    <p>Joined {formatDate(member.created_at)}</p>
                    {member.last_login && (
                      <p className="mt-0.5">
                        Last active {formatDate(member.last_login)}
                      </p>
                    )}
                  </div>

                  {/* Role selector (for non-owners) */}
                  {member.role !== "owner" ? (
                    <select
                      value={member.role}
                      onChange={(e) => handleRoleChange(member.id, e.target.value as UserRole)}
                      disabled={actionLoading === member.id}
                      className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer bg-transparent ${roleStyles[member.role]}`}
                    >
                      <option value="admin">Admin</option>
                      <option value="member">Member</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  ) : (
                    <span
                      className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${roleStyles[member.role]}`}
                    >
                      {roleLabels[member.role]}
                    </span>
                  )}

                  {member.role !== "owner" && (
                    <button
                      onClick={() => handleRemoveMember(member.id, member.name)}
                      disabled={actionLoading === member.id}
                      className="btn-ghost text-xs text-gray-500 hover:text-red-400"
                    >
                      {actionLoading === member.id ? (
                        <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                      ) : (
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      )}
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
