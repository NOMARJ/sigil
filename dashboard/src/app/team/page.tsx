"use client";

import { useState } from "react";
import type { User, UserRole } from "@/lib/types";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const mockMembers: User[] = [
  {
    id: "user-001",
    email: "alice@company.com",
    name: "Alice Chen",
    avatar_url: null,
    role: "owner",
    created_at: "2025-06-15T10:00:00Z",
    last_login: "2026-02-15T08:30:00Z",
  },
  {
    id: "user-002",
    email: "bob@company.com",
    name: "Bob Martinez",
    avatar_url: null,
    role: "admin",
    created_at: "2025-07-20T14:00:00Z",
    last_login: "2026-02-14T22:15:00Z",
  },
  {
    id: "user-003",
    email: "carol@company.com",
    name: "Carol Davis",
    avatar_url: null,
    role: "member",
    created_at: "2025-09-01T09:00:00Z",
    last_login: "2026-02-15T07:45:00Z",
  },
  {
    id: "user-004",
    email: "dave@company.com",
    name: "Dave Wilson",
    avatar_url: null,
    role: "member",
    created_at: "2025-11-10T16:00:00Z",
    last_login: "2026-02-13T19:20:00Z",
  },
  {
    id: "user-005",
    email: "eve@contractor.io",
    name: "Eve Thompson",
    avatar_url: null,
    role: "viewer",
    created_at: "2026-01-05T11:00:00Z",
    last_login: "2026-02-12T10:00:00Z",
  },
];

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
  const [members] = useState<User[]>(mockMembers);

  const handleInvite = (e: React.FormEvent) => {
    e.preventDefault();
    // In a real app, this would call the API
    alert(`Invite sent to ${inviteEmail} as ${inviteRole}`);
    setInviteEmail("");
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

      {/* Invite form */}
      <div className="card">
        <div className="card-header">
          <h2 className="section-header">Invite Member</h2>
          <p className="section-description">
            Send an invitation to join your team.
          </p>
        </div>
        <div className="card-body">
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
            <button type="submit" className="btn-primary">
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 6v6m0 0v6m0-6h6m-6 0H6" />
              </svg>
              Send Invite
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

                <span
                  className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${roleStyles[member.role]}`}
                >
                  {roleLabels[member.role]}
                </span>

                {member.role !== "owner" && (
                  <button className="btn-ghost text-xs text-gray-500 hover:text-red-400">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
