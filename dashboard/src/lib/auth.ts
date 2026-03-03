"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import * as api from "./api";
import type { User } from "./types";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  auth0Configured: boolean;
  loginWithEmail: (email: string, password: string) => Promise<void>;
  loginWithOAuth: (connection?: string) => void;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  // Auth0 is always configured in production (server-side routes handle it)
  const auth0Configured = typeof window !== "undefined";

  // Restore session on mount
  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      // 1. Try Auth0 session first (for OAuth users)
      try {
        const res = await fetch("/api/auth/token");
        if (res.ok) {
          const { accessToken } = await res.json();
          if (accessToken) {
            try {
              const appUser = await api.getCurrentUser();
              if (!cancelled) {
                // Ensure user has a plan field for development
                const userWithPlan = { ...appUser, plan: appUser.plan || "pro" as const };
                setUser(userWithPlan);
                setLoading(false);
                return;
              }
            } catch {
              // Auth0 token may not be recognized by our API, fall through
            }
          }
        }
      } catch {
        // Auth0 unavailable, fall through
      }

      // 2. Fall back to localStorage token (email/password users)
      if (typeof window !== "undefined") {
        const token = localStorage.getItem("sigil_access_token");
        if (token) {
          try {
            const appUser = await api.getCurrentUser();
            if (!cancelled) {
              // Ensure user has a plan field for development
              const userWithPlan = { ...appUser, plan: appUser.plan || "pro" as const };
              setUser(userWithPlan);
              setLoading(false);
              return;
            }
          } catch {
            // Token expired or invalid -- clear it
            localStorage.removeItem("sigil_access_token");
            localStorage.removeItem("sigil_refresh_token");
          }
        }
      }

      if (!cancelled) {
        setUser(null);
        setLoading(false);
      }
    }

    restoreSession();

    return () => {
      cancelled = true;
    };
  }, []);

  const loginWithEmail = useCallback(async (email: string, password: string) => {
    const tokens = await api.login({ email, password });
    // Store tokens in localStorage
    if (typeof window !== "undefined") {
      localStorage.setItem("sigil_access_token", tokens.access_token);
      if (tokens.refresh_token) {
        localStorage.setItem("sigil_refresh_token", tokens.refresh_token);
      }
    }
    // Set user from the token response or fetch from API
    if (tokens.user) {
      const userWithPlan = { ...tokens.user, plan: tokens.user.plan || "pro" as const };
      setUser(userWithPlan);
    } else {
      const appUser = await api.getCurrentUser();
      const userWithPlan = { ...appUser, plan: appUser.plan || "pro" as const };
      setUser(userWithPlan);
    }
  }, []);

  const loginWithOAuth = useCallback((connection?: string) => {
    // Auth0 handles OAuth via redirect-based flow
    const url = connection
      ? `/api/auth/login?connection=${connection}`
      : "/api/auth/login";
    window.location.href = url;
  }, []);

  const logout = useCallback(async () => {
    // Clear localStorage tokens (email/password users)
    if (typeof window !== "undefined") {
      localStorage.removeItem("sigil_access_token");
      localStorage.removeItem("sigil_refresh_token");
    }

    // Call API logout (best-effort)
    try {
      await api.logout();
    } catch {
      // Even if server-side logout fails, we still clear local state
    }

    setUser(null);

    // Redirect to Auth0 logout to clear the Auth0 session
    window.location.href = "/api/auth/logout";
  }, []);

  const isAuthenticated = user !== null;

  return React.createElement(
    AuthContext.Provider,
    {
      value: {
        user,
        loading,
        isAuthenticated,
        auth0Configured,
        loginWithEmail,
        loginWithOAuth,
        logout,
      },
    },
    children,
  );
}
