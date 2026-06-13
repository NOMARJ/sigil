"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import type { User } from "./types";

type AuthContextType = {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  loginWithOAuth: (connection?: string) => void;
  logout: () => Promise<void>;
};

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

  // Restore session on mount
  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      try {
        const res = await fetch("/api/auth/me", {
          credentials: 'include',
          cache: 'no-store',
        });
        if (res.ok) {
          const userData = await res.json();
          if (!cancelled && userData.id) {
            const user = {
              id: userData.id,
              email: userData.email,
              name: userData.name || userData.email,
              avatar_url: userData.avatar_url || null,
              role: userData.role,
              plan: userData.plan,
              created_at: userData.created_at || new Date().toISOString(),
              last_login: new Date().toISOString(),
            };
            setUser(user);
            setLoading(false);
            return;
          }
        }
      } catch {
        // Auth0 session not available
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

  const loginWithOAuth = useCallback((connection?: string) => {
    // Auth0 handles OAuth via redirect-based flow
    const url = connection
      ? `/auth/login?connection=${encodeURIComponent(connection)}`
      : "/auth/login";
    window.location.href = url;
  }, []);

  const logout = useCallback(async () => {
    setUser(null);
    // Redirect to Auth0 logout to clear the Auth0 session
    window.location.href = "/auth/logout";
  }, []);

  const isAuthenticated = user !== null;

  return React.createElement(
    AuthContext.Provider,
    {
      value: {
        user,
        loading,
        isAuthenticated,
        loginWithOAuth,
        logout,
      },
    },
    children,
  );
}
