"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import * as api from "./api";
import type { User } from "./types";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
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

  // Restore session on mount
  useEffect(() => {
    let cancelled = false;

    async function restoreSession() {
      // Only try Auth0 session
      try {
        const res = await fetch("/api/auth/token", {
          credentials: 'include',
          cache: 'no-store',
        });
        if (res.ok) {
          const { accessToken } = await res.json();
          if (accessToken) {
            try {
              const appUser = await api.getCurrentUser();
              if (!cancelled) {
                const userWithPlan = { ...appUser, plan: appUser.plan || "pro" as const };
                setUser(userWithPlan);
                setLoading(false);
                return;
              }
            } catch {
              // Token invalid, user not authenticated
            }
          }
        }
      } catch {
        // Auth0 unavailable
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
      ? `/api/auth/login?connection=${connection}`
      : "/api/auth/login";
    window.location.href = url;
  }, []);

  const logout = useCallback(async () => {
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
        loginWithOAuth,
        logout,
      },
    },
    children,
  );
}
