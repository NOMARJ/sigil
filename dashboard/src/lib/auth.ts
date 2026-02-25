"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { supabase } from "./supabase";
import * as api from "./api";
import type { User } from "./types";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  loginWithEmail: (email: string, password: string) => Promise<void>;
  loginWithGitHub: () => Promise<void>;
  loginWithGoogle: () => Promise<void>;
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
      // 1. Try Supabase session first
      if (supabase) {
        try {
          const { data: { session } } = await supabase.auth.getSession();
          if (session?.access_token) {
            // We have a Supabase session — fetch our app user from the API
            try {
              const appUser = await api.getCurrentUser();
              if (!cancelled) {
                setUser(appUser);
                setLoading(false);
                return;
              }
            } catch {
              // Supabase token may not be recognized by our API, fall through
            }
          }
        } catch {
          // Supabase unavailable, fall through
        }
      }

      // 2. Fall back to localStorage token
      if (typeof window !== "undefined") {
        const token = localStorage.getItem("sigil_access_token");
        if (token) {
          try {
            const appUser = await api.getCurrentUser();
            if (!cancelled) {
              setUser(appUser);
              setLoading(false);
              return;
            }
          } catch {
            // Token expired or invalid — clear it
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

    // Listen for Supabase auth changes (OAuth callbacks, etc.)
    let subscription: { unsubscribe: () => void } | undefined;
    if (supabase) {
      const { data: { subscription: sub } } = supabase.auth.onAuthStateChange(
        async (_event, session) => {
          if (session?.access_token) {
            try {
              const appUser = await api.getCurrentUser();
              if (!cancelled) setUser(appUser);
            } catch {
              if (!cancelled) setUser(null);
            }
          } else {
            // Only clear user if we don't have a localStorage token
            const localToken = typeof window !== "undefined"
              ? localStorage.getItem("sigil_access_token")
              : null;
            if (!localToken && !cancelled) {
              setUser(null);
            }
          }
        },
      );
      subscription = sub;
    }

    return () => {
      cancelled = true;
      subscription?.unsubscribe();
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
      setUser(tokens.user);
    } else {
      const appUser = await api.getCurrentUser();
      setUser(appUser);
    }
  }, []);

  const loginWithGitHub = useCallback(async () => {
    if (!supabase) {
      throw new Error(
        "GitHub login is not available. Supabase is not configured. Please use email/password login instead.",
      );
    }

    const { error } = await supabase.auth.signInWithOAuth({
      provider: "github",
      options: {
        redirectTo: typeof window !== "undefined"
          ? `${window.location.origin}/auth/callback`
          : "https://app.sigilsec.ai/auth/callback",
      },
    });

    if (error) throw error;
  }, []);

  const loginWithGoogle = useCallback(async () => {
    if (!supabase) {
      throw new Error(
        "Google login is not available. Supabase is not configured. Please use email/password login instead.",
      );
    }

    const { error } = await supabase.auth.signInWithOAuth({
      provider: "google",
      options: {
        redirectTo: typeof window !== "undefined"
          ? `${window.location.origin}/auth/callback`
          : "https://app.sigilsec.ai/auth/callback",
      },
    });

    if (error) throw error;
  }, []);

  const logout = useCallback(async () => {
    // Clear localStorage tokens
    if (typeof window !== "undefined") {
      localStorage.removeItem("sigil_access_token");
      localStorage.removeItem("sigil_refresh_token");
    }

    // Sign out of Supabase if available
    if (supabase) {
      try {
        await supabase.auth.signOut();
      } catch {
        // Ignore Supabase sign-out errors
      }
    }

    // Call API logout (best-effort)
    try {
      await api.logout();
    } catch {
      // Even if server-side logout fails, we still clear local state
    }

    setUser(null);
  }, []);

  const isAuthenticated = user !== null;

  return React.createElement(
    AuthContext.Provider,
    {
      value: {
        user,
        loading,
        isAuthenticated,
        loginWithEmail,
        loginWithGitHub,
        loginWithGoogle,
        logout,
      },
    },
    children,
  );
}
