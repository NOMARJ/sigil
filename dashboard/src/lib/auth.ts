"use client";

// ---------------------------------------------------------------------------
// Sigil Dashboard — Auth helpers
// Token management, login/register wrappers, and auth context.
// ---------------------------------------------------------------------------

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  type ReactNode,
} from "react";
import React from "react";
import type { AuthTokens, User } from "./types";
import * as api from "./api";

// ---------------------------------------------------------------------------
// Token storage
// ---------------------------------------------------------------------------

const ACCESS_KEY = "sigil_access_token";
const REFRESH_KEY = "sigil_refresh_token";
const EXPIRES_KEY = "sigil_token_expires";

export function storeTokens(tokens: AuthTokens): void {
  localStorage.setItem(ACCESS_KEY, tokens.access_token);
  localStorage.setItem(REFRESH_KEY, tokens.refresh_token);
  localStorage.setItem(EXPIRES_KEY, String(tokens.expires_at));
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_KEY);
  localStorage.removeItem(REFRESH_KEY);
  localStorage.removeItem(EXPIRES_KEY);
}

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_KEY);
}

export function isTokenExpired(): boolean {
  const exp = localStorage.getItem(EXPIRES_KEY);
  if (!exp) return true;
  return Date.now() >= Number(exp) * 1000;
}

// ---------------------------------------------------------------------------
// Auth context
// ---------------------------------------------------------------------------

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState>({
  user: null,
  loading: true,
  login: async () => {},
  register: async () => {},
  logout: () => {},
});

export function useAuth(): AuthState {
  return useContext(AuthContext);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchUser = useCallback(async () => {
    try {
      const token = getAccessToken();
      if (!token) {
        setLoading(false);
        return;
      }

      if (isTokenExpired()) {
        const refresh = getRefreshToken();
        if (refresh) {
          const tokens = await api.refreshToken(refresh);
          storeTokens(tokens);
        } else {
          clearTokens();
          setLoading(false);
          return;
        }
      }

      const me = await api.getCurrentUser();
      setUser(me);
    } catch {
      clearTokens();
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await api.login({ email, password });
    storeTokens(tokens);
    const me = await api.getCurrentUser();
    setUser(me);
  }, []);

  const register = useCallback(
    async (email: string, password: string, name: string) => {
      const tokens = await api.register({ email, password, name });
      storeTokens(tokens);
      const me = await api.getCurrentUser();
      setUser(me);
    },
    [],
  );

  const logout = useCallback(() => {
    // Fire-and-forget server-side logout
    api.logout();
    clearTokens();
    setUser(null);
  }, []);

  return React.createElement(
    AuthContext.Provider,
    { value: { user, loading, login, register, logout } },
    children,
  );
}
