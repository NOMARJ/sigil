"use client";

import React, { createContext, useContext, useEffect, useState, useCallback } from "react";
import { supabase } from "./supabase";
import type { User, Session } from "@supabase/supabase-js";

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, name: string) => Promise<void>;
  logout: () => Promise<void>;
  loginWithGitHub: () => Promise<void>;
  loginWithGoogle: () => Promise<void>;
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

  useEffect(() => {
    // Skip if Supabase client is not initialized
    if (!supabase) {
      setLoading(false);
      return;
    }

    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setUser(session?.user ?? null);
      setLoading(false);
    });

    // Listen for auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const register = useCallback(async (email: string, password: string, name: string) => {
    if (!supabase) throw new Error('Supabase client not initialized');

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          name, // Store name in user metadata
        },
      },
    });

    if (error) throw error;

    // User will be automatically logged in after signup
    setUser(data.user);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    if (!supabase) throw new Error('Supabase client not initialized');

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) throw error;
    setUser(data.user);
  }, []);

  const logout = useCallback(async () => {
    if (!supabase) throw new Error('Supabase client not initialized');

    const { error } = await supabase.auth.signOut();
    if (error) throw error;
    setUser(null);
  }, []);

  const loginWithGitHub = useCallback(async () => {
    if (!supabase) throw new Error('Supabase client not initialized');

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: typeof window !== 'undefined'
          ? `${window.location.origin}/auth/callback`
          : 'https://app.sigilsec.ai/auth/callback',
      },
    });

    if (error) throw error;
  }, []);

  const loginWithGoogle = useCallback(async () => {
    if (!supabase) throw new Error('Supabase client not initialized');

    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: typeof window !== 'undefined'
          ? `${window.location.origin}/auth/callback`
          : 'https://app.sigilsec.ai/auth/callback',
      },
    });

    if (error) throw error;
  }, []);

  return React.createElement(
    AuthContext.Provider,
    { value: { user, loading, login, register, logout, loginWithGitHub, loginWithGoogle } },
    children
  );
}
