"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import * as api from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const { login, register: registerUser } = useAuth();

  const [mode, setMode] = useState<"login" | "register" | "forgot">("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const switchMode = (next: "login" | "register" | "forgot") => {
    setMode(next);
    setError(null);
    setSuccessMessage(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMessage(null);
    setIsLoading(true);

    try {
      if (mode === "login") {
        await login(email, password);
        router.push("/");
      } else if (mode === "register") {
        if (!name.trim()) {
          setError("Please enter your full name.");
          setIsLoading(false);
          return;
        }
        await registerUser(email, password, name);
        router.push("/");
      } else {
        // forgot mode
        const result = await api.forgotPassword(email);
        setSuccessMessage(result.message);
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "An unexpected error occurred.";
      setError(message);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 -m-8">
      <div className="w-full max-w-md px-6">
        {/* Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-600 text-white font-bold text-2xl mb-4 glow-brand">
            S
          </div>
          <h1 className="text-2xl font-bold text-gray-100 tracking-tight">
            {mode === "login"
              ? "Sign in to Sigil"
              : mode === "register"
              ? "Create your account"
              : "Reset your password"}
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Automated security auditing for AI agent code.
          </p>
        </div>

        {/* Mode tabs — only show for login/register, not for forgot */}
        {mode !== "forgot" && (
          <div className="flex mb-6 bg-gray-900 rounded-lg p-1 border border-gray-800">
            <button
              onClick={() => switchMode("login")}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                mode === "login"
                  ? "bg-gray-800 text-gray-100 shadow-sm"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              Sign In
            </button>
            <button
              onClick={() => switchMode("register")}
              className={`flex-1 py-2 text-sm font-medium rounded-md transition-colors ${
                mode === "register"
                  ? "bg-gray-800 text-gray-100 shadow-sm"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              Register
            </button>
          </div>
        )}

        {/* Form */}
        <div className="card">
          <div className="card-body">
            <form onSubmit={handleSubmit} className="space-y-5">
              {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
                  {error}
                </div>
              )}

              {successMessage && (
                <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400">
                  {successMessage}
                </div>
              )}

              {mode === "register" && (
                <div>
                  <label htmlFor="login-name" className="input-label">
                    Full name
                  </label>
                  <input
                    id="login-name"
                    type="text"
                    placeholder="Alice Chen"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="input"
                    required={mode === "register"}
                    autoFocus={mode === "register"}
                  />
                </div>
              )}

              <div>
                <label htmlFor="login-email" className="input-label">
                  Email address
                </label>
                <input
                  id="login-email"
                  type="email"
                  placeholder="you@company.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  required
                  autoFocus={mode === "login" || mode === "forgot"}
                />
              </div>

              {mode !== "forgot" && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <label htmlFor="login-password" className="input-label mb-0">
                      Password
                    </label>
                    {mode === "login" && (
                      <button
                        type="button"
                        onClick={() => switchMode("forgot")}
                        className="text-sm text-brand-400 hover:text-brand-300"
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                  <input
                    id="login-password"
                    type="password"
                    placeholder={
                      mode === "register"
                        ? "Create a password"
                        : "Enter your password"
                    }
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="input"
                    required
                    minLength={mode === "register" ? 8 : undefined}
                    autoComplete={mode === "register" ? "new-password" : "current-password"}
                  />
                  {mode === "register" && (
                    <p className="text-xs text-gray-600 mt-1">
                      Must be at least 8 characters.
                    </p>
                  )}
                </div>
              )}

              {mode === "forgot" && successMessage ? null : (
                <button
                  type="submit"
                  disabled={isLoading}
                  className="btn-primary w-full"
                >
                  {isLoading ? (
                    <span className="flex items-center gap-2">
                      <svg
                        className="animate-spin h-4 w-4"
                        viewBox="0 0 24 24"
                        fill="none"
                      >
                        <circle
                          className="opacity-25"
                          cx="12"
                          cy="12"
                          r="10"
                          stroke="currentColor"
                          strokeWidth="4"
                        />
                        <path
                          className="opacity-75"
                          fill="currentColor"
                          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                        />
                      </svg>
                      {mode === "login"
                        ? "Signing in..."
                        : mode === "register"
                        ? "Creating account..."
                        : "Sending reset link..."}
                    </span>
                  ) : mode === "login" ? (
                    "Sign in"
                  ) : mode === "register" ? (
                    "Create account"
                  ) : (
                    "Send reset link"
                  )}
                </button>
              )}
            </form>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-600 mt-6">
          {mode === "forgot" ? (
            <>
              Remember your password?{" "}
              <button
                onClick={() => switchMode("login")}
                className="text-brand-400 hover:text-brand-300 transition-colors"
              >
                Back to sign in
              </button>
            </>
          ) : mode === "login" ? (
            <>
              Don&apos;t have an account?{" "}
              <button
                onClick={() => switchMode("register")}
                className="text-brand-400 hover:text-brand-300 transition-colors"
              >
                Create one
              </button>
            </>
          ) : (
            <>
              Already have an account?{" "}
              <button
                onClick={() => switchMode("login")}
                className="text-brand-400 hover:text-brand-300 transition-colors"
              >
                Sign in
              </button>
            </>
          )}
        </p>
      </div>
    </div>
  );
}
