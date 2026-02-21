"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import * as api from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const { login, register: registerUser, loginWithGitHub } = useAuth();

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
                  autoComplete="email"
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

            {/* Social OAuth - only show for login/register */}
            {mode !== "forgot" && (
              <>
                <div className="relative mt-6">
                  <div className="absolute inset-0 flex items-center">
                    <div className="w-full border-t border-gray-800" />
                  </div>
                  <div className="relative flex justify-center text-sm">
                    <span className="px-2 bg-gray-900 text-gray-500">Or continue with</span>
                  </div>
                </div>

                <div className="mt-6">
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        await loginWithGitHub();
                      } catch (err) {
                        setError(err instanceof Error ? err.message : 'Failed to sign in with GitHub');
                      }
                    }}
                    className="flex items-center justify-center gap-3 w-full px-4 py-2.5 border border-gray-800 rounded-lg text-sm font-medium text-gray-300 bg-gray-900 hover:bg-gray-800 hover:border-gray-700 transition-colors"
                  >
                    <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20" aria-hidden="true">
                      <path fillRule="evenodd" d="M10 0C4.477 0 0 4.484 0 10.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0110 4.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.203 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.942.359.31.678.921.678 1.856 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0020 10.017C20 4.484 15.522 0 10 0z" clipRule="evenodd" />
                    </svg>
                    Continue with GitHub
                  </button>
                </div>
              </>
            )}
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
