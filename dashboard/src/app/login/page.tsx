"use client";

import { useState } from "react";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      // In a real app, this would call auth.login(email, password)
      // For demonstration, simulate a brief delay
      await new Promise((resolve) => setTimeout(resolve, 1000));
      // Redirect would happen here via router.push("/")
      alert("Login successful (demo mode)");
    } catch {
      setError("Invalid email or password. Please try again.");
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
            Sign in to Sigil
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Automated security auditing for AI agent code.
          </p>
        </div>

        {/* Login form */}
        <div className="card">
          <div className="card-body">
            <form onSubmit={handleSubmit} className="space-y-5">
              {error && (
                <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-sm text-red-400">
                  {error}
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
                  autoFocus
                />
              </div>

              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label htmlFor="login-password" className="input-label mb-0">
                    Password
                  </label>
                  <a
                    href="#"
                    className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                  >
                    Forgot password?
                  </a>
                </div>
                <input
                  id="login-password"
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input"
                  required
                />
              </div>

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
                    Signing in...
                  </span>
                ) : (
                  "Sign in"
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-600 mt-6">
          Don&apos;t have an account?{" "}
          <a
            href="#"
            className="text-brand-400 hover:text-brand-300 transition-colors"
          >
            Request access
          </a>
        </p>
      </div>
    </div>
  );
}
