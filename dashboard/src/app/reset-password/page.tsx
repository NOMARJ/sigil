"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import * as api from "@/lib/api";

export default function ResetPasswordPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get("token") ?? "";

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // If no token in the URL, show an immediate error
  useEffect(() => {
    if (!token) {
      setError("No reset token found. Please request a new password reset link.");
    }
  }, [token]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setIsLoading(true);

    try {
      const result = await api.resetPassword(token, newPassword);
      setSuccessMessage(result.message + " Redirecting to login...");
      setTimeout(() => {
        router.push("/login");
      }, 2000);
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
            Set a new password
          </h1>
          <p className="text-sm text-gray-500 mt-2">
            Enter your new password below.
          </p>
        </div>

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

              {!successMessage && (
                <>
                  <div>
                    <label htmlFor="reset-password" className="input-label">
                      New password
                    </label>
                    <input
                      id="reset-password"
                      type="password"
                      placeholder="Create a new password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="input"
                      required
                      minLength={8}
                      autoFocus
                    />
                    <p className="text-xs text-gray-600 mt-1">
                      Must be at least 8 characters.
                    </p>
                  </div>

                  <div>
                    <label htmlFor="reset-confirm-password" className="input-label">
                      Confirm new password
                    </label>
                    <input
                      id="reset-confirm-password"
                      type="password"
                      placeholder="Repeat your new password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="input"
                      required
                      minLength={8}
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading || !token}
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
                        Resetting password...
                      </span>
                    ) : (
                      "Reset password"
                    )}
                  </button>
                </>
              )}
            </form>
          </div>
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-600 mt-6">
          Remember your password?{" "}
          <a
            href="/login"
            className="text-brand-400 hover:text-brand-300 transition-colors"
          >
            Back to sign in
          </a>
        </p>
      </div>
    </div>
  );
}
