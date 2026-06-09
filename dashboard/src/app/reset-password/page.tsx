"use client";

import { useEffect } from "react";

/**
 * Legacy password reset URL — superseded by Auth0 Universal Login (ADR-0002).
 *
 * The old flow generated `/reset-password?token=...` links via the
 * dashboard backend. Auth0 now owns identity, and stale tokens (if any
 * still in users' inboxes) cannot resolve. Redirect to Auth0 login;
 * users can click "Don't remember your password?" on the hosted login
 * page to trigger Auth0's password reset flow (which Auth0 emails and
 * processes end-to-end).
 */
export default function ResetPasswordPage() {
  useEffect(() => {
    window.location.replace("/auth/login");
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 -m-8">
      <div className="w-full max-w-md px-6 text-center">
        <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-brand-600 text-white font-bold text-2xl mb-4 glow-brand">
          S
        </div>
        <h1 className="text-2xl font-bold text-gray-100 tracking-tight mb-2">
          Redirecting to sign in
        </h1>
        <p className="text-sm text-gray-500">
          Password resets are now handled by our identity provider. On the
          sign-in page, click &ldquo;Don&apos;t remember your password?&rdquo; to receive
          a reset link.
        </p>
      </div>
    </div>
  );
}
