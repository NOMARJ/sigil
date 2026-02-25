"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";

/** Routes that do not require authentication. */
const PUBLIC_ROUTES = ["/login", "/auth/callback", "/reset-password"];

interface AuthGuardProps {
  children: React.ReactNode;
}

export default function AuthGuard({ children }: AuthGuardProps) {
  const { user, loading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();

  const isPublicRoute = PUBLIC_ROUTES.some(
    (route) => pathname === route || pathname.startsWith(route + "/"),
  );

  useEffect(() => {
    if (loading) return;

    if (!user && !isPublicRoute) {
      router.replace("/login");
    }

    if (user && isPublicRoute) {
      router.replace("/");
    }
  }, [user, loading, isPublicRoute, router]);

  // Show a loading state while checking auth
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="flex flex-col items-center gap-4">
          <div className="flex items-center justify-center w-12 h-12 rounded-xl bg-brand-600 text-white font-bold text-xl animate-pulse">
            S
          </div>
          <div className="flex items-center gap-2 text-sm text-gray-500">
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
            Loading...
          </div>
        </div>
      </div>
    );
  }

  // If not authenticated and not on a public route, don't render children
  // (redirect will happen via useEffect above)
  if (!user && !isPublicRoute) {
    return null;
  }

  // If authenticated and on a public route, don't render children
  // (redirect will happen via useEffect above)
  if (user && isPublicRoute) {
    return null;
  }

  return <>{children}</>;
}
