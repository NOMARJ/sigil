"use client";

import { useState } from "react";
import { usePathname } from "next/navigation";
import { AuthProvider } from "@/lib/auth";
import AuthGuard from "@/components/AuthGuard";
import Sidebar from "@/components/Sidebar";
import { ErrorBoundary } from "./ErrorBoundary";

/** Routes where the sidebar should be hidden (full-screen layouts). */
const NO_SIDEBAR_ROUTES = ["/login", "/bot", "/methodology", "/terms", "/privacy"];

interface LayoutShellProps {
  children: React.ReactNode;
}

export default function LayoutShell({ children }: LayoutShellProps) {
  const pathname = usePathname();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const hideSidebar = NO_SIDEBAR_ROUTES.some(
    (route) => pathname === route || pathname.startsWith(route + "/"),
  );

  return (
    <AuthProvider>
      <AuthGuard>
        {hideSidebar ? (
          <main className="min-h-screen">
            <div className="p-8">
              <ErrorBoundary>{children}</ErrorBoundary>
            </div>
          </main>
        ) : (
          <>
            <Sidebar
              isOpen={sidebarOpen}
              onClose={() => setSidebarOpen(false)}
            />
            {/* Mobile hamburger button */}
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="fixed top-4 left-4 z-50 p-2 rounded-lg bg-gray-900 border border-gray-800 text-gray-400 hover:text-gray-200 lg:hidden"
              aria-label="Open sidebar"
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <main className="lg:ml-64 min-h-screen">
              <div className="p-8">
                <ErrorBoundary>{children}</ErrorBoundary>
              </div>
            </main>
          </>
        )}
      </AuthGuard>
    </AuthProvider>
  );
}
