"use client";

import { usePathname } from "next/navigation";
import { AuthProvider } from "@/lib/auth";
import AuthGuard from "@/components/AuthGuard";
import Sidebar from "@/components/Sidebar";

/** Routes where the sidebar should be hidden (full-screen layouts). */
const NO_SIDEBAR_ROUTES = ["/login"];

interface LayoutShellProps {
  children: React.ReactNode;
}

export default function LayoutShell({ children }: LayoutShellProps) {
  const pathname = usePathname();

  const hideSidebar = NO_SIDEBAR_ROUTES.some(
    (route) => pathname === route || pathname.startsWith(route + "/"),
  );

  return (
    <AuthProvider>
      <AuthGuard>
        {hideSidebar ? (
          <main className="min-h-screen">
            <div className="p-8">{children}</div>
          </main>
        ) : (
          <>
            <Sidebar />
            <main className="ml-64 min-h-screen">
              <div className="p-8">{children}</div>
            </main>
          </>
        )}
      </AuthGuard>
    </AuthProvider>
  );
}
