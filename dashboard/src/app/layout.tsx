import type { Metadata } from "next";
import "./globals.css";
import LayoutShell from "@/components/LayoutShell";
import PostHogProvider from "@/components/PostHogProvider";

export const metadata: Metadata = {
  title: "Sigil — Security Audit Dashboard",
  description:
    "Automated security auditing for AI agent code. Scan repos, packages, and agent tooling for malicious patterns.",
  icons: {
    icon: [
      { url: "/brand/favicon/favicon.svg", type: "image/svg+xml" },
      {
        url: "/brand/favicon/favicon-dark.svg",
        type: "image/svg+xml",
        media: "(prefers-color-scheme: light)",
      },
    ],
  },
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: "#0A0A0A",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-[#0A0A0A] text-[#E5E5E5]">
        <PostHogProvider>
          <LayoutShell>{children}</LayoutShell>
        </PostHogProvider>
      </body>
    </html>
  );
}
