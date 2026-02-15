import type { Metadata } from "next";
import "./globals.css";
import LayoutShell from "@/components/LayoutShell";

export const metadata: Metadata = {
  title: "Sigil — Security Audit Dashboard",
  description:
    "Automated security auditing for AI agent code. Scan repos, packages, and agent tooling for malicious patterns.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="bg-gray-950 text-gray-100">
        <LayoutShell>{children}</LayoutShell>
      </body>
    </html>
  );
}
