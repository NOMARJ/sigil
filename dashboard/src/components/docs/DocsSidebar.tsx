"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

interface NavItem {
  label: string;
  href: string;
  isNew?: boolean;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const sections: NavSection[] = [
  {
    title: "Getting Started",
    items: [
      { label: "Introduction", href: "/docs" },
      { label: "Quick Start", href: "/docs/getting-started" },
      { label: "Installation", href: "/docs/getting-started#installation" },
    ],
  },
  {
    title: "CLI",
    items: [
      { label: "Command Reference", href: "/docs/cli" },
      { label: "Configuration", href: "/docs/configuration" },
      { label: "Shell Aliases", href: "/docs/configuration#shell-aliases" },
    ],
  },
  {
    title: "Integrations",
    items: [
      { label: "MCP Server", href: "/docs/mcp", isNew: true },
      { label: "VS Code / Cursor", href: "/docs/ide-plugins/vscode" },
      { label: "JetBrains", href: "/docs/ide-plugins/jetbrains" },
      { label: "CI/CD Pipelines", href: "/docs/cicd", isNew: true },
      { label: "GitHub Actions", href: "/docs/cicd#github-actions" },
    ],
  },
  {
    title: "Reference",
    items: [
      { label: "Scan Phases", href: "/docs/scan-phases" },
      { label: "API Reference", href: "/docs/api" },
      { label: "Threat Model", href: "/docs/threat-model" },
    ],
  },
  {
    title: "Advanced",
    items: [
      { label: "Architecture", href: "/docs/architecture" },
      { label: "Deployment", href: "/docs/deployment" },
      { label: "Troubleshooting", href: "/docs/troubleshooting", isNew: true },
    ],
  },
];

interface DocsSidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export default function DocsSidebar({ isOpen = false, onClose }: DocsSidebarProps) {
  const pathname = usePathname();
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set());

  const toggleSection = (title: string) => {
    setCollapsedSections((prev) => {
      const next = new Set(prev);
      if (next.has(title)) {
        next.delete(title);
      } else {
        next.add(title);
      }
      return next;
    });
  };

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-0 left-0 z-40 w-64 h-screen bg-gray-950 border-r border-gray-800 flex flex-col transition-transform duration-200 ease-in-out overflow-y-auto ${
          isOpen ? "translate-x-0" : "-translate-x-full"
        } lg:translate-x-0 lg:sticky lg:top-0`}
      >
        {/* Brand */}
        <div className="flex items-center gap-3 px-5 py-4 border-b border-gray-800">
          <Link href="/" className="flex items-center gap-2">
            <div className="flex items-center justify-center w-7 h-7 rounded-md bg-brand-600 text-white font-bold text-sm">
              S
            </div>
            <span className="text-sm font-bold text-white tracking-tight">
              Sigil Docs
            </span>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {sections.map((section) => {
            const isCollapsed = collapsedSections.has(section.title);

            return (
              <div key={section.title} className="mb-4">
                <button
                  onClick={() => toggleSection(section.title)}
                  className="flex items-center justify-between w-full px-2 py-1.5 text-xs font-semibold text-gray-500 uppercase tracking-wider hover:text-gray-400 transition-colors"
                >
                  {section.title}
                  <svg
                    className={`w-3 h-3 transition-transform ${
                      isCollapsed ? "-rotate-90" : ""
                    }`}
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {!isCollapsed && (
                  <div className="mt-1 space-y-0.5">
                    {section.items.map((item) => {
                      const isActive = pathname === item.href || (item.href !== "/docs" && pathname.startsWith(item.href.split("#")[0]));

                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          onClick={onClose}
                          className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm transition-colors ${
                            isActive
                              ? "bg-brand-600/10 text-brand-400 font-medium"
                              : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                          }`}
                        >
                          {item.label}
                          {item.isNew && (
                            <span className="px-1.5 py-0.5 text-[10px] font-medium bg-brand-500/10 text-brand-400 rounded">
                              New
                            </span>
                          )}
                        </Link>
                      );
                    })}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-gray-800">
          <a
            href="https://github.com/NOMARJ/sigil"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-400 transition-colors"
          >
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            Edit on GitHub
          </a>
        </div>
      </aside>
    </>
  );
}
