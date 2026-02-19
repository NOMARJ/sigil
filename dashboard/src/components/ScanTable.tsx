"use client";

import Link from "next/link";
import type { Scan } from "@/lib/types";
import VerdictBadge from "./VerdictBadge";

interface ScanTableProps {
  scans: Scan[];
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function sourceIcon(source: string): string {
  switch (source) {
    case "pip":
      return "PyPI";
    case "npm":
      return "npm";
    case "git":
      return "Git";
    case "local":
      return "Local";
    default:
      return source;
  }
}

export default function ScanTable({ scans }: ScanTableProps) {
  if (scans.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <svg className="w-12 h-12 mx-auto mb-3 text-gray-700" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
        </svg>
        <p className="text-sm">No scans found</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-gray-500 text-left">
            <th className="pb-3 pr-4 font-medium">Package</th>
            <th className="pb-3 pr-4 font-medium">Source</th>
            <th className="pb-3 pr-4 font-medium">Verdict</th>
            <th className="pb-3 pr-4 font-medium">Score</th>
            <th className="pb-3 pr-4 font-medium">Findings</th>
            <th className="pb-3 font-medium">Date</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/50">
          {scans.map((scan) => (
            <tr
              key={scan.id}
              className="hover:bg-gray-800/30 transition-colors"
            >
              <td className="py-3 pr-4">
                <Link
                  href={`/scans/${scan.id}`}
                  className="text-gray-100 hover:text-brand-400 font-medium transition-colors"
                >
                  {scan.package_name}
                  {scan.package_version && (
                    <span className="text-gray-500 font-normal ml-1">
                      @{scan.package_version}
                    </span>
                  )}
                </Link>
              </td>
              <td className="py-3 pr-4">
                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
                  {sourceIcon(scan.source)}
                </span>
              </td>
              <td className="py-3 pr-4">
                <VerdictBadge verdict={scan.verdict} size="sm" />
              </td>
              <td className="py-3 pr-4 font-mono text-gray-300">
                {scan.score}
              </td>
              <td className="py-3 pr-4 text-gray-400">
                {scan.findings_count}
              </td>
              <td className="py-3 text-gray-500 text-xs">
                {formatDate(scan.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
