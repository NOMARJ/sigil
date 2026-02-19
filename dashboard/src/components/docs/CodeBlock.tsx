"use client";

import { useState } from "react";

interface CodeBlockProps {
  code: string;
  language?: string;
  filename?: string;
  showLineNumbers?: boolean;
  diff?: boolean;
}

export default function CodeBlock({
  code,
  language = "bash",
  filename,
  showLineNumbers = false,
  diff = false,
}: CodeBlockProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lines = code.split("\n");

  return (
    <div className="group relative rounded-lg border border-gray-800 bg-gray-900 overflow-hidden">
      {/* Header */}
      {(filename || language) && (
        <div className="flex items-center justify-between px-4 py-2 border-b border-gray-800 bg-gray-900/50">
          <span className="text-xs font-medium text-gray-500 font-mono">
            {filename ?? language}
          </span>
          <button
            onClick={handleCopy}
            className="text-xs text-gray-500 hover:text-gray-300 transition-colors opacity-0 group-hover:opacity-100"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
      )}

      {/* Code */}
      <div className="overflow-x-auto">
        <pre className="p-4 text-sm leading-relaxed">
          <code className={`language-${language}`}>
            {lines.map((line, i) => (
              <div key={i} className={`flex ${getDiffClass(line, diff)}`}>
                {showLineNumbers && (
                  <span className="select-none pr-4 text-right w-8 text-gray-600 text-xs leading-relaxed">
                    {i + 1}
                  </span>
                )}
                <span className="flex-1 text-gray-300">{line}</span>
              </div>
            ))}
          </code>
        </pre>
      </div>

      {/* Floating copy button (when no header) */}
      {!filename && !language && (
        <button
          onClick={handleCopy}
          className="absolute top-2 right-2 text-xs text-gray-500 hover:text-gray-300 transition-colors opacity-0 group-hover:opacity-100 bg-gray-800 px-2 py-1 rounded"
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      )}
    </div>
  );
}

function getDiffClass(line: string, diff: boolean): string {
  if (!diff) return "";
  if (line.startsWith("+")) return "bg-green-500/10 text-green-400";
  if (line.startsWith("-")) return "bg-red-500/10 text-red-400";
  return "";
}
