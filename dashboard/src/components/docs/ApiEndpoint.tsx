"use client";

import { useState } from "react";

interface ApiEndpointProps {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  description: string;
  authRequired?: boolean;
  requestBody?: string;
  responseBody?: string;
  children?: React.ReactNode;
}

const methodColors: Record<string, string> = {
  GET: "bg-green-500/10 text-green-400 border-green-500/20",
  POST: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  PUT: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  PATCH: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  DELETE: "bg-red-500/10 text-red-400 border-red-500/20",
};

export default function ApiEndpoint({
  method,
  path,
  description,
  authRequired = true,
  requestBody,
  responseBody,
  children,
}: ApiEndpointProps) {
  const [expanded, setExpanded] = useState(false);
  const [copiedCurl, setCopiedCurl] = useState(false);

  const curlCommand = generateCurl(method, path, requestBody);

  const handleCopyCurl = async () => {
    await navigator.clipboard.writeText(curlCommand);
    setCopiedCurl(true);
    setTimeout(() => setCopiedCurl(false), 2000);
  };

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900 overflow-hidden my-4">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-800/30 transition-colors"
      >
        <span
          className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-bold border ${methodColors[method]}`}
        >
          {method}
        </span>
        <code className="text-sm text-gray-200 font-mono">{path}</code>
        {authRequired && (
          <span className="ml-auto text-xs text-gray-600 flex items-center gap-1">
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Auth
          </span>
        )}
        <svg
          className={`w-4 h-4 text-gray-500 transition-transform ${
            expanded ? "rotate-180" : ""
          } ${authRequired ? "" : "ml-auto"}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div className="border-t border-gray-800 px-4 py-4 space-y-4">
          <p className="text-sm text-gray-400">{description}</p>

          {children}

          {requestBody && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                Request Body
              </h4>
              <pre className="p-3 bg-gray-950 rounded-lg text-sm text-gray-300 overflow-x-auto">
                <code>{requestBody}</code>
              </pre>
            </div>
          )}

          {responseBody && (
            <div>
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider mb-2">
                Response
              </h4>
              <pre className="p-3 bg-gray-950 rounded-lg text-sm text-gray-300 overflow-x-auto">
                <code>{responseBody}</code>
              </pre>
            </div>
          )}

          {/* Copy as curl */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-medium text-gray-500 uppercase tracking-wider">
                cURL
              </h4>
              <button
                onClick={handleCopyCurl}
                className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
              >
                {copiedCurl ? "Copied!" : "Copy"}
              </button>
            </div>
            <pre className="p-3 bg-gray-950 rounded-lg text-sm text-gray-300 overflow-x-auto">
              <code>{curlCommand}</code>
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

function generateCurl(method: string, path: string, body?: string): string {
  const base = "https://api.sigilsec.ai";
  let cmd = `curl -X ${method} \\\n  -H "Authorization: Bearer $TOKEN" \\\n  -H "Content-Type: application/json"`;
  if (body) {
    cmd += ` \\\n  -d '${body}'`;
  }
  cmd += ` \\\n  ${base}${path}`;
  return cmd;
}
