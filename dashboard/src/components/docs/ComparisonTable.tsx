interface Feature {
  name: string;
  values: Record<string, "yes" | "no" | "partial" | string>;
}

interface ComparisonTableProps {
  tools: string[];
  features: Feature[];
  highlightTool?: string;
}

function StatusCell({ value }: { value: string }) {
  if (value === "yes") {
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-green-500/10">
        <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
        </svg>
      </span>
    );
  }

  if (value === "no") {
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-500/10">
        <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
        </svg>
      </span>
    );
  }

  if (value === "partial") {
    return (
      <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-yellow-500/10">
        <svg className="w-4 h-4 text-yellow-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 12H4" />
        </svg>
      </span>
    );
  }

  return <span className="text-sm text-gray-400">{value}</span>;
}

export default function ComparisonTable({
  tools,
  features,
  highlightTool,
}: ComparisonTableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-gray-800">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 bg-gray-900/50">
            <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
              Capability
            </th>
            {tools.map((tool) => (
              <th
                key={tool}
                className={`text-center px-4 py-3 text-xs font-medium uppercase tracking-wider ${
                  tool === highlightTool
                    ? "text-brand-400 bg-brand-500/5"
                    : "text-gray-500"
                }`}
              >
                {tool}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {features.map((feature, i) => (
            <tr
              key={feature.name}
              className={`border-b border-gray-800/50 ${
                i % 2 === 0 ? "" : "bg-gray-900/30"
              }`}
            >
              <td className="px-4 py-3 text-gray-300 font-medium">
                {feature.name}
              </td>
              {tools.map((tool) => (
                <td
                  key={tool}
                  className={`text-center px-4 py-3 ${
                    tool === highlightTool ? "bg-brand-500/5" : ""
                  }`}
                >
                  <StatusCell value={feature.values[tool] ?? "no"} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
