import type { Verdict } from "@/lib/types";

const verdictStyles: Record<string, string> = {
  LOW_RISK: "bg-green-500/10 text-green-400 border-green-500/20",
  MEDIUM_RISK: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  HIGH_RISK: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  CRITICAL_RISK: "bg-red-500/10 text-red-400 border-red-500/20",
};

const verdictDots: Record<string, string> = {
  LOW_RISK: "bg-green-400",
  MEDIUM_RISK: "bg-yellow-400",
  HIGH_RISK: "bg-orange-400",
  CRITICAL_RISK: "bg-red-400",
};

/** Display label for verdict (strip _RISK suffix for readability). */
function verdictLabel(v: string): string {
  return v.replace(/_RISK$/, "");
}

const DEFAULT_STYLE = "bg-gray-500/10 text-gray-400 border-gray-500/20";
const DEFAULT_DOT = "bg-gray-400";

interface VerdictBadgeProps {
  verdict: Verdict | string;
  size?: "sm" | "md" | "lg";
}

export default function VerdictBadge({ verdict, size = "md" }: VerdictBadgeProps) {
  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-[10px]",
    md: "px-2.5 py-1 text-xs",
    lg: "px-3 py-1.5 text-sm",
  };

  const dotSizes = {
    sm: "w-1.5 h-1.5",
    md: "w-2 h-2",
    lg: "w-2.5 h-2.5",
  };

  const style = verdictStyles[verdict] ?? DEFAULT_STYLE;
  const dot = verdictDots[verdict] ?? DEFAULT_DOT;

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-semibold tracking-wide uppercase ${style} ${sizeClasses[size]}`}
    >
      <span className={`rounded-full ${dot} ${dotSizes[size]}`} />
      {verdictLabel(verdict)}
    </span>
  );
}
