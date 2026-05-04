import type { Verdict } from "@/lib/types";

// Brand v1.0 verdict family — 5-tier scale (directive 2026-05-04 §3).
//   CLEAN    score 0      #22C55E
//   LOW      score 1-9    #EAB308
//   MEDIUM   score 10-24  #F97316
//   HIGH     score 25-49  #EF4444
//   CRITICAL score 50+    #DC2626
const verdictStyles: Record<string, string> = {
  CLEAN:         "bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/20",
  LOW_RISK:      "bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/20",
  MEDIUM_RISK:   "bg-[#F97316]/10 text-[#F97316] border-[#F97316]/20",
  HIGH_RISK:     "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/20",
  CRITICAL_RISK: "bg-[#DC2626]/10 text-[#DC2626] border-[#DC2626]/30",
};

const verdictDots: Record<string, string> = {
  CLEAN:         "bg-[#22C55E]",
  LOW_RISK:      "bg-[#EAB308]",
  MEDIUM_RISK:   "bg-[#F97316]",
  HIGH_RISK:     "bg-[#EF4444]",
  CRITICAL_RISK: "bg-[#DC2626]",
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
