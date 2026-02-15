import type { Verdict } from "@/lib/types";

const verdictStyles: Record<Verdict, string> = {
  CLEAN: "bg-green-500/10 text-green-400 border-green-500/20",
  LOW: "bg-blue-500/10 text-blue-400 border-blue-500/20",
  MEDIUM: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  HIGH: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  CRITICAL: "bg-red-500/10 text-red-400 border-red-500/20",
};

const verdictDots: Record<Verdict, string> = {
  CLEAN: "bg-green-400",
  LOW: "bg-blue-400",
  MEDIUM: "bg-yellow-400",
  HIGH: "bg-orange-400",
  CRITICAL: "bg-red-400",
};

interface VerdictBadgeProps {
  verdict: Verdict;
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

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border font-semibold tracking-wide uppercase ${verdictStyles[verdict]} ${sizeClasses[size]}`}
    >
      <span className={`rounded-full ${verdictDots[verdict]} ${dotSizes[size]}`} />
      {verdict}
    </span>
  );
}
