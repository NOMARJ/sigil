// Brand v1.0 — scan-level attestation Seal (directive 2026-05-04 §1, §3, §4).
//
// 5-tier verdict family. The Seal SVG carries the visual identity; the paired
// text label carries meaning for colour-blind users and terminals. Per directive
// §4 (strict liability), the CLEAN state never reads "Safe to install" — only
// attestation phrasing like "8/8 phases passed".
//
// Below 32px the Seal switches to `sigil-seal-small.svg` (no dots, no inner ring)
// per directive §1.

export type SealVerdictTier = "clean" | "low" | "medium" | "high" | "critical";
export type SealVerdictSize = "sm" | "md" | "lg";

interface SealVerdictProps {
  verdict: SealVerdictTier;
  size?: SealVerdictSize;
  phasesPassed?: number;
  score?: number;
  showLabel?: boolean;
}

const verdictConfig: Record<SealVerdictTier, { src: string; color: string; label: string }> = {
  clean:    { src: "/brand/seal/sigil-seal-clean.svg",    color: "#22C55E", label: "CLEAN" },
  low:      { src: "/brand/seal/sigil-seal-low.svg",      color: "#EAB308", label: "LOW RISK" },
  medium:   { src: "/brand/seal/sigil-seal-medium.svg",   color: "#F97316", label: "MEDIUM RISK" },
  high:     { src: "/brand/seal/sigil-seal-high.svg",     color: "#EF4444", label: "HIGH RISK" },
  critical: { src: "/brand/seal/sigil-seal-critical.svg", color: "#DC2626", label: "CRITICAL" },
};

const sizePx: Record<SealVerdictSize, number> = { sm: 24, md: 56, lg: 96 };
const labelClass: Record<SealVerdictSize, string> = {
  sm: "text-[10px] tracking-[0.12em]",
  md: "text-xs tracking-[0.12em]",
  lg: "text-sm tracking-[0.14em]",
};

/**
 * Map a numeric scan risk score to a verdict tier per directive §3:
 *   0       → clean
 *   1-9     → low
 *   10-24   → medium
 *   25-49   → high
 *   50+     → critical
 */
export function scoreToVerdict(score: number): SealVerdictTier {
  if (score <= 0) return "clean";
  if (score < 10) return "low";
  if (score < 25) return "medium";
  if (score < 50) return "high";
  return "critical";
}

export default function SealVerdict({
  verdict,
  size = "md",
  phasesPassed,
  score,
  showLabel = true,
}: SealVerdictProps) {
  const config = verdictConfig[verdict];
  const px = sizePx[size];
  // Below 32px the Seal loses dots and inner ring for legibility.
  const src = px <= 24 ? "/brand/seal/sigil-seal-small.svg" : config.src;

  const cleanSubtext =
    verdict === "clean" && phasesPassed === 8
      ? "8/8 phases passed"
      : verdict === "clean"
        ? "no findings detected"
        : null;
  const scoreSubtext = typeof score === "number" ? `score ${score}` : null;

  return (
    <span
      className="inline-flex items-center gap-3"
      role="img"
      aria-label={`Sigil verdict: ${config.label}${typeof score === "number" ? `, score ${score}` : ""}`}
    >
      <img
        src={src}
        alt=""
        width={px}
        height={px}
        // Tinted with currentColor when the small variant is in play (it uses
        // currentColor inheritance). The pre-coloured per-verdict variants
        // ignore this; harmless either way.
        style={{ color: config.color }}
        className="block"
      />
      {showLabel && (
        <span className="flex flex-col leading-tight">
          <span
            className={`font-mono font-bold uppercase ${labelClass[size]}`}
            style={{ color: config.color }}
          >
            {config.label}
          </span>
          {(cleanSubtext || scoreSubtext) && (
            <span className="font-mono text-[10px] text-[#787878]">
              {[cleanSubtext, scoreSubtext].filter(Boolean).join(" · ")}
            </span>
          )}
        </span>
      )}
    </span>
  );
}
