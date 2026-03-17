interface ConfidenceBadgeProps {
  confidence?: "HIGH" | "MEDIUM" | "LOW";
  size?: "sm" | "md" | "lg";
}

export default function ConfidenceBadge({ confidence, size = "sm" }: ConfidenceBadgeProps) {
  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-xs",
    md: "px-2 py-1 text-xs", 
    lg: "px-3 py-1.5 text-sm",
  };

  // Graceful handling of missing confidence (v1 scans)
  if (!confidence) {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full font-medium bg-gray-500/10 text-gray-500 border border-gray-500/20 ${sizeClasses[size]}`}
      >
        <span className="w-1.5 h-1.5 bg-gray-500 rounded-full" />
        —
      </span>
    );
  }

  // Color mapping: HIGH = red, MEDIUM = yellow, LOW = gray
  const confidenceStyles = {
    HIGH: {
      bg: "bg-red-500/10",
      text: "text-red-400", 
      border: "border-red-500/20",
      dot: "bg-red-400"
    },
    MEDIUM: {
      bg: "bg-yellow-500/10",
      text: "text-yellow-400",
      border: "border-yellow-500/20", 
      dot: "bg-yellow-400"
    },
    LOW: {
      bg: "bg-gray-500/10",
      text: "text-gray-400",
      border: "border-gray-500/20",
      dot: "bg-gray-400"
    }
  };

  const style = confidenceStyles[confidence];

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-medium ${style.bg} ${style.text} border ${style.border} ${sizeClasses[size]}`}
    >
      <span className={`w-1.5 h-1.5 ${style.dot} rounded-full`} />
      {confidence}
    </span>
  );
}