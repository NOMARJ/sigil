interface ScanBadgeProps {
  scannerVersion?: string;
  rescannedAt?: string;
  size?: "sm" | "md" | "lg";
}

export default function ScanBadge({ scannerVersion, rescannedAt, size = "sm" }: ScanBadgeProps) {
  const sizeClasses = {
    sm: "px-1.5 py-0.5 text-xs",
    md: "px-2 py-1 text-xs",
    lg: "px-3 py-1.5 text-sm",
  };

  // Determine badge type based on scanner version and rescan status
  if (rescannedAt) {
    // Blue "Recently Updated" badge for rescanned items
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20 ${sizeClasses[size]}`}
      >
        <span className="w-1.5 h-1.5 bg-blue-400 rounded-full" />
        Recently Updated
      </span>
    );
  }

  if (!scannerVersion || scannerVersion === "1.0.0") {
    // Yellow "Legacy Scan" badge for v1 scans
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full font-medium bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 ${sizeClasses[size]}`}
      >
        <span className="w-1.5 h-1.5 bg-yellow-400 rounded-full" />
        Legacy Scan
      </span>
    );
  }

  if (scannerVersion === "2.0.0") {
    // Green "Enhanced Scanner" badge for v2 scans
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-full font-medium bg-green-500/10 text-green-400 border border-green-500/20 ${sizeClasses[size]}`}
      >
        <span className="w-1.5 h-1.5 bg-green-400 rounded-full" />
        Enhanced Scanner
      </span>
    );
  }

  // Default badge for unknown versions
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-medium bg-gray-500/10 text-gray-400 border border-gray-500/20 ${sizeClasses[size]}`}
    >
      <span className="w-1.5 h-1.5 bg-gray-400 rounded-full" />
      v{scannerVersion}
    </span>
  );
}