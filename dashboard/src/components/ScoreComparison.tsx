interface ScoreComparisonProps {
  originalScore: number;
  newScore: number;
  size?: "sm" | "md" | "lg";
  showPercentage?: boolean;
}

export default function ScoreComparison({ 
  originalScore, 
  newScore, 
  size = "md",
  showPercentage = true 
}: ScoreComparisonProps) {
  const change = newScore - originalScore;
  const changePercentage = originalScore > 0 ? Math.round((change / originalScore) * 100) : 0;
  
  const sizeClasses = {
    sm: {
      original: "text-sm",
      new: "text-sm font-semibold",
      arrow: "w-3 h-3",
      percentage: "text-xs"
    },
    md: {
      original: "text-base",
      new: "text-base font-semibold", 
      arrow: "w-4 h-4",
      percentage: "text-sm"
    },
    lg: {
      original: "text-lg",
      new: "text-lg font-semibold",
      arrow: "w-5 h-5", 
      percentage: "text-base"
    }
  };

  // Color coding: green for decrease (better), red for increase (worse)
  const isImprovement = change < 0;
  const colorClass = isImprovement ? "text-green-400" : change > 0 ? "text-red-400" : "text-gray-400";
  
  const size_config = sizeClasses[size];

  return (
    <div className="flex items-center gap-2">
      {/* Original score with strikethrough */}
      <span className={`line-through text-gray-500 ${size_config.original}`}>
        {originalScore}
      </span>
      
      {/* Arrow indicator */}
      <svg 
        className={`${size_config.arrow} ${colorClass}`}
        fill="none" 
        stroke="currentColor" 
        viewBox="0 0 24 24"
      >
        {isImprovement ? (
          // Down arrow for improvement
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" />
        ) : change > 0 ? (
          // Up arrow for worsening  
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" />
        ) : (
          // Right arrow for no change
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 8l4 4m0 0l-4 4m4-4H3" />
        )}
      </svg>
      
      {/* New score */}
      <span className={`${colorClass} ${size_config.new}`}>
        {newScore}
      </span>
      
      {/* Percentage change */}
      {showPercentage && change !== 0 && (
        <span className={`${colorClass} ${size_config.percentage} ml-1`}>
          ({isImprovement ? '' : '+'}
          {changePercentage}%)
        </span>
      )}
    </div>
  );
}