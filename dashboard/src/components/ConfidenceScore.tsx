import type { LLMConfidenceLevel } from "@/lib/types";

interface ConfidenceScoreProps {
  confidence: number;
  confidenceLevel: LLMConfidenceLevel;
  size?: "sm" | "md" | "lg";
  showLabel?: boolean;
  showPercentage?: boolean;
}

export default function ConfidenceScore({
  confidence,
  confidenceLevel,
  size = "md",
  showLabel = true,
  showPercentage = true
}: ConfidenceScoreProps): JSX.Element {
  const percentage = Math.round(confidence * 100);

  // Color mapping based on confidence level
  const colors = {
    low: {
      bg: "bg-gray-600",
      text: "text-gray-400",
      progress: "bg-gray-500"
    },
    medium: {
      bg: "bg-yellow-600",
      text: "text-yellow-400", 
      progress: "bg-yellow-500"
    },
    high: {
      bg: "bg-orange-600",
      text: "text-orange-400",
      progress: "bg-orange-500"
    },
    very_high: {
      bg: "bg-red-600",
      text: "text-red-400",
      progress: "bg-red-500"
    }
  };

  const sizeClasses = {
    sm: {
      height: "h-1.5",
      text: "text-xs",
      spacing: "gap-1"
    },
    md: {
      height: "h-2",
      text: "text-sm", 
      spacing: "gap-2"
    },
    lg: {
      height: "h-3",
      text: "text-base",
      spacing: "gap-3"
    }
  };

  const colorScheme = colors[confidenceLevel];
  const sizeScheme = sizeClasses[size];

  return (
    <div className={`flex items-center ${sizeScheme.spacing}`}>
      {/* Progress bar */}
      <div className="flex-1">
        <div className={`w-full ${sizeScheme.height} bg-gray-800 rounded-full overflow-hidden`}>
          <div 
            className={`${sizeScheme.height} ${colorScheme.progress} rounded-full transition-all duration-300 ease-out`}
            style={{ width: `${percentage}%` }}
          />
        </div>
      </div>

      {/* Label and percentage */}
      <div className={`flex items-center gap-2 ${sizeScheme.text} font-medium`}>
        {showPercentage && (
          <span className={colorScheme.text}>
            {percentage}%
          </span>
        )}
        
        {showLabel && (
          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colorScheme.text} ${colorScheme.bg}/10 border-current/20`}>
            {confidenceLevel.replace('_', ' ').toUpperCase()}
          </span>
        )}
      </div>
    </div>
  );
}

// Utility component for showing confidence distribution
interface ConfidenceDistributionProps {
  summary: Record<string, number>;
  total: number;
}

export function ConfidenceDistribution({ 
  summary, 
  total 
}: ConfidenceDistributionProps): JSX.Element {
  const levels: LLMConfidenceLevel[] = ["very_high", "high", "medium", "low"];
  const colors = {
    very_high: "bg-red-500",
    high: "bg-orange-500", 
    medium: "bg-yellow-500",
    low: "bg-gray-500"
  };

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-medium text-gray-300">Confidence Distribution</h4>
      
      {/* Stacked bar */}
      <div className="flex h-2 bg-gray-800 rounded-full overflow-hidden">
        {levels.map((level) => {
          const count = summary[level] || 0;
          const percentage = total > 0 ? (count / total) * 100 : 0;
          
          if (percentage === 0) return null;
          
          return (
            <div
              key={level}
              className={`${colors[level]} transition-all duration-300`}
              style={{ width: `${percentage}%` }}
              title={`${level}: ${count} insights`}
            />
          );
        })}
      </div>

      {/* Legend */}
      <div className="grid grid-cols-2 gap-2 text-xs">
        {levels.map((level) => {
          const count = summary[level] || 0;
          if (count === 0) return null;
          
          return (
            <div key={level} className="flex items-center gap-2">
              <div className={`w-2 h-2 ${colors[level]} rounded-full`} />
              <span className="text-gray-400">
                {level.replace('_', ' ')}: {count}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}