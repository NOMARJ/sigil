interface StatsCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  trend?: number;
  icon: React.ReactNode;
  accentColor?: string;
}

export default function StatsCard({
  title,
  value,
  subtitle,
  trend,
  icon,
  accentColor = "brand",
}: StatsCardProps) {
  const trendIsPositive = trend !== undefined && trend >= 0;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <p className="text-xs font-medium text-gray-500 uppercase tracking-wider">
            {title}
          </p>
          <p className="mt-2 text-3xl font-bold text-gray-100 tracking-tight">
            {value}
          </p>
          {(subtitle || trend !== undefined) && (
            <div className="mt-2 flex items-center gap-2">
              {trend !== undefined && (
                <span
                  className={`inline-flex items-center text-xs font-medium ${
                    trendIsPositive ? "text-green-400" : "text-red-400"
                  }`}
                >
                  {trendIsPositive ? (
                    <svg className="w-3 h-3 mr-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clipRule="evenodd" />
                    </svg>
                  ) : (
                    <svg className="w-3 h-3 mr-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  )}
                  {Math.abs(trend)}%
                </span>
              )}
              {subtitle && (
                <span className="text-xs text-gray-500">{subtitle}</span>
              )}
            </div>
          )}
        </div>
        <div
          className={`flex items-center justify-center w-10 h-10 rounded-lg bg-${accentColor}-500/10 text-${accentColor}-400`}
        >
          {icon}
        </div>
      </div>
    </div>
  );
}
