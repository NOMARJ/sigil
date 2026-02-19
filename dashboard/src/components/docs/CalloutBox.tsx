interface CalloutBoxProps {
  variant: "info" | "warning" | "tip" | "danger";
  title?: string;
  children: React.ReactNode;
}

const variantStyles = {
  info: {
    container: "border-blue-500/30 bg-blue-500/5",
    icon: "text-blue-400",
    title: "text-blue-400",
    iconPath: "M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  },
  warning: {
    container: "border-yellow-500/30 bg-yellow-500/5",
    icon: "text-yellow-400",
    title: "text-yellow-400",
    iconPath: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z",
  },
  tip: {
    container: "border-green-500/30 bg-green-500/5",
    icon: "text-green-400",
    title: "text-green-400",
    iconPath: "M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z",
  },
  danger: {
    container: "border-red-500/30 bg-red-500/5",
    icon: "text-red-400",
    title: "text-red-400",
    iconPath: "M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z",
  },
};

const defaultTitles = {
  info: "Note",
  warning: "Warning",
  tip: "Tip",
  danger: "Danger",
};

export default function CalloutBox({ variant, title, children }: CalloutBoxProps) {
  const styles = variantStyles[variant];
  const displayTitle = title ?? defaultTitles[variant];

  return (
    <div className={`rounded-lg border-l-4 p-4 my-4 ${styles.container}`}>
      <div className="flex items-start gap-3">
        <svg
          className={`w-5 h-5 mt-0.5 flex-shrink-0 ${styles.icon}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d={styles.iconPath}
          />
        </svg>
        <div className="flex-1 min-w-0">
          <p className={`text-sm font-semibold mb-1 ${styles.title}`}>
            {displayTitle}
          </p>
          <div className="text-sm text-gray-300 leading-relaxed">{children}</div>
        </div>
      </div>
    </div>
  );
}
