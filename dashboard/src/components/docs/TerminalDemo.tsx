"use client";

import { useState, useEffect, useRef } from "react";

interface TerminalLine {
  text: string;
  color?: "green" | "red" | "yellow" | "blue" | "cyan" | "gray" | "white" | "bold";
  delay?: number;
}

interface TerminalDemoProps {
  lines: TerminalLine[];
  title?: string;
  autoplay?: boolean;
  speed?: number;
}

const colorClasses: Record<string, string> = {
  green: "text-green-400",
  red: "text-red-400",
  yellow: "text-yellow-400",
  blue: "text-blue-400",
  cyan: "text-cyan-400",
  gray: "text-gray-500",
  white: "text-gray-100",
  bold: "text-gray-100 font-bold",
};

export default function TerminalDemo({
  lines,
  title = "Terminal",
  autoplay = true,
  speed = 50,
}: TerminalDemoProps) {
  const [visibleLines, setVisibleLines] = useState<number>(autoplay ? 0 : lines.length);
  const [isPlaying, setIsPlaying] = useState(autoplay);
  const containerRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);

  useEffect(() => {
    if (!isPlaying) return;

    if (visibleLines >= lines.length) {
      setIsPlaying(false);
      return;
    }

    const currentLine = lines[visibleLines];
    const delay = currentLine?.delay ?? speed;

    timeoutRef.current = setTimeout(() => {
      setVisibleLines((prev) => prev + 1);
    }, delay);

    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, [visibleLines, isPlaying, lines, speed]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [visibleLines]);

  const handleRestart = () => {
    setVisibleLines(0);
    setIsPlaying(true);
  };

  const handleToggle = () => {
    if (visibleLines >= lines.length) {
      handleRestart();
    } else {
      setIsPlaying(!isPlaying);
    }
  };

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 overflow-hidden">
      {/* Title bar */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-gray-900 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500/60" />
            <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
            <span className="w-3 h-3 rounded-full bg-green-500/60" />
          </div>
          <span className="text-xs text-gray-500 ml-2 font-mono">{title}</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleToggle}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            title={isPlaying ? "Pause" : "Play"}
          >
            {isPlaying ? (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 9v6m4-6v6" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              </svg>
            )}
          </button>
          <button
            onClick={handleRestart}
            className="text-gray-500 hover:text-gray-300 transition-colors"
            title="Restart"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
          </button>
        </div>
      </div>

      {/* Terminal content */}
      <div
        ref={containerRef}
        className="p-4 font-mono text-sm leading-relaxed max-h-96 overflow-y-auto"
      >
        {lines.slice(0, visibleLines).map((line, i) => (
          <div key={i} className={colorClasses[line.color ?? "white"]}>
            {line.text}
          </div>
        ))}
        {isPlaying && visibleLines < lines.length && (
          <span className="inline-block w-2 h-4 bg-gray-400 animate-pulse" />
        )}
      </div>
    </div>
  );
}
