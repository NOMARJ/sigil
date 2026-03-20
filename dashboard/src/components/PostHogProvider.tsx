"use client";

import posthog from "posthog-js";
import { useEffect } from "react";

interface PostHogProviderProps {
  children: React.ReactNode;
}

export default function PostHogProvider({ children }: PostHogProviderProps) {
  useEffect(() => {
    const key = process.env.NEXT_PUBLIC_POSTHOG_KEY;

    if (!key) {
      return;
    }

    if (typeof navigator !== "undefined" && navigator.doNotTrack === "1") {
      return;
    }

    posthog.init(key, {
      api_host:
        process.env.NEXT_PUBLIC_POSTHOG_HOST ?? "https://app.posthog.com",
      autocapture: false,
      capture_pageview: true,
      persistence: "localStorage+cookie",
    });
  }, []);

  return <>{children}</>;
}
