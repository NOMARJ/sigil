"use client";

import { useState, useEffect } from "react";
import { useUser } from "@auth0/nextjs-auth0/client";
import { useRouter, useSearchParams } from "next/navigation";
import OnboardingFlow from "@/components/OnboardingFlow";

export default function ProOnboardingPage(): JSX.Element {
  const { user, isLoading } = useUser();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isProUser, setIsProUser] = useState(false);

  // Check if user has Pro subscription
  useEffect(() => {
    // This would be replaced with actual subscription check
    const userPlan = "pro"; // Mock - would come from user object or API call
    const isPro = userPlan === "pro" || userPlan === "team" || userPlan === "enterprise";
    
    setIsProUser(isPro);
    
    // Redirect non-Pro users to upgrade page
    if (!isPro && !isLoading) {
      router.push("/pro?upgrade=true");
    }
  }, [user, isLoading, router]);

  // Show loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-purple-600"></div>
      </div>
    );
  }

  // Redirect if not authenticated
  if (!user) {
    router.push("/login?returnTo=/onboarding/pro");
    return <div></div>;
  }

  // Show onboarding flow for Pro users
  if (isProUser) {
    return (
      <div className="min-h-screen bg-gray-900">
        <OnboardingFlow />
      </div>
    );
  }

  // Fallback for non-Pro users (shouldn't reach here due to redirect)
  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center">
      <div className="text-center">
        <h1 className="text-2xl font-bold text-white mb-4">
          Pro Subscription Required
        </h1>
        <p className="text-gray-400 mb-6">
          This feature requires a Pro subscription to access AI-powered threat detection.
        </p>
        <button
          onClick={() => router.push("/pro")}
          className="bg-purple-600 hover:bg-purple-700 text-white px-6 py-2 rounded-lg"
        >
          Upgrade to Pro
        </button>
      </div>
    </div>
  );
}