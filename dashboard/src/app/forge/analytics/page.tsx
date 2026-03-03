"use client";

import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";

export default function ForgeAnalyticsPage() {
  const { user } = useAuth();

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="pro" currentPlan={user.plan}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Analytics</h1>
          <p className="text-gray-400 mt-1">
            Advanced analytics and insights for your tracked tools
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
          </svg>
          <h3 className="text-lg font-medium text-gray-400 mb-2">Coming Soon</h3>
          <p className="text-gray-500">
            Advanced analytics and reporting features will be available here soon.
          </p>
        </div>
      </div>
    </PlanGate>
  );
}