"use client";

import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";

export default function ForgeMonitoringPage() {
  const { user } = useAuth();

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="team" currentPlan={user.plan}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Monitoring</h1>
          <p className="text-gray-400 mt-1">
            Real-time monitoring and alerting for your AI tools and frameworks
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-12 text-center">
          <svg className="w-16 h-16 text-gray-600 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 4V2c0-1.1.9-2 2-2h6c1.1 0 2 .9 2 2v2h4c1.1 0 2 .9 2 2v11c0 1.1-.9 2-2 2H3c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2h4zM9 4h6V2H9v2zm3 8l4-4-1.41-1.41L12 9.17 9.91 7.09 8.5 8.5 12 12z" />
          </svg>
          <h3 className="text-lg font-medium text-gray-400 mb-2">Coming Soon</h3>
          <p className="text-gray-500">
            Real-time monitoring and alerting features will be available here soon.
          </p>
        </div>
      </div>
    </PlanGate>
  );
}