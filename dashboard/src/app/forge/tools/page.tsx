"use client";

import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";

export default function MyToolsPage() {
  const { user } = useAuth();

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="pro" currentPlan={user.plan}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">My Tools</h1>
          <p className="text-gray-400 mt-1">
            Tracked tool management is unavailable in this release.
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-2">
            Tool Tracking Unavailable
          </h2>
          <p className="text-gray-400 text-sm max-w-2xl">
            Forge classification and discovery remain available, but personal
            tool tracking has no server-backed storage path. No local or sample
            tracked tools are shown here.
          </p>
        </div>
      </div>
    </PlanGate>
  );
}
