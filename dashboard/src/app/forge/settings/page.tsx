"use client";

import { useAuth } from "@/lib/auth";
import PlanGate from "@/components/PlanGate";

export default function ForgeSettingsPage() {
  const { user } = useAuth();

  if (!user?.plan) {
    return <div>Loading...</div>;
  }

  return (
    <PlanGate requiredPlan="pro" currentPlan={user.plan}>
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Forge Settings</h1>
          <p className="text-gray-400 mt-1">
            Forge settings are unavailable in this release.
          </p>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-2">
            Settings Not Available
          </h2>
          <p className="text-gray-400 text-sm max-w-2xl">
            This page does not save preferences until Forge has a server-backed
            settings API. Existing discovery and classification pages are not
            affected.
          </p>
        </div>
      </div>
    </PlanGate>
  );
}
