"use client";

import { ReactNode } from "react";
import type { PlanTier } from "@/lib/types";

interface PlanGateProps {
  children: ReactNode;
  requiredPlan: PlanTier;
  currentPlan: PlanTier;
  fallback?: ReactNode;
}

const planHierarchy: Record<PlanTier, number> = {
  free: 0,
  pro: 1,
  team: 2,
  enterprise: 3,
};

const planNames: Record<PlanTier, string> = {
  free: "Free",
  pro: "Pro",
  team: "Team",
  enterprise: "Enterprise",
};

function hasAccess(currentPlan: PlanTier, requiredPlan: PlanTier): boolean {
  return planHierarchy[currentPlan] >= planHierarchy[requiredPlan];
}

export default function PlanGate({ 
  children, 
  requiredPlan, 
  currentPlan,
  fallback 
}: PlanGateProps) {
  if (hasAccess(currentPlan, requiredPlan)) {
    return <>{children}</>;
  }

  if (fallback) {
    return <>{fallback}</>;
  }

  return (
    <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-6 text-center">
      <div className="inline-flex items-center justify-center w-12 h-12 rounded-full bg-amber-500/10 mb-4">
        <svg className="w-6 h-6 text-amber-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h3 className="text-lg font-semibold text-white mb-2">
        {planNames[requiredPlan]} Plan Required
      </h3>
      <p className="text-gray-400 mb-6">
        This feature requires a {planNames[requiredPlan]} plan or higher. 
        You&apos;re currently on the {planNames[currentPlan]} plan.
      </p>
      <button 
        onClick={() => window.open('/settings#billing', '_self')}
        className="inline-flex items-center px-4 py-2 rounded-md bg-brand-600 hover:bg-brand-700 text-white font-medium transition-colors"
      >
        Upgrade Plan
      </button>
    </div>
  );
}