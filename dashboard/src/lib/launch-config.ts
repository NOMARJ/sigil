/**
 * Frontend Launch Configuration
 * 
 * Controls which Pro features are visible and available in the UI
 * during constrained launch phase.
 */

export enum LaunchPhase {
  CONSTRAINED = "constrained",
  BETA_EXPANSION = "beta", 
  FULL_ROLLOUT = "full"
}

export enum ProFeature {
  // Core Features (Constrained Launch)
  FINDING_INVESTIGATION = "finding_investigation",
  FALSE_POSITIVE_VERIFICATION = "false_positive_verification", 
  INTERACTIVE_CHAT = "interactive_chat",
  CREDIT_SYSTEM = "credit_system",
  
  // Beta Features (Post-Launch)
  SESSION_MANAGEMENT = "session_management",
  SMART_MODEL_ROUTING = "smart_model_routing",
  
  // Advanced Features (v2 - Hidden)
  REMEDIATION_GENERATION = "remediation_generation",
  ATTACK_CHAIN_ANALYSIS = "attack_chain_analysis", 
  VERSION_COMPARISON = "version_comparison",
  DYNAMIC_CONTEXT = "dynamic_context",
  COMPLIANCE_MAPPING = "compliance_mapping",
  BULK_INVESTIGATION = "bulk_investigation",
  FEEDBACK_LEARNING = "feedback_learning"
}

interface FeatureConfig {
  enabled: boolean;
  description: string;
  creditCost: number;
  userVisible: boolean;
  requiresBeta?: boolean;
}

class LaunchConfig {
  private currentPhase: LaunchPhase;
  private featureConfigs: Map<ProFeature, FeatureConfig>;

  constructor() {
    this.currentPhase = this.getLaunchPhase();
    this.featureConfigs = this.initializeFeatures();
  }

  private getLaunchPhase(): LaunchPhase {
    // Get from environment or default to constrained
    const phase = process.env.NEXT_PUBLIC_LAUNCH_PHASE || "constrained";
    return (phase as LaunchPhase) || LaunchPhase.CONSTRAINED;
  }

  private initializeFeatures(): Map<ProFeature, FeatureConfig> {
    const features = new Map<ProFeature, FeatureConfig>();

    // Core features (always enabled)
    const coreFeatures: [ProFeature, FeatureConfig][] = [
      [ProFeature.FINDING_INVESTIGATION, {
        enabled: true,
        description: "Deep-dive analysis of specific security findings",
        creditCost: 4,
        userVisible: true
      }],
      [ProFeature.FALSE_POSITIVE_VERIFICATION, {
        enabled: true, 
        description: "AI-powered verification of false positives",
        creditCost: 4,
        userVisible: true
      }],
      [ProFeature.INTERACTIVE_CHAT, {
        enabled: true,
        description: "Ask questions about your scan results", 
        creditCost: 2,
        userVisible: true
      }],
      [ProFeature.CREDIT_SYSTEM, {
        enabled: true,
        description: "Transparent usage tracking and cost control",
        creditCost: 0,
        userVisible: true
      }]
    ];

    // Beta features
    const betaEnabled = [LaunchPhase.BETA_EXPANSION, LaunchPhase.FULL_ROLLOUT].includes(this.currentPhase);
    const betaFeatures: [ProFeature, FeatureConfig][] = [
      [ProFeature.SESSION_MANAGEMENT, {
        enabled: betaEnabled,
        description: "Save and resume investigation sessions",
        creditCost: 0,
        userVisible: betaEnabled,
        requiresBeta: true
      }],
      [ProFeature.SMART_MODEL_ROUTING, {
        enabled: betaEnabled,
        description: "Automatic model selection for cost optimization", 
        creditCost: 0,
        userVisible: false // Background feature
      }]
    ];

    // Advanced features (v2 only)
    const fullEnabled = this.currentPhase === LaunchPhase.FULL_ROLLOUT;
    const advancedFeatures: [ProFeature, FeatureConfig][] = [
      [ProFeature.REMEDIATION_GENERATION, {
        enabled: fullEnabled,
        description: "AI-generated secure code fixes",
        creditCost: 6,
        userVisible: false // Hidden until v2
      }],
      [ProFeature.ATTACK_CHAIN_ANALYSIS, {
        enabled: fullEnabled,
        description: "Trace attack chains through code",
        creditCost: 12,
        userVisible: false
      }],
      [ProFeature.VERSION_COMPARISON, {
        enabled: fullEnabled,
        description: "Compare security between versions",
        creditCost: 8,
        userVisible: false
      }],
      [ProFeature.DYNAMIC_CONTEXT, {
        enabled: false, // Not implemented
        description: "Expand analysis context dynamically",
        creditCost: 4,
        userVisible: false
      }],
      [ProFeature.COMPLIANCE_MAPPING, {
        enabled: fullEnabled,
        description: "Map findings to compliance frameworks",
        creditCost: 3, 
        userVisible: false
      }],
      [ProFeature.BULK_INVESTIGATION, {
        enabled: fullEnabled,
        description: "Investigate similar findings in bulk",
        creditCost: 10,
        userVisible: false
      }],
      [ProFeature.FEEDBACK_LEARNING, {
        enabled: fullEnabled,
        description: "Learn from user feedback to improve accuracy",
        creditCost: 0,
        userVisible: false
      }]
    ];

    // Add all features to map
    [...coreFeatures, ...betaFeatures, ...advancedFeatures].forEach(([feature, config]) => {
      features.set(feature, config);
    });

    return features;
  }

  isFeatureEnabled(feature: ProFeature): boolean {
    return this.featureConfigs.get(feature)?.enabled ?? false;
  }

  isFeatureVisible(feature: ProFeature): boolean {
    const config = this.featureConfigs.get(feature);
    return (config?.enabled && config?.userVisible) ?? false;
  }

  getEnabledFeatures(): ProFeature[] {
    return Array.from(this.featureConfigs.entries())
      .filter(([, config]) => config.enabled)
      .map(([feature]) => feature);
  }

  getVisibleFeatures(): ProFeature[] {
    return Array.from(this.featureConfigs.entries())
      .filter(([, config]) => config.enabled && config.userVisible)
      .map(([feature]) => feature);
  }

  getFeatureCost(feature: ProFeature): number {
    return this.featureConfigs.get(feature)?.creditCost ?? 0;
  }

  getFeatureDescription(feature: ProFeature): string {
    return this.featureConfigs.get(feature)?.description ?? "";
  }

  getConstrainedLaunchFeatures(): Record<string, string> {
    const features: Record<string, string> = {};
    
    [
      ProFeature.FINDING_INVESTIGATION,
      ProFeature.FALSE_POSITIVE_VERIFICATION,
      ProFeature.INTERACTIVE_CHAT,
      ProFeature.CREDIT_SYSTEM
    ].forEach(feature => {
      if (this.isFeatureVisible(feature)) {
        features[feature] = this.getFeatureDescription(feature);
      }
    });

    return features;
  }

  get launchPhase(): LaunchPhase {
    return this.currentPhase;
  }

  get launchMessage(): string {
    const messages = {
      [LaunchPhase.CONSTRAINED]: "Core interactive AI features available",
      [LaunchPhase.BETA_EXPANSION]: "Extended Pro features in beta",
      [LaunchPhase.FULL_ROLLOUT]: "All Pro features available"
    };
    return messages[this.currentPhase] || "Features available";
  }

  // Helper methods for specific feature checks
  get canInvestigateFindings(): boolean {
    return this.isFeatureEnabled(ProFeature.FINDING_INVESTIGATION);
  }

  get canVerifyFalsePositives(): boolean {
    return this.isFeatureEnabled(ProFeature.FALSE_POSITIVE_VERIFICATION);
  }

  get canUseInteractiveChat(): boolean {
    return this.isFeatureEnabled(ProFeature.INTERACTIVE_CHAT);
  }

  get canGenerateRemediation(): boolean {
    return this.isFeatureEnabled(ProFeature.REMEDIATION_GENERATION);
  }

  get canAnalyzeAttackChains(): boolean {
    return this.isFeatureEnabled(ProFeature.ATTACK_CHAIN_ANALYSIS);
  }

  get canMapCompliance(): boolean {
    return this.isFeatureEnabled(ProFeature.COMPLIANCE_MAPPING);
  }
}

// Global instance
export const launchConfig = new LaunchConfig();

// React hook for components
export function useLaunchConfig() {
  return launchConfig;
}

// Helper function for feature checks in components
export function useFeature(feature: ProFeature) {
  return {
    isEnabled: launchConfig.isFeatureEnabled(feature),
    isVisible: launchConfig.isFeatureVisible(feature),
    cost: launchConfig.getFeatureCost(feature),
    description: launchConfig.getFeatureDescription(feature)
  };
}