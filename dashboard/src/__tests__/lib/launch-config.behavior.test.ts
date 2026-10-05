import type * as Config from '@/lib/launch-config';

// [MOCK] Explicit launch-phase fixtures; no environment or entitlement changes.
const originalPhase = process.env.NEXT_PUBLIC_LAUNCH_PHASE;
function load(phase?: string): typeof Config {
  if (phase === undefined) delete process.env.NEXT_PUBLIC_LAUNCH_PHASE;
  else process.env.NEXT_PUBLIC_LAUNCH_PHASE = phase;
  let config!: typeof Config;
  jest.isolateModules(() => { config = require('@/lib/launch-config'); });
  return config;
}
afterEach(() => {
  if (originalPhase === undefined) delete process.env.NEXT_PUBLIC_LAUNCH_PHASE;
  else process.env.NEXT_PUBLIC_LAUNCH_PHASE = originalPhase;
});

describe('launch configuration', () => {
  it.each([undefined, '', 'constrained'])('defaults %s to constrained features and keeps unimplemented chat hidden', phase => {
    const { launchConfig: config, ProFeature: F } = load(phase);
    expect(config.launchPhase).toBe('constrained');
    expect(config.launchMessage).toBe('Core interactive AI features available');
    expect(config.getEnabledFeatures()).toEqual([F.FINDING_INVESTIGATION, F.FALSE_POSITIVE_VERIFICATION, F.CREDIT_SYSTEM]);
    expect(config.getVisibleFeatures()).toEqual(config.getEnabledFeatures());
    expect(config.canInvestigateFindings).toBe(true);
    expect(config.canVerifyFalsePositives).toBe(true);
    expect(config.canUseInteractiveChat).toBe(false);
    expect(config.canGenerateRemediation).toBe(false);
    expect(config.canAnalyzeAttackChains).toBe(false);
    expect(config.canMapCompliance).toBe(false);
    expect(config.getConstrainedLaunchFeatures()).toEqual({
      finding_investigation: 'Deep-dive analysis of specific security findings',
      false_positive_verification: 'AI-powered verification of false positives',
      credit_system: 'Transparent usage tracking and cost control',
    });
  });
  it('makes session management visible in beta while model routing stays in the background', () => {
    const { launchConfig: config, ProFeature: F } = load('beta');
    expect(config.launchMessage).toBe('Extended Pro features in beta');
    expect(config.getEnabledFeatures()).toEqual([F.FINDING_INVESTIGATION, F.FALSE_POSITIVE_VERIFICATION, F.CREDIT_SYSTEM, F.SESSION_MANAGEMENT, F.SMART_MODEL_ROUTING]);
    expect(config.isFeatureVisible(F.SESSION_MANAGEMENT)).toBe(true);
    expect(config.isFeatureVisible(F.SMART_MODEL_ROUTING)).toBe(false);
    expect(config.canGenerateRemediation).toBe(false);
  });
  it('enables the implemented advanced features in full rollout without exposing hidden features', () => {
    const { launchConfig: config, ProFeature: F } = load('full');
    expect(config.launchMessage).toBe('All Pro features available');
    expect(config.canGenerateRemediation).toBe(true);
    expect(config.canAnalyzeAttackChains).toBe(true);
    expect(config.canMapCompliance).toBe(true);
    expect(config.isFeatureEnabled(F.VERSION_COMPARISON)).toBe(true);
    expect(config.isFeatureEnabled(F.BULK_INVESTIGATION)).toBe(true);
    expect(config.isFeatureEnabled(F.FEEDBACK_LEARNING)).toBe(true);
    expect(config.isFeatureEnabled(F.DYNAMIC_CONTEXT)).toBe(false);
    expect(config.canUseInteractiveChat).toBe(false);
    expect(config.getVisibleFeatures()).toEqual([F.FINDING_INVESTIGATION, F.FALSE_POSITIVE_VERIFICATION, F.CREDIT_SYSTEM, F.SESSION_MANAGEMENT]);
  });
  it('returns fail-closed feature defaults for an unknown feature', () => {
    const { launchConfig: config, useFeature, ProFeature: F } = load('constrained');
    const unknown = 'mock-unrecognized' as Config.ProFeature;
    expect(config.isFeatureEnabled(unknown)).toBe(false);
    expect(config.isFeatureVisible(unknown)).toBe(false);
    expect(config.getFeatureCost(unknown)).toBe(0);
    expect(config.getFeatureDescription(unknown)).toBe('');
    expect(useFeature(unknown)).toEqual({ isEnabled: false, isVisible: false, cost: 0, description: '' });
    expect(useFeature(F.FINDING_INVESTIGATION)).toEqual({ isEnabled: true, isVisible: true, cost: 4, description: 'Deep-dive analysis of specific security findings' });
  });
  it('exposes the singleton and a fallback message for an unknown phase', () => {
    const { launchConfig, useLaunchConfig } = load('mock-unknown-phase');
    expect(useLaunchConfig()).toBe(launchConfig);
    expect(launchConfig.launchMessage).toBe('Features available');
    expect(launchConfig.canGenerateRemediation).toBe(false);
  });
});
