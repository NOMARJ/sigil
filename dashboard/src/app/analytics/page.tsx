'use client';

/**
 * Analytics Dashboard for Sigil Pro
 * 
 * Displays usage metrics, threat discoveries, and engagement analytics
 * for Pro users to track their security analysis insights and costs.
 */

import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { 
  Activity, 
  TrendingUp, 
  Shield, 
  DollarSign, 
  AlertTriangle, 
  Eye,
  Clock,
  Target,
  BarChart3,
  Calendar
} from 'lucide-react';

// Types for analytics data
interface UserUsageStats {
  user_id: string;
  current_period_start: string;
  scans_this_period: number;
  tokens_used: number;
  cost_this_period: number;
  threats_discovered: number;
  zero_days_found: number;
  plan_limits: {
    max_scans_per_month: number;
    max_tokens_per_month: number;
    max_cost_per_month: number;
  };
  usage_by_day: Array<{
    date: string;
    scans: number;
    tokens: number;
    insights: number;
    threats: number;
  }>;
  top_threat_categories: Array<{
    threat_type: string;
    count: number;
    avg_confidence: number;
  }>;
}

interface ChurnRiskMetrics {
  user_id: string;
  risk_score: number;
  risk_category: string;
  last_scan_date: string | null;
  monthly_scans: number;
  threat_hit_rate: number;
  avg_session_duration: number;
  feature_adoption_score: number;
}

// Components
const MetricCard: React.FC<{
  title: string;
  value: string | number;
  change?: string;
  icon: React.ReactNode;
  trend?: 'up' | 'down' | 'neutral';
}> = ({ title, value, change, icon, trend = 'neutral' }) => {
  const trendColor = trend === 'up' ? 'text-green-600' : trend === 'down' ? 'text-red-600' : 'text-gray-600';

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-gray-600">{title}</p>
            <p className="text-2xl font-bold">{value}</p>
            {change && (
              <p className={`text-xs ${trendColor} flex items-center mt-1`}>
                <TrendingUp className="w-3 h-3 mr-1" />
                {change}
              </p>
            )}
          </div>
          <div className="text-blue-600">
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

const ThreatCategoryChart: React.FC<{ categories: UserUsageStats['top_threat_categories'] }> = ({ categories }) => {
  if (!categories.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Top Threat Categories</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-gray-500 text-center py-4">No threats discovered yet</p>
        </CardContent>
      </Card>
    );
  }

  const maxCount = Math.max(...categories.map(c => c.count));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Top Threat Categories</CardTitle>
        <CardDescription>Most frequently discovered threat types</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {categories.map((category) => (
            <div key={category.threat_type} className="flex items-center space-x-4">
              <div className="flex-1">
                <div className="flex justify-between items-center mb-2">
                  <span className="text-sm font-medium capitalize">
                    {category.threat_type.replace(/_/g, ' ')}
                  </span>
                  <div className="flex items-center space-x-2">
                    <Badge variant="outline" className="text-xs">
                      {category.count} found
                    </Badge>
                    <Badge 
                      variant={category.avg_confidence > 0.8 ? "default" : "secondary"}
                      className="text-xs"
                    >
                      {(category.avg_confidence * 100).toFixed(0)}% confidence
                    </Badge>
                  </div>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{ width: `${(category.count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

const UsageChart: React.FC<{ data: UserUsageStats['usage_by_day'] }> = ({ data }) => {
  if (!data.length) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Usage Trend</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-gray-500 text-center py-4">No usage data available</p>
        </CardContent>
      </Card>
    );
  }

  const maxScans = Math.max(...data.map(d => d.scans));

  return (
    <Card>
      <CardHeader>
        <CardTitle>Usage Trend</CardTitle>
        <CardDescription>Daily scanning activity</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {data.slice(0, 14).map((day) => (
            <div key={day.date} className="flex items-center space-x-4">
              <div className="w-16 text-xs text-gray-600">
                {new Date(day.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
              </div>
              <div className="flex-1">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-sm">
                    {day.scans} scans, {day.threats} threats
                  </span>
                  <span className="text-xs text-gray-500">
                    {day.tokens.toLocaleString()} tokens
                  </span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full"
                    style={{ width: maxScans > 0 ? `${(day.scans / maxScans) * 100}%` : '0%' }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

const EngagementMetrics: React.FC<{ metrics: ChurnRiskMetrics }> = ({ metrics }) => {
  const getRiskColor = (category: string) => {
    switch (category) {
      case 'HEALTHY': return 'text-green-600 bg-green-100';
      case 'LOW_ENGAGEMENT': return 'text-yellow-600 bg-yellow-100';
      case 'ENGAGEMENT_METRICS': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Engagement Insights</CardTitle>
        <CardDescription>Your usage patterns and feature adoption</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-2">
            <label className="text-sm font-medium">Engagement Level</label>
            <Badge className={getRiskColor(metrics.risk_category)}>
              {metrics.risk_category === 'ENGAGEMENT_METRICS' ? 'Active' : metrics.risk_category.toLowerCase()}
            </Badge>
          </div>
          
          <div className="space-y-2">
            <label className="text-sm font-medium">Monthly Activity</label>
            <p className="text-lg font-semibold">{metrics.monthly_scans} scans</p>
          </div>
          
          <div className="space-y-2">
            <label className="text-sm font-medium">Threat Discovery Rate</label>
            <p className="text-lg font-semibold">{(metrics.threat_hit_rate * 100).toFixed(1)}%</p>
          </div>
          
          <div className="space-y-2">
            <label className="text-sm font-medium">Feature Adoption</label>
            <div className="flex items-center space-x-2">
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full"
                  style={{ width: `${metrics.feature_adoption_score * 100}%` }}
                />
              </div>
              <span className="text-xs text-gray-600">
                {(metrics.feature_adoption_score * 100).toFixed(0)}%
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};

// Main Analytics Page Component
export default function AnalyticsPage() {
  const [usage, setUsage] = useState<UserUsageStats | null>(null);
  const [engagement, setEngagement] = useState<ChurnRiskMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState('30');

  useEffect(() => {
    fetchAnalytics();
  }, [timeRange]);

  const fetchAnalytics = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch usage stats
      const usageResponse = await fetch(`/api/v1/analytics/my/usage?days=${timeRange}`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (!usageResponse.ok) {
        throw new Error('Failed to fetch usage statistics');
      }

      const usageData = await usageResponse.json();
      setUsage(usageData);

      // Fetch engagement metrics
      const engagementResponse = await fetch('/api/v1/analytics/my/churn-risk', {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
        },
      });

      if (!engagementResponse.ok) {
        throw new Error('Failed to fetch engagement metrics');
      }

      const engagementData = await engagementResponse.json();
      setEngagement(engagementData);

    } catch (err) {
      console.error('Analytics fetch error:', err);
      setError(err instanceof Error ? err.message : 'Failed to load analytics');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="container mx-auto py-8">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Loading analytics...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="container mx-auto py-8">
        <Card>
          <CardContent className="p-6">
            <div className="text-center">
              <AlertTriangle className="w-12 h-12 text-red-500 mx-auto mb-4" />
              <h3 className="text-lg font-semibold mb-2">Unable to Load Analytics</h3>
              <p className="text-gray-600 mb-4">{error}</p>
              <Button onClick={fetchAnalytics}>Try Again</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const usageLimitPercentage = usage?.plan_limits.max_scans_per_month
    ? (usage.scans_this_period / usage.plan_limits.max_scans_per_month) * 100
    : 0;

  const costLimitPercentage = usage?.plan_limits.max_cost_per_month
    ? (usage.cost_this_period / usage.plan_limits.max_cost_per_month) * 100
    : 0;

  return (
    <div className="container mx-auto py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Usage Analytics</h1>
          <p className="text-gray-600 mt-1">
            Track your security analysis insights and Pro feature usage
          </p>
        </div>
        
        <div className="flex items-center space-x-4">
          <Select value={timeRange} onValueChange={setTimeRange}>
            <SelectTrigger className="w-32">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="7">Last 7 days</SelectItem>
              <SelectItem value="30">Last 30 days</SelectItem>
              <SelectItem value="90">Last 90 days</SelectItem>
            </SelectContent>
          </Select>
          
          <Button onClick={fetchAnalytics} variant="outline" size="sm">
            <BarChart3 className="w-4 h-4 mr-2" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <MetricCard
          title="AI Scans"
          value={usage?.scans_this_period.toLocaleString() || '0'}
          icon={<Activity className="w-6 h-6" />}
          change={`${usageLimitPercentage.toFixed(1)}% of limit`}
          trend={usageLimitPercentage > 80 ? 'up' : 'neutral'}
        />
        
        <MetricCard
          title="Threats Found"
          value={usage?.threats_discovered.toLocaleString() || '0'}
          icon={<Shield className="w-6 h-6" />}
          change={usage?.threats_discovered ? `${usage.zero_days_found} zero-days` : undefined}
          trend={usage?.zero_days_found ? 'up' : 'neutral'}
        />
        
        <MetricCard
          title="Estimated Cost"
          value={`$${usage?.cost_this_period.toFixed(2) || '0.00'}`}
          icon={<DollarSign className="w-6 h-6" />}
          change={`${costLimitPercentage.toFixed(1)}% of limit`}
          trend={costLimitPercentage > 80 ? 'up' : 'neutral'}
        />
        
        <MetricCard
          title="LLM Tokens"
          value={usage?.tokens_used.toLocaleString() || '0'}
          icon={<Target className="w-6 h-6" />}
        />
      </div>

      {/* Detailed Analytics Tabs */}
      <Tabs defaultValue="overview" className="space-y-6">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="threats">Threat Analysis</TabsTrigger>
          <TabsTrigger value="engagement">Engagement</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <UsageChart data={usage?.usage_by_day || []} />
            <ThreatCategoryChart categories={usage?.top_threat_categories || []} />
          </div>
        </TabsContent>

        <TabsContent value="threats" className="space-y-6">
          <div className="grid grid-cols-1 gap-6">
            <ThreatCategoryChart categories={usage?.top_threat_categories || []} />
            
            {usage?.zero_days_found > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center space-x-2">
                    <Eye className="w-5 h-5 text-orange-500" />
                    <span>Zero-Day Discoveries</span>
                  </CardTitle>
                  <CardDescription>
                    You've discovered {usage.zero_days_found} potential zero-day vulnerabilities
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <p className="text-sm text-gray-600">
                    Zero-day discoveries are novel security vulnerabilities that haven't been 
                    seen before. These findings demonstrate the value of AI-powered analysis
                    in uncovering sophisticated threats.
                  </p>
                </CardContent>
              </Card>
            )}
          </div>
        </TabsContent>

        <TabsContent value="engagement" className="space-y-6">
          {engagement && <EngagementMetrics metrics={engagement} />}
          
          <Card>
            <CardHeader>
              <CardTitle>Usage Recommendations</CardTitle>
              <CardDescription>Tips to maximize your security analysis effectiveness</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {engagement && engagement.threat_hit_rate < 0.2 && (
                <div className="p-4 bg-yellow-50 border border-yellow-200 rounded-md">
                  <p className="text-sm text-yellow-800">
                    <strong>Tip:</strong> Your threat discovery rate is {(engagement.threat_hit_rate * 100).toFixed(1)}%. 
                    Try scanning more diverse code repositories or packages to find more security issues.
                  </p>
                </div>
              )}
              
              {engagement && engagement.monthly_scans < 10 && (
                <div className="p-4 bg-blue-50 border border-blue-200 rounded-md">
                  <p className="text-sm text-blue-800">
                    <strong>Tip:</strong> You've performed {engagement.monthly_scans} scans this month. 
                    Regular scanning helps identify threats early and improves your security posture.
                  </p>
                </div>
              )}
              
              <div className="p-4 bg-green-50 border border-green-200 rounded-md">
                <p className="text-sm text-green-800">
                  <strong>Pro Tip:</strong> Use the AI analysis features for comprehensive threat detection, 
                  including zero-day discovery and advanced pattern recognition.
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}