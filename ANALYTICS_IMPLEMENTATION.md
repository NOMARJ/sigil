# Sigil Pro Analytics Implementation

## Overview

This document outlines the comprehensive analytics system implemented for Sigil Pro (US-009), providing detailed usage tracking, cost analysis, threat discovery metrics, and churn prediction capabilities for the $29/month Pro tier.

## 🎯 Features Implemented

### Core Analytics Capabilities
- **LLM Usage Tracking**: Track API calls, token consumption, processing time, and costs
- **Threat Discovery Analytics**: Log AI-detected threats with confidence scoring and zero-day detection
- **User Engagement Metrics**: Monitor session duration, feature adoption, and usage patterns
- **Churn Prediction**: Risk assessment algorithm to identify users likely to cancel
- **Business Intelligence**: Daily usage reports and trend analysis for business optimization

### Database Schema
- `user_analytics`: General event tracking for business intelligence
- `llm_usage_metrics`: Detailed LLM API usage for cost and performance analysis
- `threat_discoveries`: Individual threat discoveries for trend analysis
- `user_engagement_metrics`: Daily engagement aggregation for churn prediction
- `billing_usage_summary`: Billing period summaries for cost tracking

## 📁 Implementation Structure

### Backend Components

#### 1. Database Schema (`/api/database/analytics_schema.sql`)
```sql
-- Core tables for analytics tracking
CREATE TABLE user_analytics (...)
CREATE TABLE llm_usage_metrics (...)
CREATE TABLE threat_discoveries (...)
CREATE TABLE user_engagement_metrics (...)
CREATE TABLE billing_usage_summary (...)

-- Pre-computed views for performance
CREATE VIEW daily_usage_rollup AS ...
CREATE VIEW user_churn_risk AS ...
CREATE VIEW threat_discovery_trends AS ...
```

#### 2. Data Models (`/api/models/usage_metrics.py`)
- `UsageEvent`: General analytics events
- `LLMUsageRecord`: Detailed LLM usage tracking
- `ThreatDiscovery`: Individual threat discovery records
- `DailyUsageReport`: Business intelligence reports
- `ChurnRiskMetrics`: Churn prediction results
- `UserUsageStats`: Personal usage statistics

#### 3. Analytics Service (`/api/services/analytics_service.py`)
```python
class AnalyticsService:
    async def track_llm_usage(...)        # Track LLM API usage
    async def track_threat_discovery(...) # Log threat discoveries
    async def track_event(...)            # General event tracking
    async def get_daily_usage_report(...) # Business reports
    async def get_user_churn_risk(...)    # Churn prediction
    async def get_user_usage_stats(...)   # User dashboard stats
```

#### 4. LLM Service Integration (`/api/services/llm_service.py`)
```python
async def _track_analysis_analytics(...):
    # Automatically track analytics after successful LLM analysis
    await analytics_service.track_llm_usage(...)
    await analytics_service.track_threat_discovery(...)
```

#### 5. API Endpoints (`/api/routers/analytics.py`)
```
GET  /v1/analytics/admin/daily-usage     # Admin business reports
GET  /v1/analytics/admin/churn-risk/{id} # Admin churn assessment
GET  /v1/analytics/my/usage              # User personal stats
GET  /v1/analytics/my/churn-risk         # User engagement metrics
POST /v1/analytics/track/session-duration # Session tracking
POST /v1/analytics/track/upgrade-prompt  # Conversion tracking
```

### Frontend Components

#### 1. Analytics Dashboard (`/dashboard/src/app/analytics/page.tsx`)
- **Overview Tab**: Key metrics, usage trends, and cost tracking
- **Threat Analysis Tab**: Threat category breakdown and zero-day discoveries
- **Engagement Tab**: Usage patterns and optimization recommendations

#### 2. Key Dashboard Features
- Real-time usage metrics with plan limit tracking
- Interactive charts showing daily usage trends
- Threat category analysis with confidence scoring
- Engagement insights and retention recommendations
- Cost tracking with overage alerts

## 🚀 Setup Instructions

### 1. Database Migration
```bash
# Run the analytics tables migration
python api/migrations/create_analytics_tables.py
```

### 2. API Configuration
The analytics service is automatically initialized when the API starts. No additional configuration required.

### 3. Frontend Access
Navigate to `/analytics` in the dashboard to view usage analytics (Pro users only).

## 📊 Analytics Data Flow

### 1. LLM Usage Tracking
```
User initiates scan → LLMService.analyze_threat() → 
Analytics tracking after successful analysis → 
Store usage metrics + threat discoveries
```

### 2. User Engagement Tracking
```
Frontend user activity → Session tracking endpoints → 
Daily engagement metrics aggregation → 
Churn risk calculation
```

### 3. Business Intelligence
```
Aggregated usage data → Daily/weekly reports → 
Business metrics dashboard → 
Optimization insights
```

## 🔍 Churn Prediction Algorithm

### Risk Factors (0-100 scale)
- **No usage (30 days)**: +90 points (HIGH_RISK)
- **Low frequency (<4 scans/month)**: +25 points
- **Inactive (14+ days)**: +35 points
- **Low threat discovery (<10%)**: +20 points
- **Short sessions (<5 min)**: +15 points

### Risk Categories
- **HEALTHY**: Active usage, good threat discovery rate
- **LOW_ENGAGEMENT**: Low threat hit rate, needs guidance
- **MEDIUM_RISK**: Declining usage patterns
- **HIGH_RISK**: Extended inactivity, likely to churn

## 💰 Cost Tracking

### LLM Cost Estimates (per 1K tokens)
- GPT-4: $3.00
- GPT-4 Turbo: $1.00
- Claude-3 Sonnet: $0.30
- Claude-3 Haiku: $0.025

### Cost Optimization Features
- Cache hit tracking to reduce API calls
- Fallback usage monitoring
- Token consumption analysis
- Per-user cost attribution

## 📈 Business Intelligence Metrics

### Daily Usage Report
- Active Pro subscribers
- Total AI-powered scans
- LLM API costs and ROI
- Threat discovery rates
- Zero-day discoveries
- Cache efficiency

### User Segmentation
- Power users (high usage, high discovery rate)
- At-risk users (declining patterns)
- New users (onboarding optimization)
- Feature adopters (advanced capabilities)

## 🔐 Privacy and Security

### Data Protection
- User data aggregation for business metrics
- Personal identifiers separated from analytics
- Configurable data retention (default: 90 days detailed, 365 days aggregated)
- Optional data anonymization after retention period

### Access Control
- Admin endpoints require Enterprise tier or admin privileges
- User endpoints require Pro tier authentication
- Analytics data scoped to authenticated user context

## 📋 Success Metrics

### Business KPIs
- **LLM Cost Optimization**: Track cost per insight, optimize model usage
- **Churn Reduction**: Identify and retain at-risk users
- **Feature Adoption**: Monitor Pro feature usage patterns
- **Revenue Intelligence**: Usage-based pricing optimization

### User Value Metrics
- **Threat Discovery Rate**: Measure security analysis effectiveness
- **Zero-Day Detection**: Showcase advanced AI capabilities
- **Time to Value**: Track user onboarding and feature adoption
- **Cost Transparency**: Help users optimize their usage

## 🔄 Future Enhancements

### Phase 2 Capabilities
- Predictive threat modeling based on usage patterns
- Automated cost optimization recommendations
- Advanced business intelligence dashboards
- Integration with billing systems for usage-based pricing
- A/B testing framework for feature optimization

### Monitoring and Alerting
- Real-time usage anomaly detection
- Cost spike alerts for unexpected usage
- Churn risk notifications for retention campaigns
- Performance monitoring for analytics pipeline

## 🧪 Testing

### Unit Tests
- Analytics service functionality
- Data model validation
- Churn prediction accuracy
- Cost calculation verification

### Integration Tests
- End-to-end analytics tracking
- API endpoint functionality
- Database schema validation
- Frontend component rendering

### Performance Tests
- Analytics query performance
- Large-scale data aggregation
- Real-time dashboard responsiveness
- Database indexing efficiency

## 📚 API Documentation

### Analytics Endpoints

#### User Analytics
- `GET /v1/analytics/my/usage?days=30` - Personal usage statistics
- `GET /v1/analytics/my/churn-risk` - Engagement insights
- `POST /v1/analytics/track/session-duration` - Session tracking
- `POST /v1/analytics/track/upgrade-prompt` - Conversion tracking

#### Admin Analytics (Enterprise Only)
- `GET /v1/analytics/admin/daily-usage` - Business intelligence reports
- `GET /v1/analytics/admin/churn-risk/{user_id}` - Individual churn assessment
- `GET /v1/analytics/admin/threat-trends` - Security intelligence analysis

### Response Formats

#### User Usage Stats
```json
{
  "user_id": "user123",
  "current_period_start": "2024-03-01",
  "scans_this_period": 45,
  "tokens_used": 125000,
  "cost_this_period": 12.50,
  "threats_discovered": 23,
  "zero_days_found": 2,
  "plan_limits": {...},
  "usage_by_day": [...],
  "top_threat_categories": [...]
}
```

#### Churn Risk Metrics
```json
{
  "user_id": "user123",
  "risk_score": 25,
  "risk_category": "HEALTHY",
  "monthly_scans": 45,
  "threat_hit_rate": 0.51,
  "feature_adoption_score": 0.8
}
```

## 🎉 Implementation Complete

The comprehensive analytics system is now ready to provide detailed insights into Pro tier usage, support business intelligence initiatives, and enable data-driven optimization of Sigil's AI-powered security analysis platform.

### Key Deliverables
✅ Database schema with 5 core analytics tables
✅ Comprehensive data models for all analytics entities  
✅ Analytics service with tracking and reporting capabilities
✅ Seamless integration with existing LLM service
✅ Complete API endpoints for user and admin analytics
✅ Interactive dashboard with usage insights and recommendations
✅ Migration script for database setup
✅ Churn prediction algorithm for user retention
✅ Cost tracking and optimization features
✅ Privacy-compliant data handling

The system is designed to scale with Sigil's growth while providing actionable insights for both users and business stakeholders.