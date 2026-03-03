# Forge Premium Backend API Design

## Overview

This document outlines the complete backend infrastructure design for Forge premium features within the Sigil API. The implementation extends the existing FastAPI backend with new authenticated endpoints that support plan-based feature gating and premium analytics.

## Architecture Overview

```
┌─────────────────────────┐
│   Forge Premium API     │
│   /forge/* endpoints    │
└─────────────────────────┘
            │
┌─────────────────────────┐
│   Plan-Based Gating     │
│   Pro/Team/Enterprise   │
└─────────────────────────┘
            │
┌─────────────────────────┐
│   Analytics & Tracking  │
│   Event Storage         │
└─────────────────────────┘
            │
┌─────────────────────────┐
│   Azure SQL Database    │
│   New Premium Tables    │
└─────────────────────────┘
```

## Database Schema

### New Tables Created

**forge_user_tools** - Track user's monitored tools
```sql
- id (UUID, PK)
- user_id (UUID, FK to users)
- tool_id (VARCHAR 255) -- Package name
- ecosystem (VARCHAR 50) -- pip, npm, mcp, etc.
- tracked_at (DATETIME)
- is_starred (BIT)
- custom_tags (JSON array)
- notes (TEXT)
```

**forge_stacks** - User-created tool combinations
```sql
- id (UUID, PK) 
- user_id (UUID, FK to users)
- team_id (UUID, FK to teams, nullable)
- name (VARCHAR 255)
- description (TEXT)
- tools (JSON array)
- is_public (BIT)
- created_at/updated_at (DATETIME)
```

**forge_alert_subscriptions** - Notification preferences
```sql
- id (UUID, PK)
- user_id (UUID, FK to users)
- tool_id (VARCHAR 255, nullable) -- Specific tool or NULL for all
- ecosystem (VARCHAR 50, nullable)
- alert_types (JSON array) -- ["security", "updates", etc.]
- channels (JSON object) -- {"email": true, "slack": false}
- is_active (BIT)
- created_at (DATETIME)
```

**forge_analytics_events** - User behavior tracking
```sql
- id (UUID, PK)
- user_id (UUID, FK to users)
- event_type (VARCHAR 100) -- "tool_tracked", "stack_created", etc.
- event_data (JSON object) -- Event-specific context
- timestamp (DATETIME)
```

**forge_user_settings** - User preferences
```sql
- user_id (UUID, PK, FK to users)
- alert_frequency (VARCHAR 50) -- "daily", "weekly", "instant"
- alert_types (JSON array)
- delivery_channels (JSON array)
- quiet_hours (JSON object, nullable)
- email_notifications (BIT)
- slack_notifications (BIT)
- weekly_digest (BIT)
- created_at/updated_at (DATETIME)
```

## API Endpoints

### Tool Tracking (Pro+ Required)

- `GET /forge/my-tools` - Get user's tracked tools
- `POST /forge/my-tools/track` - Add tool to tracking list
- `DELETE /forge/my-tools/{tool_id}/untrack` - Remove from tracking
- `PATCH /forge/my-tools/{tool_id}` - Update tool metadata (notes, tags, starred)

### Custom Stacks (Pro+ Required)

- `GET /forge/stacks` - Get user's custom stacks
- `POST /forge/stacks` - Create new tool stack
- `PUT /forge/stacks/{stack_id}` - Update existing stack
- `DELETE /forge/stacks/{stack_id}` - Delete stack

### Analytics Dashboards (Plan Gated)

- `GET /forge/analytics/personal` - Personal analytics (Pro+ required)
- `GET /forge/analytics/team` - Team analytics (Team+ required)

### Alert Management (Pro+ Required)

- `GET /forge/alerts` - Get user's alert subscriptions
- `POST /forge/alerts` - Create new alert subscription
- `PATCH /forge/alerts/{subscription_id}` - Update subscription
- `DELETE /forge/alerts/{subscription_id}` - Delete subscription

### Settings (Pro+ Required)

- `GET /forge/settings` - Get user's Forge preferences
- `PUT /forge/settings` - Update preferences

## Plan Gating Implementation

### Plan Tiers
```python
class PlanTier(str, enum.Enum):
    FREE = "free"        # Basic Forge browse/search only
    PRO = "pro"          # Tool tracking, personal analytics, alerts
    TEAM = "team"        # Team analytics, shared stacks
    ENTERPRISE = "enterprise"  # Organization analytics, advanced features
```

### Gating Middleware
```python
# Usage in endpoints
@router.get("/forge/my-tools")
async def get_tracked_tools(
    current_user: Annotated[UserResponse, Depends(get_current_user_unified)],
    _: Annotated[None, Depends(require_plan(PlanTier.PRO))],
):
    # Pro+ only endpoint
```

## Data Models

### Request/Response Models

**TrackedTool** - User's tracked tool with metadata
```python
{
    "id": "uuid",
    "tool_id": "requests", 
    "ecosystem": "pip",
    "tracked_at": "2024-01-01T00:00:00Z",
    "is_starred": false,
    "custom_tags": ["web", "http"],
    "notes": "Used in data pipeline",
    "trust_score": 85.0
}
```

**ForgeStack** - Custom tool combination
```python
{
    "id": "uuid",
    "name": "Web Scraping Stack",
    "description": "Complete web scraping setup",
    "tools": [
        {"tool_id": "requests", "ecosystem": "pip"},
        {"tool_id": "beautifulsoup4", "ecosystem": "pip"}
    ],
    "is_public": false,
    "user_id": "uuid",
    "created_at": "2024-01-01T00:00:00Z"
}
```

## Service Layer

### ForgeUserToolsService
Handles tool tracking, trust score monitoring, and recommendations:
- Trust score caching for performance
- Personalized tool recommendations based on user preferences
- Security alert checking for tracked tools
- Usage statistics aggregation

### ForgeAnalyticsService (Existing)
Manages event tracking and analytics aggregation:
- Real-time event logging
- Personal/Team/Organization analytics
- Plan-based analytics access control

## Integration Points

### Authentication
- Uses existing `get_current_user_unified` dependency
- Supports both Supabase Auth and custom JWT tokens
- All premium endpoints require authentication

### Plan Enforcement
- Leverages existing `require_plan()` dependency factory
- Automatic 403 responses for insufficient plan tier
- Plan checking happens before endpoint execution

### Database
- Extends existing Azure SQL database
- Uses existing `api.database.db` connection pool
- Follows existing schema patterns and conventions

### Billing Integration
- Reads plan tier from existing user.subscription data
- Compatible with existing Stripe billing system
- Plan changes immediately affect feature access

## Error Handling

### Standard HTTP Status Codes
- `200` - Success
- `201` - Created (new resources)
- `204` - No Content (deletions)
- `400` - Bad Request (validation errors)
- `401` - Unauthorized (not authenticated)
- `403` - Forbidden (plan upgrade required)
- `404` - Not Found (resource doesn't exist)
- `409` - Conflict (duplicate tracking, etc.)
- `429` - Too Many Requests (rate limiting)
- `500` - Internal Server Error

### Plan Gate Error Response
```json
{
    "detail": "This feature requires the pro plan or higher.",
    "required_plan": "pro",
    "current_plan": "free"
}
```

## Performance Considerations

### Database Optimization
- Indexed foreign keys (user_id, tool_id, ecosystem)
- JSON field optimization for tags and metadata
- Batch operations for bulk data loading

### Caching Strategy
- Trust scores cached for 5 minutes
- Analytics summaries pre-computed for teams
- Redis integration for real-time features

### Query Optimization
- JOIN operations for related data
- Batch loading to avoid N+1 problems
- Paginated results for large datasets

## Security Measures

### Data Protection
- User isolation through user_id filtering
- Stack ownership validation before modification
- Alert subscription ownership verification

### Input Validation
- Pydantic model validation for all requests
- SQL injection prevention through parameterized queries
- File upload restrictions and validation

## Deployment

### Migration Process
1. Run `008_forge_premium_features.sql` migration
2. Deploy updated API with new router
3. Verify plan gating works correctly
4. Test all premium endpoints

### Environment Variables
No new environment variables required - uses existing:
- Database connection strings
- JWT secrets
- Plan configuration

## Monitoring

### Analytics Events
All user interactions generate analytics events:
- `tool_tracked`, `tool_untracked`
- `stack_created`, `stack_shared`
- `alert_configured`
- `analytics_viewed`

### Metrics to Track
- Premium feature adoption rates
- User tool tracking patterns
- Plan upgrade conversions
- API endpoint usage

## Future Enhancements

### Phase 2 Features
- Advanced analytics visualizations
- Team collaboration features
- Enterprise audit logging
- Custom alert rules engine

### Scalability Improvements
- Background job processing for analytics
- Webhook integrations for real-time alerts
- Advanced caching strategies
- Database read replicas

## Testing Strategy

### Unit Tests
- Model validation tests
- Service layer functionality
- Plan gating logic

### Integration Tests
- Full endpoint testing
- Authentication flow testing
- Database interaction testing

### Load Testing
- Premium endpoint performance
- Analytics aggregation speed
- Plan gating overhead

This backend design provides a solid foundation for Forge premium features while maintaining compatibility with the existing Sigil architecture and following established patterns for authentication, authorization, and data management.