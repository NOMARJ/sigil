"""
Sigil API — Resilience Integration Examples

Examples showing how to integrate the resilience patterns into existing
API endpoints and service functions.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse

# Import resilience patterns
from api.background_job_resilience import JobPriority, background_job, job_queue
from api.circuit_breakers import circuit_protected
from api.errors import (
    DatabaseError,
    ExternalServiceError,
    NotFoundError,
    ValidationError,
)
from api.graceful_degradation import (
    DegradedResponseBuilder,
    call_with_degradation,
    with_degradation,
)
from api.monitoring import record_operation, record_response_time
from api.retry import protected, retry_github_api

logger = logging.getLogger(__name__)

# Example router with resilience patterns
resilience_router = APIRouter(prefix="/api/v1/examples", tags=["resilience-examples"])


# ---------------------------------------------------------------------------
# Example 1: Basic Circuit Breaker + Retry Protection
# ---------------------------------------------------------------------------


@circuit_protected("github_api")
async def fetch_repository_metadata(repo_url: str) -> Dict[str, Any]:
    """
    Example function protected by circuit breaker.
    This would typically call GitHub API to fetch repository metadata.
    """
    # Simulate GitHub API call
    import httpx
    
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://api.github.com/repos/{repo_url}")
        
        if response.status_code != 200:
            raise ExternalServiceError(
                service="github_api",
                message=f"Failed to fetch repository: {response.status_code}",
                context={"repo_url": repo_url, "status_code": response.status_code}
            )
        
        return response.json()


@resilience_router.get("/repository/{owner}/{repo}")
@record_response_time("get_repository")
@record_operation("get_repository")
async def get_repository_info(owner: str, repo: str) -> JSONResponse:
    """
    Example endpoint that uses circuit breaker protection for external API calls.
    """
    try:
        repo_url = f"{owner}/{repo}"
        
        # Use circuit breaker protection
        metadata = await fetch_repository_metadata(repo_url)
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "repository": {
                    "name": metadata.get("name"),
                    "description": metadata.get("description"),
                    "stars": metadata.get("stargazers_count"),
                    "language": metadata.get("language"),
                },
            }
        )
        
    except ExternalServiceError as exc:
        logger.warning("GitHub API failed for %s/%s: %s", owner, repo, exc)
        
        # Return degraded response
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "message": "Repository information temporarily unavailable",
                "error": exc.message,
                "retry_after": exc.retry_after,
            }
        )


# ---------------------------------------------------------------------------
# Example 2: Combined Circuit Breaker + Retry with Fallback
# ---------------------------------------------------------------------------


@protected("github_api", max_attempts=5, base_delay=2.0)
async def fetch_repository_with_retry(repo_url: str) -> Dict[str, Any]:
    """
    Example function with combined circuit breaker and retry protection.
    """
    # This function is automatically protected by both circuit breaker and retry
    return await fetch_repository_metadata(repo_url)


async def get_cached_repository_info(repo_url: str) -> Optional[Dict[str, Any]]:
    """
    Fallback function that returns cached repository information.
    """
    from api.graceful_degradation import cached_fallback_manager
    
    cached_data = await cached_fallback_manager.get_fallback_data(
        f"repo:{repo_url}",
        max_age=3600  # 1 hour old cache is acceptable
    )
    
    if cached_data:
        logger.info("Using cached data for repository: %s", repo_url)
        return cached_data
    
    return None


@resilience_router.get("/repository-with-fallback/{owner}/{repo}")
async def get_repository_with_fallback(owner: str, repo: str) -> JSONResponse:
    """
    Example endpoint with comprehensive resilience: retry + circuit breaker + fallback.
    """
    repo_url = f"{owner}/{repo}"
    
    # Try primary data source with full protection
    repository_data = await call_with_degradation(
        service_name="github_api",
        operation=lambda: fetch_repository_with_retry(repo_url),
        fallback=lambda: get_cached_repository_info(repo_url),
    )
    
    if repository_data:
        # Cache successful response for future fallback
        from api.graceful_degradation import cached_fallback_manager
        await cached_fallback_manager.store_fallback_data(
            f"repo:{repo_url}",
            repository_data,
            ttl=3600
        )
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "repository": repository_data,
                "data_source": "live",
            }
        )
    
    # No data available at all
    raise NotFoundError("Repository", repo_url)


# ---------------------------------------------------------------------------
# Example 3: Background Job Processing with Resilience
# ---------------------------------------------------------------------------


@background_job(priority=JobPriority.HIGH, max_attempts=3, timeout_seconds=300)
async def process_repository_scan(repo_url: str, user_id: str) -> Dict[str, Any]:
    """
    Example background job that processes a repository security scan.
    This function is automatically queued and executed with retry logic.
    """
    logger.info("Starting security scan for repository: %s", repo_url)
    
    try:
        # Fetch repository data with resilience
        repo_data = await fetch_repository_with_retry(repo_url)
        
        # Simulate scan processing (in reality, this would be complex analysis)
        import asyncio
        await asyncio.sleep(10)  # Simulate processing time
        
        # Store scan results (with database resilience)
        from api.database_resilience import with_database_resilience
        
        @with_database_resilience(fallback_result={"id": "temp-scan-id"})
        async def store_scan_result():
            from api.database import db
            return await db.insert("scans", {
                "repository_url": repo_url,
                "user_id": user_id,
                "status": "completed",
                "findings": {"threats": 0, "warnings": 2},
                "metadata": repo_data,
            })
        
        scan_result = await store_scan_result()
        
        logger.info("Completed security scan for repository: %s", repo_url)
        return {
            "scan_id": scan_result["id"],
            "status": "completed",
            "repository": repo_url,
            "findings": {"threats": 0, "warnings": 2},
        }
        
    except Exception as exc:
        logger.error("Security scan failed for %s: %s", repo_url, exc)
        raise  # Will be handled by job retry logic


@resilience_router.post("/scan/{owner}/{repo}")
async def submit_repository_scan(
    owner: str,
    repo: str,
    user_id: str = "demo-user",  # In reality, this would come from auth
) -> JSONResponse:
    """
    Example endpoint that submits a repository for background security scanning.
    """
    repo_url = f"{owner}/{repo}"
    
    try:
        # Submit job for background processing
        job_id = await job_queue.submit_job(
            process_repository_scan.original_func,  # Access original function
            repo_url,
            user_id,
            priority=JobPriority.HIGH,
            max_attempts=3,
            timeout_seconds=300,
            user_id=user_id,
            correlation_id=f"scan-{owner}-{repo}",
            context={"repository": repo_url, "operation": "security_scan"},
        )
        
        return JSONResponse(
            status_code=status.HTTP_202_ACCEPTED,
            content={
                "status": "submitted",
                "message": "Repository scan submitted for processing",
                "job_id": job_id,
                "repository": repo_url,
                "estimated_completion": "5-10 minutes",
            }
        )
        
    except Exception as exc:
        logger.error("Failed to submit scan job for %s: %s", repo_url, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit repository scan"
        )


@resilience_router.get("/scan-status/{job_id}")
async def get_scan_status(job_id: str) -> JSONResponse:
    """
    Example endpoint to check the status of a background scan job.
    """
    job_status = job_queue.get_job_status(job_id)
    
    if not job_status:
        raise NotFoundError("Job", job_id)
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "success",
            "job": job_status,
        }
    )


# ---------------------------------------------------------------------------
# Example 4: Database Operations with Resilience
# ---------------------------------------------------------------------------


@resilience_router.get("/user/{user_id}/scans")
@with_degradation("database", fallback_response_builder=lambda level: {
    "scans": [],
    "status": "degraded",
    "message": "Scan history temporarily unavailable",
})
async def get_user_scans(user_id: str) -> JSONResponse:
    """
    Example endpoint showing database operations with resilience patterns.
    """
    from api.database_resilience import with_database_resilience
    from api.database import db
    
    @with_database_resilience(fallback_result=[])
    async def fetch_user_scans():
        return await db.select(
            "scans",
            filters={"user_id": user_id},
            order_by="created_at",
            order_desc=True,
            limit=50,
        )
    
    try:
        scans = await fetch_user_scans()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "user_id": user_id,
                "scans": scans,
                "total": len(scans),
            }
        )
        
    except DatabaseError as exc:
        logger.error("Database error fetching scans for user %s: %s", user_id, exc)
        
        # Return degraded response
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "degraded",
                "message": "Scan history temporarily unavailable",
                "user_id": user_id,
                "scans": [],
                "error": exc.message,
                "retry_after": exc.retry_after,
            }
        )


# ---------------------------------------------------------------------------
# Example 5: Monitoring and Health Check Integration
# ---------------------------------------------------------------------------


@resilience_router.get("/health/detailed")
async def get_detailed_health() -> JSONResponse:
    """
    Example endpoint showing detailed health information including resilience components.
    """
    from api.resilience_middleware import enhanced_health_check
    
    health_data = await enhanced_health_check()
    
    # Add example-specific health information
    health_data["examples"] = {
        "github_integration": {
            "status": "operational",
            "last_successful_call": "2023-12-07T10:30:00Z",
        },
        "background_jobs": {
            "active_scans": job_queue.get_queue_stats().get("running_jobs", 0),
            "queued_scans": job_queue.get_queue_stats().get("pending_jobs", 0),
            "failed_scans": job_queue.get_queue_stats().get("dead_letter_jobs", 0),
        },
    }
    
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=health_data,
    )


@resilience_router.get("/metrics/summary")
async def get_metrics_summary() -> JSONResponse:
    """
    Example endpoint showing how to expose application metrics.
    """
    from api.monitoring import metrics_collector
    
    try:
        # Get key metrics for the examples
        metrics = {
            "repository_requests": {
                "total": metrics_collector.get_counter_value(
                    "operations_total", {"operation": "get_repository"}
                ),
                "success": metrics_collector.get_counter_value(
                    "operations_total", {"operation": "get_repository", "status": "success"}
                ),
                "errors": metrics_collector.get_counter_value(
                    "operations_total", {"operation": "get_repository", "status": "error"}
                ),
            },
            "response_times": metrics_collector.get_histogram_stats(
                "response_time", {"operation": "get_repository"}
            ),
            "scan_jobs": {
                "submitted": metrics_collector.get_counter_value(
                    "background_jobs_total", {"type": "scan", "status": "submitted"}
                ),
                "completed": metrics_collector.get_counter_value(
                    "background_jobs_total", {"type": "scan", "status": "completed"}
                ),
                "failed": metrics_collector.get_counter_value(
                    "background_jobs_total", {"type": "scan", "status": "failed"}
                ),
            },
        }
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "metrics": metrics,
                "collection_time": "real-time",
            }
        )
        
    except Exception as exc:
        logger.error("Failed to get metrics summary: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "message": "Failed to retrieve metrics",
                "error": str(exc),
            }
        )


# ---------------------------------------------------------------------------
# Example 6: Manual Error Injection for Testing
# ---------------------------------------------------------------------------


@resilience_router.post("/admin/inject-error/{error_type}")
async def inject_error_for_testing(error_type: str) -> JSONResponse:
    """
    Example endpoint for testing error handling (only use in development).
    """
    if not settings.debug:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Error injection only available in debug mode"
        )
    
    error_types = {
        "database": DatabaseError("Simulated database error for testing"),
        "external": ExternalServiceError("github_api", "Simulated GitHub API error"),
        "validation": ValidationError("Simulated validation error"),
        "timeout": TimeoutError("test_operation", 30),
        "generic": Exception("Simulated generic error"),
    }
    
    if error_type not in error_types:
        raise ValidationError(
            f"Invalid error type. Available: {list(error_types.keys())}"
        )
    
    # Raise the specified error type
    raise error_types[error_type]


# Add router to the main application
# This would typically be done in main.py:
# app.include_router(resilience_router)


if __name__ == "__main__":
    """
    Example of how to run a simple test of the resilience patterns.
    """
    import asyncio
    
    async def test_resilience_patterns():
        """Test basic functionality of resilience patterns."""
        print("Testing resilience patterns...")
        
        # Test circuit breaker
        try:
            result = await fetch_repository_metadata("octocat/Hello-World")
            print(f"Circuit breaker test passed: {result.get('name', 'Unknown')}")
        except Exception as exc:
            print(f"Circuit breaker test failed (expected): {exc}")
        
        # Test background job submission
        try:
            job_id = await process_repository_scan.submit_job(
                "octocat/Hello-World",
                "test-user"
            )
            print(f"Background job submitted: {job_id}")
        except Exception as exc:
            print(f"Background job submission failed: {exc}")
        
        print("Resilience pattern tests completed")
    
    asyncio.run(test_resilience_patterns())