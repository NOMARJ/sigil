#!/usr/bin/env python3
"""
Forge Enrichment Worker Service

Production-ready service that includes:
- HTTP health check endpoint for Container Apps
- Enrichment worker with proper lifecycle management
- Metrics and monitoring endpoints
- Graceful shutdown handling
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from api.database import db
from bot.config import bot_settings
from bot.worker.forge_enrichment import ForgeEnrichmentWorker

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# FastAPI app for health checks and metrics
app = FastAPI(title="Forge Enrichment Worker", version="1.0.0")

# Global worker state
worker_state = {
    "status": "starting",
    "started_at": datetime.utcnow(),
    "last_run": None,
    "processed_records": 0,
    "error_count": 0,
    "current_batch": 0,
    "total_batches": 0,
}

enrichment_worker = None
worker_task = None
shutdown_event = asyncio.Event()


@app.get("/health")
async def health_check():
    """Health check endpoint for Container Apps."""
    try:
        # Check database connection
        await db.connect()
        db_connected = db.connected
        await db.disconnect()

        status = (
            "healthy"
            if db_connected and worker_state["status"] in ["running", "idle"]
            else "unhealthy"
        )

        return {
            "status": status,
            "service": "forge-enrichment-worker",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "database_connected": db_connected,
            "worker_status": worker_state["status"],
            "uptime_seconds": int(
                (datetime.utcnow() - worker_state["started_at"]).total_seconds()
            ),
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            },
        )


@app.get("/metrics")
async def get_metrics():
    """Get worker metrics and statistics."""
    try:
        # Get enrichment progress
        await db.connect()

        # Total records in public_scans
        total_result = await db.execute_raw_sql_single(
            "SELECT COUNT(*) as count FROM public_scans"
        )
        total_records = total_result["count"] if total_result else 0

        # Enriched records
        enriched_result = await db.execute_raw_sql_single(
            "SELECT COUNT(*) as count FROM forge_classification WHERE metadata_json LIKE '%\"forge_api_enriched\":true%'"
        )
        enriched_records = enriched_result["count"] if enriched_result else 0

        await db.disconnect()

        completion_percentage = (
            (enriched_records / total_records * 100) if total_records > 0 else 0
        )

        return {
            "worker_metrics": {
                "status": worker_state["status"],
                "started_at": worker_state["started_at"].isoformat(),
                "last_run": worker_state["last_run"].isoformat()
                if worker_state["last_run"]
                else None,
                "processed_records": worker_state["processed_records"],
                "error_count": worker_state["error_count"],
                "current_batch": worker_state["current_batch"],
                "total_batches": worker_state["total_batches"],
            },
            "enrichment_progress": {
                "total_records": total_records,
                "enriched_records": enriched_records,
                "pending_records": total_records - enriched_records,
                "completion_percentage": round(completion_percentage, 2),
            },
            "configuration": {
                "batch_size": bot_settings.forge_enrichment_batch_size,
                "delay_seconds": bot_settings.forge_enrichment_delay,
                "max_records": bot_settings.forge_enrichment_max_records,
                "poll_interval": bot_settings.forge_enrichment_poll_interval,
                "enabled": bot_settings.forge_enrichment_enabled,
            },
        }
    except Exception as e:
        logger.error(f"Metrics retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/start")
async def start_enrichment():
    """Manually start enrichment process."""
    global worker_task

    if worker_state["status"] == "running":
        return {"message": "Enrichment worker is already running"}

    if worker_task and not worker_task.done():
        return {"message": "Enrichment worker is already starting"}

    worker_task = asyncio.create_task(run_enrichment_worker())
    return {"message": "Enrichment worker started"}


@app.post("/stop")
async def stop_enrichment():
    """Manually stop enrichment process."""
    global worker_task

    if worker_state["status"] != "running":
        return {"message": "Enrichment worker is not running"}

    shutdown_event.set()

    if worker_task:
        try:
            await asyncio.wait_for(worker_task, timeout=30)
        except asyncio.TimeoutError:
            worker_task.cancel()

    return {"message": "Enrichment worker stopped"}


async def run_enrichment_worker():
    """Main enrichment worker function."""
    global enrichment_worker

    try:
        worker_state["status"] = "starting"
        logger.info("Starting Forge enrichment worker")

        if not bot_settings.forge_enrichment_enabled:
            worker_state["status"] = "disabled"
            logger.warning("Forge enrichment is disabled in configuration")
            return

        if not bot_settings.database_configured:
            worker_state["status"] = "error"
            logger.error("Database not configured")
            return

        # Initialize worker
        enrichment_worker = ForgeEnrichmentWorker()
        enrichment_worker.batch_size = bot_settings.forge_enrichment_batch_size
        enrichment_worker.max_records = bot_settings.forge_enrichment_max_records
        enrichment_worker.delay_between_batches = bot_settings.forge_enrichment_delay

        worker_state["status"] = "running"
        worker_state["processed_records"] = 0
        worker_state["error_count"] = 0

        logger.info("Enrichment worker configuration:")
        logger.info(f"  Batch size: {enrichment_worker.batch_size}")
        logger.info(f"  Max records: {enrichment_worker.max_records}")
        logger.info(
            f"  Delay between batches: {enrichment_worker.delay_between_batches}s"
        )

        await db.connect()

        while (
            not shutdown_event.is_set()
            and worker_state["processed_records"] < enrichment_worker.max_records
        ):
            try:
                worker_state["status"] = "running"
                worker_state["last_run"] = datetime.utcnow()

                # Find pending records
                pending_records = await enrichment_worker._find_pending_enrichments()

                if not pending_records:
                    worker_state["status"] = "idle"
                    logger.info("No records pending enrichment, sleeping...")
                    await asyncio.sleep(bot_settings.forge_enrichment_poll_interval)
                    continue

                remaining_budget = (
                    enrichment_worker.max_records - worker_state["processed_records"]
                )
                batch_records = pending_records[
                    : min(enrichment_worker.batch_size, remaining_budget)
                ]

                worker_state["current_batch"] += 1
                worker_state["total_batches"] = worker_state["current_batch"] + max(
                    0,
                    (len(pending_records) - len(batch_records))
                    // enrichment_worker.batch_size,
                )

                logger.info(
                    f"Processing batch {worker_state['current_batch']} with {len(batch_records)} records..."
                )

                # Process batch
                await enrichment_worker._process_batch(batch_records)

                worker_state["processed_records"] += len(batch_records)
                logger.info(
                    f"✅ Processed {worker_state['processed_records']}/{enrichment_worker.max_records} records"
                )

                # Sleep between batches if there are more records and we haven't hit the limit
                if worker_state[
                    "processed_records"
                ] < enrichment_worker.max_records and len(pending_records) > len(
                    batch_records
                ):
                    await asyncio.sleep(enrichment_worker.delay_between_batches)

            except Exception as e:
                worker_state["error_count"] += 1
                logger.error(f"Batch processing failed: {e}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying

        if worker_state["processed_records"] >= enrichment_worker.max_records:
            worker_state["status"] = "completed"
            logger.info(
                f"✅ Reached max records limit ({enrichment_worker.max_records}), stopping"
            )
        else:
            worker_state["status"] = "stopped"
            logger.info("✅ Enrichment process stopped by user")

    except Exception as e:
        worker_state["status"] = "error"
        worker_state["error_count"] += 1
        logger.error(f"Enrichment worker failed: {e}", exc_info=True)
    finally:
        await db.disconnect()


async def startup_event():
    """FastAPI startup event."""
    logger.info("Forge Enrichment Worker Service starting up")

    # Start enrichment worker automatically
    global worker_task
    worker_task = asyncio.create_task(run_enrichment_worker())


async def shutdown_event_handler():
    """FastAPI shutdown event."""
    logger.info("Forge Enrichment Worker Service shutting down")
    shutdown_event.set()

    global worker_task
    if worker_task and not worker_task.done():
        try:
            await asyncio.wait_for(worker_task, timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Worker shutdown timeout, cancelling task")
            worker_task.cancel()


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    shutdown_event.set()


if __name__ == "__main__":
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Add startup and shutdown event handlers
    app.add_event_handler("startup", startup_event)
    app.add_event_handler("shutdown", shutdown_event_handler)

    # Run the service
    logger.info("Starting Forge Enrichment Worker Service")
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info", access_log=True)
