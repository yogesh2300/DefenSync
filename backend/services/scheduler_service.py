"""Background scheduler — health checks and log collection."""

from __future__ import annotations

from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.collector.log_sources import DEFAULT_LOG_SOURCES
from backend.database.connection import get_session
from backend.services.detection_service import DetectionService
from backend.services.health_engine import get_health_engine
from backend.services.server_service import ServerService

logger = get_logger(__name__)

_scheduler = None


def _health_check_job() -> None:
    """Scheduled job: concurrent SSH health probes for all monitored servers."""
    try:
        stats = get_health_engine().run_cycle()
        logger.info("Scheduled health check finished stats=%s", stats)
    except Exception as exc:
        logger.exception("Scheduled health check job failed: %s", exc)


def _collect_all_job() -> None:
    """Scheduled job: collect from all active servers, then run hybrid ML detection."""
    settings = get_settings()
    session = get_session()
    try:
        server_service = ServerService(session)
        results = server_service.collect_all_active(
            tail_lines=settings.COLLECTION_TAIL_LINES,
            log_sources=DEFAULT_LOG_SOURCES,
        )
        logger.info("Scheduled collection finished servers=%d", len(results))

        owners = {
            (server.owner_id or server.created_by)
            for server in server_service.list_servers(active_only=True)
            if server.owner_id or server.created_by
        }
        detection = DetectionService(session)
        for owner_id in owners:
            detection_result = detection.run_detection(owner_id=owner_id)
            logger.info(
                "Scheduled detection complete owner=%s events=%s flagged=%s",
                owner_id,
                detection_result.get("events_analyzed"),
                detection_result.get("total_flagged"),
            )
    except Exception as exc:
        logger.exception("Scheduled collection job failed: %s", exc)
    finally:
        session.close()


def start_scheduler() -> None:
    """Start APScheduler for health checks and optional log collection."""
    global _scheduler
    settings = get_settings()
    if _scheduler is not None:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    _scheduler = BackgroundScheduler()

    if settings.HEALTH_CHECK_ENABLED:
        _scheduler.add_job(
            _health_check_job,
            "interval",
            seconds=settings.HEALTH_CHECK_INTERVAL_SECONDS,
            id="defensync_health_check",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "Health check scheduler registered every %ss",
            settings.HEALTH_CHECK_INTERVAL_SECONDS,
        )

    if settings.SCHEDULER_ENABLED:
        _scheduler.add_job(
            _collect_all_job,
            "interval",
            minutes=settings.COLLECTION_INTERVAL_MINUTES,
            id="defensync_collect_all",
            replace_existing=True,
        )
        logger.info(
            "Automatic log collection ENABLED — running every %d minutes (COLLECTION_INTERVAL_MINUTES=%d).",
            settings.COLLECTION_INTERVAL_MINUTES,
            settings.COLLECTION_INTERVAL_MINUTES,
        )
    else:
        logger.info(
            "Automatic log collection DISABLED (SCHEDULER_ENABLED=false). "
            "Set SCHEDULER_ENABLED=true in .env to enable automatic log collection every %d minutes. "
            "Manual collection via the UI or POST /api/v1/servers/{id}/collect remains available.",
            settings.COLLECTION_INTERVAL_MINUTES,
        )

    if not settings.HEALTH_CHECK_ENABLED and not settings.SCHEDULER_ENABLED:
        logger.info("Background scheduler disabled — both HEALTH_CHECK_ENABLED and SCHEDULER_ENABLED are false.")
        return

    _scheduler.start()
    logger.info("DefenSync background scheduler started.")


def stop_scheduler() -> None:
    """Shutdown background scheduler."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Background scheduler stopped.")
