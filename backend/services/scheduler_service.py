"""Background scheduler — collects logs from every active server, then runs ML detection."""

from __future__ import annotations

from backend.core.config import get_settings
from backend.core.logging import get_logger
from backend.collector.log_sources import DEFAULT_LOG_SOURCES
from backend.database.connection import get_session
from backend.services.detection_service import DetectionService
from backend.services.server_service import ServerService

logger = get_logger(__name__)

_scheduler = None


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
    """Start APScheduler if enabled in settings."""
    global _scheduler
    settings = get_settings()
    if not settings.SCHEDULER_ENABLED:
        logger.info("Background scheduler disabled (set SCHEDULER_ENABLED=true to enable).")
        return
    if _scheduler is not None:
        return

    from apscheduler.schedulers.background import BackgroundScheduler

    _scheduler = BackgroundScheduler()
    _scheduler.add_job(
        _collect_all_job,
        "interval",
        minutes=settings.COLLECTION_INTERVAL_MINUTES,
        id="defensync_collect_all",
        replace_existing=True,
    )
    _scheduler.start()
    logger.info(
        "DefenSync scheduler started — collecting from all active servers every %dm",
        settings.COLLECTION_INTERVAL_MINUTES,
    )


def stop_scheduler() -> None:
    """Shutdown background scheduler."""
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Background scheduler stopped.")
