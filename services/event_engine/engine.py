"""Central event flow: persist -> websocket -> dependent analysis -> discord.

Worker -> Parser -> Normalizer -> State comparison -> Event -> DB ->
  Celery event handler -> {Dashboard WebSocket, Dependent analysis, Discord}

TASK-032 fingerprint: event_type|target|asset|old_hash|new_hash.
TASK-033 evidence: target/asset/type/severity/scan/old/new/evidence/correlation/parent.
TASK-034 correlation: parent_event + correlation_id chains.
TASK-037 priority: explainable level + reasons.
TASK-043: broadcasts are target-scoped (global group only for target-less events).
TASK-053: dedup by state fingerprint, not asset identity alone.
TASK-071: structured logging with target_id/scan_run_id/task context.
"""
import hashlib
import json
import logging
import uuid

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

logger = logging.getLogger(__name__)

SEVERITY_BY_EVENT = {
    "NEW_SUBDOMAIN": "LOW", "SUBDOMAIN_CHANGED": "LOW", "SUBDOMAIN_REMOVED": "INFO",
    "SUBDOMAIN_REACTIVATED": "LOW",
    "NEW_DNS_RECORD": "INFO", "DNS_RECORD_CHANGED": "LOW", "DNS_RECORD_REMOVED": "INFO",
    "NEW_IP": "LOW", "IP_CHANGED": "LOW", "IP_REMOVED": "INFO", "IP_REACTIVATED": "LOW",
    "NEW_OPEN_PORT": "MEDIUM", "PORT_CLOSED": "INFO", "PORT_STATE_CHANGED": "LOW",
    "PORT_SERVICE_CHANGED": "LOW", "PORT_BANNER_CHANGED": "LOW",
    "NEW_HTTP_SERVICE": "LOW", "HTTP_SERVICE_CHANGED": "LOW", "HTTP_SERVICE_REMOVED": "INFO",
    "HTTP_SERVICE_REACTIVATED": "LOW",
    "NEW_URL": "INFO", "URL_CHANGED": "LOW", "URL_REMOVED": "INFO", "URL_REACTIVATED": "LOW",
    "NEW_API_ENDPOINT": "LOW", "API_ENDPOINT_CHANGED": "LOW",
    "API_ENDPOINT_REMOVED": "INFO", "API_ENDPOINT_REACTIVATED": "LOW",
    "NEW_JS": "INFO", "JS_CHANGED": "MEDIUM", "JS_REMOVED": "INFO", "JS_REACTIVATED": "LOW",
    "NEW_JS_ENDPOINT": "LOW", "NEW_JS_SECRET_CANDIDATE": "HIGH",
    "NEW_JS_DEPENDENCY": "INFO", "NEW_JS_LIBRARY": "INFO",
    "NEW_TECHNOLOGY": "LOW", "TECHNOLOGY_CHANGED": "MEDIUM", "TECH_VERSION_CHANGED": "MEDIUM",
    "TECHNOLOGY_REMOVED": "INFO", "TECHNOLOGY_REACTIVATED": "LOW",
    "NEW_CVE_CANDIDATE": "HIGH", "CVE_STATUS_CHANGED": "MEDIUM",
    "CVE_VALIDATED": "HIGH", "NEW_SECURITY_FINDING": "HIGH", "FINDING_CHANGED": "MEDIUM",
    "FINDING_RESOLVED": "INFO", "SCOPE_CHANGED": "MEDIUM", "AUTHORIZATION_EXPIRED": "HIGH",
    "BASELINE_STARTED": "INFO", "BASELINE_COMPLETED": "INFO", "JOB_FAILED": "MEDIUM",
    "JOB_STALLED": "HIGH",
}


def _hash_state(state) -> str:
    if not state:
        return ""
    return hashlib.sha256(json.dumps(state, sort_keys=True, default=str).encode()).hexdigest()[:16]


def make_fingerprint(event_type: str, asset_value: str, extra: str = "", target_id=None,
                     old_state=None, new_state=None) -> str:
    """TASK-032: identity includes target + old/new state hashes so distinct
    transitions on the same asset produce distinct events."""
    tid = str(target_id or "")
    oh = _hash_state(old_state) if old_state else ""
    nh = _hash_state(new_state) if new_state else ""
    base = f"{event_type}|{tid}|{(asset_value or '').strip().lower()}|{(extra or '').strip().lower()}|{oh}|{nh}"
    return hashlib.sha256(base.encode()).hexdigest()[:32]


def is_baseline_suppressed(target) -> bool:
    """During INITIAL_BASELINE, suppress normal NEW_* discord alerts (still persist events)."""
    return getattr(target, "baseline_status", "") == "INITIAL_BASELINE"


def _priority_for(event_type, asset_value, evidence):
    try:
        from services.priority import prioritize_event
        return prioritize_event(event_type, asset_value, evidence or {})
    except Exception:
        return SEVERITY_BY_EVENT.get(event_type, "INFO"), []


def emit_event(event_type, target=None, asset_type="", asset_id=None, asset_value="",
               source="", evidence=None, severity=None, confidence="unknown", extra_fp="",
               old_state=None, new_state=None, scan_run=None, parent_event=None,
               correlation_id=""):
    """Create event (dedup by state fingerprint), broadcast WS, trigger discord + dependents."""
    from apps.events.models import Event

    evidence = evidence or {}
    tid = getattr(target, "pk", target) if target is not None else None
    fingerprint = make_fingerprint(event_type, asset_value or "", extra_fp,
                                   target_id=tid, old_state=old_state, new_state=new_state)
    # TASK-053: same fingerprint => same state => dedup. Different state => new event.
    existing = Event.objects.filter(fingerprint=fingerprint).first()
    if existing:
        return existing, False
    sev = severity or SEVERITY_BY_EVENT.get(event_type, "INFO")
    prio, reasons = _priority_for(event_type, asset_value or "", evidence)
    # severity wins for display compat; priority stored separately
    event = Event.objects.create(
        event_type=event_type, target=target, asset_type=asset_type, asset_id=asset_id,
        asset_value=asset_value or "", severity=sev, confidence=confidence,
        source=source or "", evidence=evidence, fingerprint=fingerprint,
        old_state=old_state or {}, new_state=new_state or {},
        scan_run=scan_run, parent_event=parent_event,
        correlation_id=correlation_id or (parent_event.correlation_id if parent_event else "") or uuid.uuid4().hex[:12],
        priority=prio, priority_reasons=reasons,
    )
    logger.info("event emitted", extra={"target_id": tid, "scan_run_id": getattr(scan_run, "pk", None),
                                        "operation": "emit_event", "status": event_type,
                                        "event_id": event.id})
    broadcast_event(event)
    try:
        from apps.jobs import tasks as job_tasks
        job_tasks.handle_event_dependents.delay(event.id)
    except Exception as e:
        logger.warning("dependent dispatch failed: %s", e)
    try:
        from apps.alerts import tasks as alert_tasks
        if target is not None and is_baseline_suppressed(target) and event_type.startswith("NEW_"):
            from apps.events.models import Alert
            Alert.objects.create(event=event, target=target, channel="discord", status="SUPPRESSED",
                                 payload_preview="suppressed during INITIAL_BASELINE")
        else:
            alert_tasks.send_discord_alert.delay(event.id)
    except Exception as e:
        logger.warning("discord dispatch failed: %s", e)
    return event, True


def broadcast_event(event):
    """TASK-043: target events go ONLY to target_N group. Global 'events' group
    receives only target-less system events. Prevents cross-target WS leakage."""
    try:
        layer = get_channel_layer()
        payload = {
            "type": "event.created",
            "id": event.id, "event_type": event.event_type,
            "asset_value": event.asset_value, "severity": event.severity,
            "priority": getattr(event, "priority", event.severity),
            "target": event.target.root_domain if event.target else "",
            "target_id": event.target_id, "created_at": event.created_at.isoformat(),
            "correlation_id": getattr(event, "correlation_id", ""),
        }
        if event.target_id:
            async_to_sync(layer.group_send)(f"target_{event.target_id}", {"type": "event_message", "data": payload})
        else:
            async_to_sync(layer.group_send)("events", {"type": "event_message", "data": payload})
    except Exception as e:
        logger.warning("websocket broadcast failed: %s", e)


def broadcast_job_like(job):
    """Job progress: always to target_N when known, plus global jobs feed (no asset data)."""
    try:
        layer = get_channel_layer()
        target = getattr(job, "target", None)
        payload = {"type": "job.progress", "id": job.id,
                   "job_type": getattr(job, "job_type", "js_analysis"),
                   "status": job.status, "progress": getattr(job, "progress", 0),
                   "stage": getattr(job, "current_stage", ""),
                   "target": target.root_domain if target else "",
                   "target_id": target.id if target else None}
        if target is not None:
            async_to_sync(layer.group_send)(f"target_{target.id}", {"type": "event_message", "data": payload})
        async_to_sync(layer.group_send)("jobs", {"type": "event_message", "data": payload})
    except Exception as e:
        logger.warning("job broadcast failed: %s", e)


broadcast_job = broadcast_job_like  # backwards-compatible alias
