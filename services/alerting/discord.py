"""Discord alert engine: dedup already done via fingerprint; here: severity policy,
redaction, throttling/batching. HIGH/CRITICAL bypass batching."""

import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
BATCH_WINDOW_SECONDS = 300  # aggregate INFO/LOW for 5 min


def mask_secret(value: str) -> str:
    v = (value or "").strip()
    if len(v) <= 8:
        return "********"
    return f"{v[:4]}********{v[-2:]}"


def redact_evidence(evidence: dict[str, Any]) -> dict[str, Any]:
    """Return a redacted copy safe for Discord."""
    if not isinstance(evidence, dict):
        return {}
    red = {}
    for k, v in evidence.items():
        lk = k.lower()
        if any(s in lk for s in ("secret", "key", "token", "password", "credential", "auth")):
            red[k] = mask_secret(str(v)) + " (full evidence stored internally)"
        elif isinstance(v, str) and len(v) > 300:
            red[k] = v[:300] + "... (truncated)"
        else:
            red[k] = v
    return red


def format_event(event) -> str:
    if event.event_type == "NEW_SUBDOMAIN":
        target = event.target.root_domain if event.target else "-"
        return (
            "🆕 **NEW SUBDOMAIN**\n\n"
            f"Target:\n{target}\n\n"
            f"Subdomain:\n{event.asset_value[:200]}\n\n"
            f"Source:\n{event.source or '-'}\n\n"
            f"First Seen:\n{event.created_at.strftime('%Y-%m-%d %H:%M UTC')}\n\n"
            "Status:\nProcessing downstream jobs..."
        )
    icons = {"CRITICAL": "🚨", "HIGH": "🚨", "MEDIUM": "⚠️", "LOW": "ℹ️", "INFO": "ℹ️"}
    icon = icons.get(event.severity, "ℹ️")
    title = event.event_type.replace("_", " ")
    target = event.target.root_domain if event.target else "-"
    lines = [
        f"{icon} **{title}**",
        f"Asset: `{event.asset_value[:200]}`",
        f"Target: {target}",
        f"Severity: {event.severity} | Source: {event.source or '-'}",
    ]
    ev = redact_evidence(event.evidence or {})
    for k, v in list(ev.items())[:6]:
        lines.append(f"{k}: {v}")
    lines.append("Full evidence: stored internally")
    return "\n".join(lines)


def should_send(event) -> tuple[bool, str]:
    if not settings.DISCORD_ENABLED or not settings.DISCORD_WEBHOOK_URL:
        return False, "discord disabled"
    min_sev = getattr(settings, "DISCORD_MIN_SEVERITY", "LOW")
    if SEV_ORDER.get(event.severity, 0) < SEV_ORDER.get(min_sev, 0):
        return False, f"below min severity {min_sev}"
    return True, "ok"


def send_to_discord(text: str) -> tuple[bool, str]:
    import requests

    url = settings.DISCORD_WEBHOOK_URL
    if not url:
        return False, "no webhook"
    # Discord limit 2000 chars
    if len(text) > 1900:
        text = text[:1900] + "\n...(truncated)"
    try:
        r = requests.post(url, json={"content": text}, timeout=15)
        if r.status_code in (200, 204):
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)[:500]


def dispatch_event(event):
    """Immediate send for MEDIUM+; batch INFO/LOW into digest window."""
    from apps.events.models import Alert
    from apps.monitoring.models import DiscordBatch

    ok, reason = should_send(event)
    if not ok:
        Alert.objects.create(
            event=event, channel="discord", status="SUPPRESSED", payload_preview=reason
        )
        return "SUPPRESSED"
    if SEV_ORDER.get(event.severity, 0) >= SEV_ORDER.get("MEDIUM", 2):
        text = format_event(event)
        sent, err = send_to_discord(text)
        Alert.objects.create(
            event=event,
            channel="discord",
            status="SENT" if sent else "FAILED",
            payload_preview=text[:500],
            error="" if sent else err,
            sent_at=timezone.now() if sent else None,
        )
        return "SENT" if sent else "FAILED"
    # batch INFO/LOW
    window_end = timezone.now() + timedelta(seconds=BATCH_WINDOW_SECONDS)
    batch = DiscordBatch.objects.filter(status="PENDING").order_by("-created_at").first()
    if batch is None:
        batch = DiscordBatch.objects.create(
            status="PENDING", event_ids=[], window_ends_at=window_end
        )
    ids = batch.event_ids or []
    if event.id not in ids:
        ids.append(event.id)
    batch.event_ids = ids
    batch.save(update_fields=["event_ids"])
    Alert.objects.create(
        event=event,
        channel="discord",
        status="BATCHED",
        payload_preview=f"batched, window ends {batch.window_ends_at}",
    )
    return "BATCHED"


def flush_batches() -> int:
    """Send due digest batches. Returns number of batches flushed."""
    from apps.events.models import Alert, Event
    from apps.monitoring.models import DiscordBatch

    now = timezone.now()
    count = 0
    for batch in DiscordBatch.objects.filter(status="PENDING", window_ends_at__lte=now):
        events = list(
            Event.objects.filter(id__in=batch.event_ids or []).order_by("created_at")[:25]
        )
        if not events:
            batch.status = "SENT"
            batch.sent_at = now
            batch.save(update_fields=["status", "sent_at"])
            continue
        lines = ["📋 **Recon digest** (batched INFO/LOW)"]
        for e in events:
            lines.append(f"• {e.event_type} `{e.asset_value[:100]}` ({e.severity})")
        sent, err = send_to_discord("\n".join(lines))
        batch.status = "SENT" if sent else "FAILED"
        batch.sent_at = now if sent else None
        batch.save(update_fields=["status", "sent_at"])
        if not sent:
            # P2-011/P2-013: DiscordBatch has no error column, so without this
            # a FAILED batch is undiagnosable -- the operator sees a status but
            # never the reason (rate limit, bad webhook, 5xx, no webhook set).
            logger.warning(
                "discord batch send failed",
                extra={
                    "operation": "flush_discord_batches",
                    "status": "ERROR",
                    "discord_batch_id": batch.pk,
                    "event_count": len(events),
                    "error": (err or "")[:200],
                },
            )
        Alert.objects.filter(event__in=[e.id for e in events], status="BATCHED").update(
            status="SENT" if sent else "FAILED"
        )
        count += 1
    return count
