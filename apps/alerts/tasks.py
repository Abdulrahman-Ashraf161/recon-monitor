"""Discord delivery tasks."""

from celery import shared_task


@shared_task(name="apps.alerts.tasks.send_discord_alert")
def send_discord_alert(event_id):
    from apps.events.models import Event
    from services.alerting import discord as dalert

    try:
        event = Event.objects.select_related("target").get(pk=event_id)
    except Event.DoesNotExist:
        return {"status": "SKIPPED"}
    return {"status": dalert.dispatch_event(event)}


@shared_task(name="apps.alerts.tasks.flush_discord_batches")
def flush_discord_batches():
    from services.alerting import discord as dalert

    return {"flushed": dalert.flush_batches()}


@shared_task(name="apps.alerts.tasks.send_baseline_summary")
def send_baseline_summary(target_id, summary):
    from apps.targets.models import Target
    from services.alerting import discord as dalert

    try:
        target = Target.objects.get(pk=target_id)
    except Target.DoesNotExist:
        return {"status": "SKIPPED"}
    from django.conf import settings

    if not settings.DISCORD_ENABLED or not settings.DISCORD_WEBHOOK_URL:
        return {"status": "SUPPRESSED"}
    lines = ["✅ **BASELINE COMPLETE**", f"Target: `{target.root_domain}`"]
    for k, v in (summary or {}).items():
        lines.append(f"{k}: {v}")
    sent, err = dalert.send_to_discord("\n".join(lines))
    return {"status": "SENT" if sent else "FAILED", "error": err}
