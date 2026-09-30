from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def settings_index(request):
    from django.conf import settings as djsettings

    webhook = getattr(djsettings, "DISCORD_WEBHOOK_URL", "")
    masked = ("************" + webhook[-4:]) if webhook else "(not configured)"
    ctx = {
        "discord_enabled": getattr(djsettings, "DISCORD_ENABLED", False),
        "discord_masked": masked,
        "min_severity": getattr(djsettings, "DISCORD_MIN_SEVERITY", "LOW"),
    }
    return render(request, "core/settings.html", ctx)


@login_required
def system_status(request):
    from django.db import connection

    from apps.events.models import Alert
    from apps.jobs.models import ScanJob
    from services.tool_adapters.adapters import tool_health

    try:
        with connection.cursor() as c:
            c.execute("SELECT 1")
        db = "ok"
    except Exception as e:
        db = f"error: {e}"
    ctx = {
        "db": db,
        "tools": tool_health(),
        "job_counts": {
            s: ScanJob.objects.filter(status=s).count() for s, _ in ScanJob.STATUS_CHOICES
        },
        "recent_alerts": Alert.objects.select_related("event").order_by("-created_at")[:10],
    }
    return render(request, "core/system.html", ctx)
