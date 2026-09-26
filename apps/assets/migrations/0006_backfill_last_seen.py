"""Task 11 edge: backfill last_seen=now() for all active rows once, so the first
reconcile after deploy does not mass-mark long-lived assets as REMOVED."""
from django.db import migrations
from django.utils import timezone


def backfill_last_seen(apps, schema_editor):
    now = timezone.now()
    for model, active_filter in [
        ("Subdomain", {"is_active": True}),
        ("IPAddress", {"is_active": True}),
        ("Port", {"state": "open"}),
        ("HTTPService", {}),
        ("URLAsset", {}),
        ("APIEndpoint", {}),
        ("JavaScriptAsset", {}),
        ("Technology", {}),
    ]:
        m = apps.get_model("assets", model)
        qs = m.objects.all()
        if active_filter:
            qs = qs.filter(**active_filter)
        qs.update(last_seen=now)


class Migration(migrations.Migration):
    dependencies = [
        ("assets", "0005_ipaddress_confirmed_dedicated_and_more"),
    ]

    operations = [
        migrations.RunPython(backfill_last_seen, migrations.RunPython.noop),
    ]
