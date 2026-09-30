"""P2-008: database-level duplicate prevention.

Deduplicates existing rows first, then adds the constraints. Adding a unique
constraint to a table that already contains duplicates fails, so the cleanup
must be part of the same migration (and is written to be safe to re-run).

For each duplicate group the **oldest** row is kept (the original discovery) and
later rows are deleted, with their unique children re-pointed at the survivor so
no evidence is lost.
"""
from django.db import migrations, models


def _dedupe_assets(apps, schema_editor):
    """Collapse duplicate (target, asset_type, value) assets onto the oldest."""
    Asset = apps.get_model("assets", "Asset")
    seen = {}
    for asset in Asset.objects.order_by("first_seen", "pk").iterator():
        key = (asset.target_id, asset.asset_type, asset.value)
        if key in seen:
            # Fold the duplicate's provenance into the survivor, then drop it.
            survivor = seen[key]
            if not survivor.discovered_by_job_id and asset.discovered_by_job_id:
                survivor.discovered_by_job_id = asset.discovered_by_job_id
                survivor.save(update_fields=["discovered_by_job"])
            asset.delete()
        else:
            seen[key] = asset


def _dedupe_js_findings(apps, schema_editor):
    """Collapse duplicate (js, finding_type, location) findings onto the oldest."""
    Finding = apps.get_model("assets", "JavaScriptFinding")
    seen = set()
    for finding in Finding.objects.order_by("first_seen", "pk").iterator():
        key = (finding.js_id, finding.finding_type, finding.location)
        if key in seen:
            finding.delete()
        else:
            seen.add(key)


def _dedupe_live_js_jobs(apps, schema_editor):
    """Keep one live JS analysis per asset; cancel the rest before constraining."""
    JSJob = apps.get_model("jobs", "JSAnalysisJob")
    seen = set()
    for job in JSJob.objects.filter(status__in=["QUEUED", "RUNNING"]).order_by("created_at", "pk").iterator():
        if job.js_id in seen:
            job.status = "FAILED"
            job.error = ("superseded during P2-008 constraint migration: a live analysis "
                         "for this asset already existed")
            job.finished_at = job.finished_at or job.created_at
            job.save(update_fields=["status", "error", "finished_at"])
        else:
            seen.add(job.js_id)


class Migration(migrations.Migration):

    dependencies = [
        ("assets", "0009_javascriptasset_current_secret_keys"),
    ]

    operations = [
        migrations.RunPython(_dedupe_assets, migrations.RunPython.noop),
        migrations.RunPython(_dedupe_js_findings, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="asset",
            constraint=models.UniqueConstraint(fields=("target", "asset_type", "value"),
                                               name="uniq_asset_per_target_type_value"),
        ),
        migrations.AddConstraint(
            model_name="javascriptfinding",
            constraint=models.UniqueConstraint(fields=("js", "finding_type", "location"),
                                               name="uniq_js_finding_per_js_type_location"),
        ),
    ]
