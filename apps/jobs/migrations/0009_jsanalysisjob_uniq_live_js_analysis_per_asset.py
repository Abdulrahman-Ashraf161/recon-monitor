"""P2-008: at most one live JS analysis per asset, enforced in the database.

The cleanup runs first: any duplicate live job for the same script is failed
(never silently dropped) so the conditional unique index can be added safely.
"""
from django.db import migrations, models


def _dedupe_live_js_jobs(apps, schema_editor):
    """Keep the oldest live analysis per asset; fail the rest with a reason."""
    JSJob = apps.get_model("jobs", "JSAnalysisJob")
    seen = set()
    for job in JSJob.objects.filter(status__in=["QUEUED", "RUNNING"]).order_by("created_at", "pk").iterator():
        if job.js_id in seen:
            job.status = "FAILED"
            job.error = ("superseded during the P2-008 constraint migration: a live "
                         "analysis for this asset already existed")
            job.finished_at = job.finished_at or job.created_at
            job.save(update_fields=["status", "error", "finished_at"])
        else:
            seen.add(job.js_id)


class Migration(migrations.Migration):

    dependencies = [
        ("jobs", "0008_scanrun_uniq_live_run_per_target_type"),
    ]

    operations = [
        migrations.RunPython(_dedupe_live_js_jobs, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="jsanalysisjob",
            constraint=models.UniqueConstraint(
                fields=("js",),
                condition=models.Q(status__in=["QUEUED", "RUNNING"]),
                name="uniq_live_js_analysis_per_asset",
            ),
        ),
    ]
