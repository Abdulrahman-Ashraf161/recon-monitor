"""P0-009 data migration: preserve legacy ScanJob.run_id and link real ScanRun rows.

``ScanJob.run_id`` was a free-form string that any caller could type into, so it
could not be constrained, joined, or trusted. The column is replaced by a real
``scan_run`` FK plus ``run_id_legacy``.

The audit copy of the legacy id was already taken by migration 0004, before the
old column was dropped. This migration:
1. links each job to a real ``ScanRun`` when a run of the same target and scan
   window can be identified unambiguously, and
3. leaves jobs unlinked (rather than guessing) when there is more than one
   candidate, recording the ambiguity in the job's stats for the operator.

Deliberately conservative: never guess when ambiguous, because a wrong
execution root silently mis-attributes findings to the wrong run.
"""
from django.db import migrations


def preserve_and_link(apps, schema_editor):
    ScanJob = apps.get_model("jobs", "ScanJob")
    ScanRun = apps.get_model("jobs", "ScanRun")

    # Group runs by target; a job is linked only when exactly one run of its
    # target overlaps the job's own lifetime.
    runs_by_target = {}
    for run in ScanRun.objects.all().values("id", "target_id", "started_at", "created_at"):
        runs_by_target.setdefault(run["target_id"], []).append(run)

    ambiguous = 0
    for job in ScanJob.objects.filter(scan_run__isnull=True).iterator():
        candidates = runs_by_target.get(job.target_id, [])
        if not candidates:
            continue
        if len(candidates) == 1:
            job.scan_run_id = candidates[0]["id"]
            job.save(update_fields=["scan_run"])
            continue
        # More than one run for the target: only link if the job's window sits
        # inside exactly one run's window. Otherwise record the ambiguity.
        job_start = job.started_at or job.created_at
        overlapping = [
            r for r in candidates
            if r["started_at"] and r["started_at"] <= job_start
            and (not job.finished_at or not r["created_at"] or r["created_at"] >= job.finished_at)
        ]
        if len(overlapping) == 1:
            job.scan_run_id = overlapping[0]["id"]
            job.save(update_fields=["scan_run"])
        elif len(overlapping) > 1:
            ambiguous += 1
            stats = dict(job.stats or {})
            stats["scan_run_link"] = {
                "legacy_run_id": job.run_id_legacy or "",
                "candidates": [r["id"] for r in overlapping],
                "note": "ambiguous: operator must set the execution root",
            }
            job.stats = stats
            job.save(update_fields=["stats"])
    if ambiguous:
        import logging

        logging.getLogger(__name__).warning(
            "%s ScanJob rows had an ambiguous execution root; recorded in stats for review",
            ambiguous,
        )


def unlink(apps, schema_editor):
    """Reverse: drop the inferred links, keep the audit copy of run_id."""
    ScanJob = apps.get_model("jobs", "ScanJob")
    ScanJob.objects.update(scan_run=None)


class Migration(migrations.Migration):

    dependencies = [("jobs", "0004_remove_scanjob_run_id_assetobservation_job_and_more")]

    operations = [migrations.RunPython(preserve_and_link, unlink)]
