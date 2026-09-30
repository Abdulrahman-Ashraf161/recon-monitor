"""P1-001 step 1 — close duplicate live runs before enforcing uniqueness.

The conditional unique index added in 0008 cannot be applied while two live
runs exist for the same (target, scan_type) — that is precisely the state the
old check-then-act code could produce. Rather than silently deleting history
(these rows carry the evidence of the race), the *newest* run in each
duplicated group is kept as the surviving live run and the older duplicates are
retired to SKIPPED with an explanatory error summary.

Keeps the newest because it is the run a worker would most likely have been
holding, and it is the one whose jobs/observations reference live stages.
Retiring the older ones loses no provenance: they keep their jobs, tool
executions and observations, and remain queryable.
"""
from django.db import migrations

TERMINAL = "SKIPPED"


def close_duplicates(apps, schema_editor):
    ScanRun = apps.get_model("jobs", "ScanRun")
    db = schema_editor.connection.alias

    seen = set()
    duplicates = []
    # Newest first, so the first row seen for a (target, scan_type) is the keeper.
    for run in (ScanRun.objects.using(db)
                .filter(status__in=["PENDING", "RUNNING"])
                .order_by("target_id", "scan_type", "-created_at", "-pk")):
        key = (run.target_id, run.scan_type)
        if key in seen:
            duplicates.append(run.pk)
        else:
            seen.add(key)

    if not duplicates:
        return

    ScanRun.objects.using(db).filter(pk__in=duplicates).update(
        status=TERMINAL,
        error_summary=(
            "Retired by migration 0007: duplicate live run for the same "
            "(target, scan_type) created by the pre-P1-001 race in "
            "_get_or_create_run(). Historical jobs and observations are intact."
        ),
    )


def restore_note(apps, schema_editor):
    """Reversible: the constraint (0008) is unapplied first, so nothing to undo.

    Retiring a duplicate is not undone — restoring it to PENDING/RUNNING would
    re-create the exact race this migration exists to close.
    """


class Migration(migrations.Migration):
    dependencies = [
        ("jobs", "0006_jsanalysisjob_scan_run"),
        ("targets", "0006_seed_owner_memberships"),
    ]

    operations = [
        migrations.RunPython(close_duplicates, restore_note),
    ]
