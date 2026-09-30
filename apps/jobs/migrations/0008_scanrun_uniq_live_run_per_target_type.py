"""P1-001 step 2 — at most one live run per (target, scan_type).

Backs the atomic insert-and-catch in ``_get_or_create_run()`` with a database
guarantee that holds across processes. Terminal runs are unaffected, so run
history still accumulates normally.
"""
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("jobs", "0007_close_duplicate_live_scan_runs"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="scanrun",
            constraint=models.UniqueConstraint(
                condition=models.Q(("status__in", ["PENDING", "RUNNING"])),
                fields=("target", "scan_type"),
                name="uniq_live_run_per_target_type",
            ),
        ),
    ]
