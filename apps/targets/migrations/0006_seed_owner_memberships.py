"""P0-002 data migration: seed TargetMembership rows for the pre-existing install.

Before this migration the platform was single-tenant ("every authenticated
viewer may browse every target"). Switching to enforced membership would have
locked every existing operator out of the targets already in the database, so
we backfill explicit OWNER rows for the users who demonstrably had full access
before: Django superusers and ADMIN-profile users.

This is the only "invent" step in the remediation, and it is deliberately
conservative: it grants OWNER only to users who already had global access, and
never invents memberships for ordinary viewers/operators (they must be granted
access deliberately by an owner).
"""
from django.db import migrations


def seed_owners(apps, schema_editor):
    User = apps.get_model("auth", "User")
    Profile = apps.get_model("accounts", "Profile")
    Target = apps.get_model("targets", "Target")
    TargetMembership = apps.get_model("targets", "TargetMembership")

    # ``accounts.0003`` is a hard dependency of this migration, so the Profile
    # table always exists here; no defensive try/except is needed (and none may
    # be added — a swallowed failure would silently skip the backfill).
    admin_user_ids = {u.pk for u in User.objects.filter(is_superuser=True)}
    admin_user_ids |= {
        p.user_id for p in Profile.objects.filter(role="ADMIN", is_global_target_admin=True)
    }

    if not admin_user_ids:
        return

    target_ids = list(Target.objects.values_list("id", flat=True))
    existing = set(
        TargetMembership.objects.filter(user_id__in=admin_user_ids).values_list(
            "user_id", "target_id"
        )
    )
    rows = [
        TargetMembership(user_id=uid, target_id=tid, role="OWNER")
        for tid in target_ids
        for uid in admin_user_ids
        if (uid, tid) not in existing
    ]
    if rows:
        TargetMembership.objects.bulk_create(rows, batch_size=500)


def unseed_owners(apps, schema_editor):
    """Reverse: intentionally does NOT delete membership rows.

    These rows carry no provenance marker, so by the time a rollback happens the
    OWNER grants seeded here are indistinguishable from grants an operator made
    afterwards. Deleting them would strip real access from real users and could
    re-lock the install, which is a far worse outcome than leaving the backfill
    in place — rolling back this data migration does not disable the isolation
    feature, the ``SINGLE_TENANT_ALL_TARGETS`` / global-admin settings do.
    """
    import logging

    logging.getLogger(__name__).warning(
        "0006 reverse: TargetMembership backfill left in place on purpose; "
        "verify access manually before rolling further back"
    )


class Migration(migrations.Migration):

    dependencies = [
        ("targets", "0005_targetmembership_target_archived_at_and_more"),
        ("accounts", "0003_profile_is_global_target_admin"),
    ]

    operations = [migrations.RunPython(seed_owners, unseed_owners)]
