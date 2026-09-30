"""Deterministic multi-target fixtures (P3-009).

Every security/isolation test in the suite builds its world from these helpers
so that the authorization matrix is identical everywhere:

    admin  — superuser (global override)
    user_a — VIEWER on Target A only
    user_b — VIEWER on Target B only
    owner_a — OWNER on Target A
    operator_a — OPERATOR on Target A
    Target A, Target B  (+ archive/unauthorized variants)

Import from tests.fixtures (module-level helpers, no TestCase inheritance) so
they work with both ``manage.py test`` and ``pytest``.
"""

from django.contrib.auth.models import User
from django.utils import timezone

from apps.assets.models import (
    CVE,
    APIEndpoint,
    HTTPService,
    IPAddress,
    JavaScriptAsset,
    Port,
    SecurityFinding,
    Subdomain,
    Technology,
    URLAsset,
)
from apps.events.models import Alert, Event
from apps.jobs.models import AssetObservation, ScanJob, ScanRun, ToolExecution
from apps.monitoring.models import ExportJob
from apps.targets.models import Target, TargetMembership

# Fixed password for every fixture user. Never used outside tests.
FIXTURE_PASSWORD = "Fixture-Passw0rd!2024"

COUNTER = {"n": 0}


def _uniq(prefix):
    COUNTER["n"] += 1
    return f"{prefix}-{COUNTER['n']}"


def reset_counters():
    COUNTER["n"] = 0


def make_user(
    username=None,
    role="VIEWER",
    superuser=False,
    password=FIXTURE_PASSWORD,
    must_change_password=False,
):
    username = username or _uniq("user")
    user = User.objects.create_user(
        username=username,
        email=f"{username}@fixture.invalid",
        password=password,
        is_superuser=superuser,
        is_staff=superuser,
    )
    profile = user.profile
    profile.role = role
    profile.must_change_password = must_change_password
    profile.save()
    return user


def make_admin(username=None):
    return make_user(username=username, role="ADMIN", superuser=True)


def make_target(
    root_domain=None,
    name=None,
    status=Target.STATUS_ACTIVE,
    authorization_status=Target.AUTH_AUTHORIZED,
    authorization_expires_at=None,
    baseline_status="BASELINE_COMPLETE",
    **kwargs,
):
    root_domain = root_domain or f"{_uniq('t')}.example.com"
    return Target.objects.create(
        name=name or root_domain,
        root_domain=root_domain,
        status=status,
        authorization_status=authorization_status,
        authorization_expires_at=authorization_expires_at,
        baseline_status=baseline_status,
        **kwargs,
    )


def grant(user, target, role=TargetMembership.ROLE_VIEWER):
    return TargetMembership.objects.create(user=user, target=target, role=role)


def make_world():
    """Build the canonical two-target, two-user world.

    Returns a dict with every handle the tests need. Nothing is shared between
    worlds — each call creates fresh rows.
    """
    admin = make_admin()
    user_a = make_user(role="VIEWER")
    user_b = make_user(role="VIEWER")
    owner_a = make_user(role="OPERATOR")
    operator_a = make_user(role="OPERATOR")
    outsider = make_user(role="VIEWER")

    target_a = make_target(root_domain="alpha.example.com")
    target_b = make_target(root_domain="beta.example.com")

    grant(user_a, target_a, TargetMembership.ROLE_VIEWER)
    grant(user_b, target_b, TargetMembership.ROLE_VIEWER)
    grant(owner_a, target_a, TargetMembership.ROLE_OWNER)
    grant(operator_a, target_a, TargetMembership.ROLE_OPERATOR)
    # `outsider` intentionally holds NO membership anywhere.

    return {
        "admin": admin,
        "user_a": user_a,
        "user_b": user_b,
        "owner_a": owner_a,
        "operator_a": operator_a,
        "outsider": outsider,
        "target_a": target_a,
        "target_b": target_b,
    }


def make_scan_run(target, scan_type="MONITORING", status="RUNNING", **kwargs):
    return ScanRun.objects.create(
        target=target,
        scan_type=scan_type,
        status=status,
        started_at=timezone.now(),
        **kwargs,
    )


def make_scan_job(
    target, job_type="http", status=ScanJob.STATUS_COMPLETED, scan_run=None, parent=None, **kwargs
):
    return ScanJob.objects.create(
        target=target,
        job_type=job_type,
        status=status,
        scan_run=scan_run,
        parent=parent,
        started_at=timezone.now(),
        finished_at=timezone.now(),
        **kwargs,
    )


def make_tool_execution(
    target,
    scan_run=None,
    job=None,
    tool_name="httpx",
    status=ToolExecution.STATUS_COMPLETED,
    **kwargs,
):
    return ToolExecution.objects.create(
        target=target,
        scan_run=scan_run,
        job=job,
        tool_name=tool_name,
        status=status,
        started_at=timezone.now(),
        finished_at=timezone.now(),
        exit_code=0,
        **kwargs,
    )


def make_observation(
    target,
    scan_run,
    asset_type="SUBDOMAIN",
    asset_value="a.alpha.example.com",
    job=None,
    tool_execution=None,
    observed=True,
    **kwargs,
):
    return AssetObservation.objects.create(
        target=target,
        scan_run=scan_run,
        asset_type=asset_type,
        asset_value=asset_value,
        job=job,
        tool_execution=tool_execution,
        observed=observed,
        **kwargs,
    )


def make_event(
    target,
    event_type="NEW_SUBDOMAIN",
    asset_value="a.alpha.example.com",
    scan_run=None,
    parent_event=None,
    **kwargs,
):
    import uuid

    from services.event_engine.engine import make_fingerprint

    fingerprint = kwargs.pop(
        "fingerprint",
        make_fingerprint(
            event_type,
            asset_value,
            kwargs.pop("extra_fp", ""),
            target_id=getattr(target, "pk", None),
            old_state=kwargs.get("old_state"),
            new_state=kwargs.get("new_state"),
        ),
    )
    return Event.objects.create(
        event_type=event_type,
        target=target,
        asset_value=asset_value,
        fingerprint=fingerprint or uuid.uuid4().hex[:32],
        scan_run=scan_run,
        parent_event=parent_event,
        **kwargs,
    )


def make_alert(event, target=None, status=Alert.STATUS_PENDING, **kwargs):
    return Alert.objects.create(
        event=event,
        target=target or event.target,
        status=status,
        **kwargs,
    )


def make_export_job(
    target,
    created_by=None,
    export_type="subdomains",
    format="txt",
    status=ExportJob.STATUS_QUEUED,
    **kwargs,
):
    return ExportJob.objects.create(
        target=target,
        created_by=created_by,
        export_type=export_type,
        format=format,
        status=status,
        **kwargs,
    )


# --- asset factories (used by export-isolation tests) -------------------------


def seed_assets_for(target, marker):
    """Create one of every asset type for `target`, all values tagged `marker`.

    Field names/required args verified against apps.assets.models: every asset
    needs first_seen/last_seen, HTTPService needs url+host, URLAsset needs
    raw_url, JS needs host+sha256, Technology/CVE/Finding need asset_value and
    their own type fields.
    """
    from django.utils import timezone

    now = timezone.now()
    common = {"first_seen": now, "last_seen": now}
    DNSRecord = __import__("apps.assets.models", fromlist=["DNSRecord"]).DNSRecord

    sub = Subdomain.objects.create(
        target=target, hostname=f"{marker}.{target.root_domain}", **common
    )
    ip = IPAddress.objects.create(target=target, ip="93.184.216.34", is_active=True, **common)
    dns = DNSRecord.objects.create(
        target=target, hostname=sub.hostname, record_type="A", value=ip.ip, **common
    )
    # Port.ip and HTTPService.ip/port are plain columns (CharField/IntegerField),
    # not relations — pass the scalar values, not the model instances.
    port = Port.objects.create(
        target=target, ip=ip.ip, port=443, protocol="tcp", state="open", **common
    )
    http = HTTPService.objects.create(
        target=target,
        ip=ip.ip,
        port=port.port,
        host=sub.hostname,
        url=f"https://{sub.hostname}",
        **common,
    )
    url = URLAsset.objects.create(
        target=target,
        raw_url=f"https://{sub.hostname}/x?a=1",
        canonical_url=f"https://{sub.hostname}/x",
        host=sub.hostname,
        **common,
    )
    api = APIEndpoint.objects.create(
        target=target,
        url=f"https://{sub.hostname}/api/v1",
        method="GET",
        host=sub.hostname,
        **common,
    )
    js = JavaScriptAsset.objects.create(
        target=target,
        js_url=f"https://{sub.hostname}/a.js",
        host=sub.hostname,
        sha256=("0" * 63 + "1"),
        **common,
    )
    tech = Technology.objects.create(
        target=target,
        product=f"nginx-{marker}",
        version="1.0",
        asset_value=f"https://{sub.hostname}",
        **common,
    )
    cve = CVE.objects.create(
        target=target,
        cve_id=f"CVE-2024-{marker.upper()[:4]}",
        product="nginx",
        asset_value=f"https://{sub.hostname}",
        **common,
    )
    finding = SecurityFinding.objects.create(
        target=target,
        title=f"finding-{marker}",
        finding_type="MISCONFIG",
        asset_value=f"https://{sub.hostname}",
        **common,
    )
    return {
        "subdomain": sub,
        "ip": ip,
        "dns": dns,
        "port": port,
        "http": http,
        "url": url,
        "api": api,
        "js": js,
        "technology": tech,
        "cve": cve,
        "finding": finding,
    }
