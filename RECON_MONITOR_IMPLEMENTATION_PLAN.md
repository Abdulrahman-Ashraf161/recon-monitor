# Recon Monitor — Full Refactoring, Hardening, Application Isolation, UI/UX, and Verification Plan

## Document Purpose

This document is the implementation specification for upgrading **Recon Monitor** from its current reconnaissance orchestration and monitoring implementation into a reliable, target-isolated, state-aware external attack-surface monitoring platform.

The document is intentionally written as an executable task plan for an AI coding agent.

The implementing agent MUST:

1. Read this entire document before modifying the repository.
2. Inspect the existing repository and understand the current implementation before changing it.
3. Execute tasks in the order defined here unless a dependency requires a different order.
4. Preserve working functionality unless a task explicitly replaces it.
5. Never claim a task is complete without performing the verification defined for that task.
6. Keep all data, jobs, events, assets, findings, reports, metrics, and UI views strictly isolated by target.
7. Update documentation whenever implementation behavior changes.
8. Run a final full-system audit after all tasks are completed.
9. Fix regressions discovered during verification before declaring the project complete.
10. Never silently weaken scope validation, authorization boundaries, or target isolation.

---

# 1. Project Vision

Recon Monitor should become a **continuous external attack-surface monitoring platform** that can:

- Monitor multiple authorized targets independently.
- Discover subdomains and external assets.
- Resolve and track DNS records.
- Discover and monitor IPs and ports.
- Probe HTTP/HTTPS services.
- Discover historical and live URLs.
- Analyze APIs.
- Analyze JavaScript assets.
- Detect technologies and versions.
- Correlate technologies with vulnerability intelligence.
- Perform targeted validation where configured.
- Track asset state over time.
- Detect meaningful changes.
- Correlate related changes into attack-surface events.
- Prioritize important changes.
- Notify users without producing excessive duplicate alerts.
- Provide a professional target-centric web application.
- Preserve historical evidence.
- Clearly distinguish active, inactive, suspected, removed, and unknown assets.
- Provide reliable per-target reporting and analytics.

The application must not behave like one global database containing loosely related reconnaissance results.

The correct conceptual model is:

```text
User
  |
  +-- Target A
  |     |
  |     +-- Scan Runs
  |     +-- Assets
  |     +-- DNS
  |     +-- IPs
  |     +-- Ports
  |     +-- HTTP Services
  |     +-- URLs
  |     +-- APIs
  |     +-- JavaScript
  |     +-- Technologies
  |     +-- Vulnerability Candidates
  |     +-- Findings
  |     +-- Events
  |     +-- Alerts
  |     +-- Reports
  |
  +-- Target B
        |
        +-- Completely independent data lifecycle
```

Cross-target contamination MUST be impossible through normal application flows.

---

# 2. Mandatory Implementation Rules

## 2.1 Target Isolation

Every target-owned object MUST have an explicit relationship to the owning target, directly or through an immutable ownership chain.

Do not rely on hostname strings alone.

Do not infer target ownership from:

- domain suffixes,
- URLs,
- IP addresses,
- request parameters,
- frontend state,
- session state,
- object names.

Every query, API endpoint, Celery task, event, alert, report, dashboard component, and websocket update must enforce target ownership.

---

## 2.2 No Global Recon State

Avoid global tables that mix assets belonging to different targets unless the table represents genuinely global reference data.

Global reference data may include:

- CVE metadata,
- tool definitions,
- technology signatures,
- system configuration.

Target-owned data must not be global.

---

## 2.3 Historical State Must Be Preserved

Do not overwrite historical state when the purpose is monitoring.

Current state and historical observations must be distinguishable.

At minimum, the system must support:

```text
Current State
Historical Observations
Change Events
Evidence
```

---

## 2.4 Explicit Statuses

Use explicit state values rather than relying on missing rows or timestamps.

Recommended asset lifecycle:

```text
DISCOVERED
ACTIVE
SUSPECTED_INACTIVE
INACTIVE
REMOVED
REACTIVATED
UNKNOWN
```

Not every asset type needs every state, but state transitions must be explicit.

---

## 2.5 Tool Failures Must Be Honest

Do not report a scan as fully successful when a major tool failed and a reduced-capability fallback was used.

Use:

```text
PENDING
RUNNING
COMPLETED
PARTIAL
DEGRADED
FAILED
CANCELLED
SKIPPED
```

A scan result should indicate which capabilities were actually executed.

---

# 3. Phase 0 — Repository Baseline and Architecture Audit

## TASK-001 — Repository Inventory

### Goal

Create an accurate map of the repository before refactoring.

### Actions

Inspect:

- Django apps
- models
- views
- serializers/forms
- URLs/routes
- Celery tasks
- management commands
- tool adapters
- normalization
- correlation
- event engine
- scope engine
- monitoring tasks
- templates
- static files
- JavaScript
- CSS
- migrations
- settings
- Docker configuration
- environment configuration
- tests
- README
- workflow documentation

### Required Output

Create:

```text
docs/ARCHITECTURE.md
```

Document:

- current architecture
- data flow
- task flow
- target ownership
- event flow
- UI flow
- tool execution flow
- known architectural gaps

### Verification

The implementing agent must verify that every major package/module has been mapped.

---

# 4. Phase 1 — Target Isolation and Data Ownership

This phase is the highest priority.

## TASK-002 — Introduce Strong Target Ownership

### Goal

Make Target the root ownership boundary for all reconnaissance data.

### Actions

Review every model.

For every target-specific model, ensure there is a direct or immutable ownership path to:

```text
Target
```

Expected target-owned domains include:

- Subdomain
- DNSRecord
- IPAddress
- Port
- HTTPService
- URL
- APIEndpoint
- JavaScriptAsset
- JSFinding
- Technology
- TechnologyVersion
- CVECandidate
- Finding
- Event
- Alert
- ScanRun
- Observation
- Report
- ToolExecution
- AssetRelationship

### Requirements

Prefer direct:

```python
target = ForeignKey(Target, ...)
```

for critical security boundaries where practical.

If indirect ownership is used, it must be impossible for an object to reference an asset from another target.

### Verification

For every target-owned model:

- create Target A
- create Target B
- create assets under both
- verify queries for A never return B
- verify API endpoints cannot retrieve B assets using A context
- verify background tasks preserve ownership
- verify reports contain only one target

---

## TASK-003 — Add Database-Level Isolation Constraints

### Goal

Prevent invalid relationships at the database/application validation level.

### Actions

Add constraints where applicable.

Examples:

```text
Target A Subdomain
must not reference
Target B HTTPService
```

If Django/database constraints cannot express a relationship directly, enforce it in:

- model validation
- service-layer validation
- serializers/forms
- task validation

Do not rely only on frontend validation.

### Verification

Write tests attempting invalid cross-target relationships.

Expected result:

```text
Rejected
```

---

## TASK-004 — Refactor Querysets to Be Target-Scoped

### Goal

Eliminate accidental global queries.

### Actions

Search the repository for:

```text
.objects.all()
.objects.filter(...)
.objects.get(...)
.objects.first()
.objects.last()
```

in target-sensitive code.

Replace with target-scoped querysets where required:

```python
Model.objects.filter(target=target)
```

or an equivalent ownership-safe manager/service.

### Special attention

Review:

- dashboard counts
- latest assets
- latest events
- HTTP services
- JS assets
- technologies
- CVEs
- findings
- reports
- Celery tasks
- websocket broadcasts
- notification queries

### Verification

Add automated tests proving no dashboard/API/report can leak data across targets.

---

## TASK-005 — Add Target-Scoped Managers/Services

### Goal

Make safe querying the default.

Create reusable services/managers where useful:

```text
TargetScopedQuerySet
TargetAssetService
TargetEventService
TargetReportService
```

Avoid repeating unsafe filtering logic throughout views.

### Verification

At least the main application paths should use target-scoped access helpers.

---

# 5. Phase 2 — Scan Run and Observation Architecture

## TASK-006 — Introduce ScanRun

### Goal

Represent each monitoring execution as a first-class object.

Recommended fields:

```text
id
target
scan_type
profile
status
started_at
finished_at
requested_by
trigger
configuration_snapshot
error_summary
coverage_summary
```

Suggested scan types:

```text
DISCOVERY
MONITORING
ACTIVE
PASSIVE
FULL
VALIDATION
```

### Requirements

The configuration used for a scan must be preserved so historical scans remain reproducible.

---

## TASK-007 — Introduce ToolExecution

Track individual tool execution.

Recommended fields:

```text
scan_run
target
tool_name
command
status
started_at
finished_at
exit_code
stdout_reference
stderr_reference
duration
fallback_used
coverage
error
```

Do not store sensitive credentials in command logs.

### Verification

A failed tool must be visible as failed/degraded rather than silently disappearing.

---

## TASK-008 — Introduce AssetObservation

### Goal

Represent what was observed during each scan.

Recommended:

```text
scan_run
target
asset_type
asset_id
observed
metadata_hash
observed_at
evidence
```

This allows:

```text
Scan 100 → asset observed
Scan 101 → asset observed
Scan 102 → asset missing
```

without destroying history.

---

## TASK-009 — Build Snapshot/Diff Engine

### Goal

Compare two target-specific observations safely.

Pipeline:

```text
Current Scan
    |
    v
Normalized Snapshot
    |
    v
Previous Snapshot
    |
    v
Diff Engine
    |
    +-- Added
    +-- Removed
    +-- Changed
    +-- Unchanged
```

Diffs must include old and new state where applicable.

---

# 6. Phase 3 — Reconciliation and State Engine

## TASK-010 — Fix Subdomain Reconciliation

Correct incorrect event generation and lifecycle handling.

Required events:

```text
NEW_SUBDOMAIN
SUBDOMAIN_CHANGED
SUBDOMAIN_REMOVED
SUBDOMAIN_REACTIVATED
```

Do not emit `NEW_SUBDOMAIN` when an old subdomain disappears.

### Verification

Test:

```text
Scan 1: api.example.com
Scan 2: api.example.com
Scan 3: api.example.com absent
Scan 4: api.example.com returns
```

Expected:

```text
NEW_SUBDOMAIN
SUBDOMAIN_REMOVED
SUBDOMAIN_REACTIVATED
```

with no duplicate false-positive NEW events.

---

## TASK-011 — DNS State Reconciliation

Support:

```text
A
AAAA
CNAME
NS
MX
TXT
CAA
```

where supported by the selected DNS tooling.

Track:

```text
NEW_DNS_RECORD
DNS_RECORD_CHANGED
DNS_RECORD_REMOVED
```

For each change preserve:

```text
old_value
new_value
record_type
hostname
```

---

## TASK-012 — IP Lifecycle

Track:

```text
NEW_IP
IP_CHANGED
IP_REMOVED
IP_REACTIVATED
```

Preserve relationships:

```text
Subdomain -> IP
IP -> Target
IP -> Ports
```

Do not merge an IP globally between unrelated targets.

The same IP may legitimately appear in multiple targets, but each target must retain its own relationship and observations.

---

## TASK-013 — Port State Tracking

Track:

```text
NEW_OPEN_PORT
PORT_CLOSED
PORT_STATE_CHANGED
PORT_SERVICE_CHANGED
PORT_BANNER_CHANGED
```

Record:

```text
IP
port
protocol
state
service
product
version
banner
first_seen
last_seen
last_changed
```

Do not hard-code a tiny set of ports.

Port ranges must be configurable per scan profile.

---

# 7. Phase 4 — HTTP Monitoring

## TASK-014 — Build HTTP Fingerprinting

Create a normalized HTTP fingerprint containing, where available:

```text
scheme
host
port
status_code
title
redirect_chain
server
content_type
content_length
ip
tls_metadata
technologies
headers_of_interest
```

Calculate a deterministic fingerprint.

Example concept:

```text
HTTP fingerprint =
hash(normalized relevant state)
```

---

## TASK-015 — HTTP Change Detection

Generate:

```text
NEW_HTTP_SERVICE
HTTP_SERVICE_CHANGED
HTTP_SERVICE_REMOVED
HTTP_SERVICE_REACTIVATED
```

Detect changes to:

- status
- title
- IP
- server
- redirect
- TLS
- technologies
- relevant headers

Do not only compare status and title.

---

## TASK-016 — HTTP Evidence

Every meaningful HTTP change should retain enough evidence to explain:

```text
What changed?
When?
Old value?
New value?
Which scan detected it?
Which target?
Which asset?
```

---

# 8. Phase 5 — URL and Content Discovery

## TASK-017 — Complete URL Discovery Pipeline

Implement configured support for:

```text
gau
waybackurls
waymore
katana
```

Normalize and deduplicate output.

Each URL must belong to:

```text
Target
HTTPService where applicable
ScanRun
```

---

## TASK-018 — Active Content Discovery

Integrate active discovery where enabled:

```text
ffuf
dirsearch
gobuster
```

Do not automatically run all tools for every target.

Create scan profiles.

---

## TASK-019 — URL Lifecycle

Track:

```text
NEW_URL
URL_CHANGED
URL_REMOVED
URL_REACTIVATED
```

Normalize:

- scheme
- hostname
- port
- path
- query parameters
- fragments
- encoding

Avoid incorrectly treating semantically identical URLs as different assets.

---

# 9. Phase 6 — API Intelligence

## TASK-020 — Improve API Classification

Detect:

```text
REST
GraphQL
Swagger
OpenAPI
Versioned APIs
Authentication endpoints
Administrative endpoints
```

Do not rely only on path strings.

Use evidence from:

- content type
- response body
- headers
- known API schemas
- endpoint structure

---

## TASK-021 — Introduce APIEndpoint Model

Recommended:

```text
target
http_service
url
method
path
api_type
version
parameters
content_type
authentication_hint
first_seen
last_seen
state
fingerprint
```

---

## TASK-022 — API Change Detection

Generate:

```text
NEW_API_ENDPOINT
API_ENDPOINT_CHANGED
API_ENDPOINT_REMOVED
API_ENDPOINT_REACTIVATED
```

Track meaningful changes to:

- method
- path
- parameters
- API version
- content type
- schema evidence

---

# 10. Phase 7 — JavaScript Intelligence

## TASK-023 — JavaScript Asset Lifecycle

Track:

```text
target
url
source_http_service
sha256
size
status
first_seen
last_seen
state
```

Events:

```text
NEW_JS
JS_CHANGED
JS_REMOVED
JS_REACTIVATED
```

---

## TASK-024 — Complete JS Analysis Pipeline

Where configured, support:

```text
jsluice
LinkFinder
SecretFinder
regex analysis
Semgrep
Retire.js
```

Internal Python analysis may remain as a fallback, but the documentation must accurately distinguish:

```text
Native analysis
External tool analysis
Fallback analysis
```

---

## TASK-025 — Semantic JS Diff

When a JS file changes, compare:

```text
routes
API endpoints
secret candidates
dependencies
libraries
interesting strings
```

Generate secondary events such as:

```text
NEW_JS_ENDPOINT
NEW_JS_SECRET_CANDIDATE
NEW_JS_DEPENDENCY
NEW_JS_LIBRARY
```

Do not treat every SHA256 change as equally important.

---

# 11. Phase 8 — Technology Intelligence

## TASK-026 — Technology Evidence Engine

Technology detection should combine available evidence from:

```text
HTTP headers
HTML
cookies
JavaScript
TLS
response patterns
httpx
tool-specific fingerprints
```

Each technology result should ideally contain:

```text
product
vendor
version
confidence
evidence
source
```

---

## TASK-027 — Technology Change Detection

Track:

```text
NEW_TECHNOLOGY
TECHNOLOGY_CHANGED
TECHNOLOGY_REMOVED
TECHNOLOGY_REACTIVATED
```

Do not treat a low-confidence technology guess as a definitive fact.

---

# 12. Phase 9 — CVE Correlation and Validation

## TASK-028 — Normalize Technology Before CVE Matching

Normalize:

```text
vendor
product
version
```

before querying vulnerability intelligence.

Avoid naive string matching.

---

## TASK-029 — CVE Candidate Lifecycle

Use explicit states:

```text
CANDIDATE
POTENTIALLY_AFFECTED
VALIDATION_PENDING
VALIDATED
NOT_AFFECTED
EXPIRED
RESOLVED
```

A version match alone must not be represented as a confirmed vulnerability.

---

## TASK-030 — Targeted Nuclei Validation

Nuclei validation must be tied to the specific candidate asset.

Required flow:

```text
Technology
   |
   v
CVE Candidate
   |
   v
Affected Asset
   |
   v
Relevant Validation Templates
   |
   v
Validation
   |
   +-- Validated
   +-- Not Affected
   +-- Inconclusive
```

Do not simply scan an arbitrary latest-N set of HTTP services for every candidate.

---

## TASK-031 — Finding Lifecycle

Findings must support:

```text
OPEN
VALIDATED
RESOLVED
REOPENED
FALSE_POSITIVE
```

Every finding must belong to exactly one target.

---

# 13. Phase 10 — Event Engine

## TASK-032 — Redesign Event Fingerprinting

Event identity must include enough state to distinguish separate transitions.

Recommended conceptual identity:

```text
event_type
target
asset
old_state_hash
new_state_hash
```

Do not deduplicate all future changes merely because they involve the same asset.

---

## TASK-033 — Event Evidence

Every event should contain:

```text
target
asset
event_type
severity/priority
created_at
scan_run
old_state
new_state
evidence
correlation_id
parent_event
```

---

## TASK-034 — Event Correlation

Allow related events to form a chain:

```text
NEW_SUBDOMAIN
    |
    +-- NEW_IP
          |
          +-- NEW_PORT
                |
                +-- NEW_HTTP_SERVICE
                      |
                      +-- NEW_API
                            |
                            +-- NEW_JS
```

The system should be able to explain the relationship between events.

---

# 14. Phase 11 — Change Intelligence

## TASK-035 — Build Change Intelligence Layer

Do not stop at:

```text
Change detected
```

The system should answer:

```text
What changed?
Why does it matter?
What other assets are related?
What downstream changes occurred?
Which target does it belong to?
What evidence supports it?
```

---

## TASK-036 — Change Grouping

Group related changes into one logical change incident where appropriate.

Example:

```text
New subdomain
  -> new IP
  -> new port
  -> new HTTP service
  -> new API
  -> new JS
```

should be representable as one attack-surface expansion event with child changes.

---

# 15. Phase 12 — Target Prioritization

## TASK-037 — Asset Priority

Add explainable priority levels:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

Priority must be based on explicit factors.

Possible factors:

```text
asset type
exposure
asset naming indicators
change type
technology
service
API exposure
administrative surface
validation state
```

Do not present unexplained scores.

---

## TASK-038 — Priority Explanation

Every high-priority item should explain why it received that priority.

Example:

```text
HIGH

Reasons:
- Newly discovered internet-facing API
- Administrative path
- New port 8443
- Technology version changed
```

---

# 16. Phase 13 — Target-Centric Application Redesign

This phase directly addresses the requirement that results for different targets never mix.

## TASK-039 — Target Selector

The application must have a persistent target context.

Example:

```text
Target:
[ example.com ▼ ]
```

The selected target must control:

- dashboard
- assets
- scans
- events
- findings
- technologies
- reports
- alerts
- settings

Never show a global mixed dashboard unless explicitly requested.

---

## TASK-040 — Target Overview Dashboard

Create a professional target dashboard.

Suggested layout:

```text
Target Header
------------------------------------------------
Target name
Scope status
Monitoring status
Last scan
Next scan
Scan health

Metrics
------------------------------------------------
Active Assets
Subdomains
IPs
Open Ports
HTTP Services
URLs
APIs
JS Assets
Technologies
Findings

Changes
------------------------------------------------
New Assets
Removed Assets
Changed Assets
High Priority Events

Attack Surface
------------------------------------------------
Asset graph / topology

Recent Events
------------------------------------------------
Timeline

Scan Health
------------------------------------------------
Tool coverage
Failures
Degraded capabilities
```

---

## TASK-041 — Target Detail Pages

Create dedicated pages for:

```text
Target Overview
Assets
Subdomains
DNS
IPs
Ports
HTTP Services
URLs
APIs
JavaScript
Technologies
Vulnerabilities
Events
Scan Runs
Reports
Settings
```

Every page must inherit the active target context.

---

## TASK-042 — Target Isolation in Frontend

Do not rely on:

```text
localStorage
frontend filtering
hidden UI elements
```

for security.

Backend APIs must enforce target ownership.

Frontend target context is only a usability layer.

---

## TASK-043 — Prevent Cross-Target Websocket Leakage

Websocket events must include target context.

A browser subscribed to Target A must not receive:

```text
Target B events
```

even if both targets are owned by the same user.

---

# 17. Phase 14 — Professional UI/UX

## TASK-044 — Redesign Visual System

Create a consistent design system.

Requirements:

- consistent spacing
- consistent typography
- clear hierarchy
- restrained color palette
- semantic status colors
- accessible contrast
- reusable cards
- reusable tables
- reusable badges
- reusable filters
- responsive layout
- dark/light mode if supported
- professional empty states
- professional loading states
- error states
- skeleton loading where useful

Do not use excessive gradients, decorative effects, or inconsistent card styles.

---

## TASK-045 — Professional Navigation

Recommended navigation:

```text
Targets
Dashboard
Assets
  Subdomains
  DNS
  IPs
  Ports
  HTTP
  URLs
  APIs
  JavaScript
  Technologies

Security
  Vulnerability Candidates
  Findings
  Events

Operations
  Scan Runs
  Tool Health
  Reports

Configuration
  Target Settings
  Scope
  Scan Profiles
  Notifications
```

---

## TASK-046 — Asset Tables

Tables must support:

- search
- filtering
- sorting
- pagination
- status badges
- priority
- first seen
- last seen
- last changed
- target context
- export where appropriate

Avoid huge unpaginated tables.

---

## TASK-047 — Event Timeline

Create a target-specific timeline.

Example:

```text
21:42  New subdomain
       api-stage.example.com

21:43  New IP
       1.2.3.4

21:44  New port
       8443/tcp

21:44  New HTTP service
       https://api-stage.example.com:8443

21:46  New API endpoint
       /api/v2/admin
```

Allow expanding an event to inspect evidence.

---

## TASK-048 — Scan Run UI

Every scan should show:

```text
Status
Duration
Profile
Tools executed
Tools failed
Fallbacks
Coverage
Assets discovered
Changes detected
Events generated
Errors
```

---

## TASK-049 — Tool Health UI

Display:

```text
Tool
Installed
Version
Last execution
Success rate
Last error
Capability
```

Distinguish:

```text
AVAILABLE
MISSING
FAILED
DEGRADED
```

---

# 18. Phase 15 — Reporting

## TASK-050 — Target-Specific Reports

Every generated report MUST be tied to exactly one target and one scan/report scope.

Never combine targets unless an explicit multi-target report feature is implemented.

Reports should include:

```text
Target
Scan period
Executive summary
Attack surface summary
New assets
Removed assets
Changed assets
Technologies
API changes
JS changes
CVE candidates
Validated findings
Tool coverage
Failures
```

---

## TASK-051 — Historical Comparison Reports

Allow:

```text
Scan A
vs
Scan B
```

for the same target only.

Reject comparisons between unrelated targets unless explicitly designed as a cross-target comparison feature.

---

# 19. Phase 16 — Alerts and Notifications

## TASK-052 — Target-Aware Notifications

Every notification must contain:

```text
target
event
asset
timestamp
priority
evidence
```

---

## TASK-053 — Alert Deduplication

Prevent repeated alerts for the same unchanged state.

Use event/state fingerprints rather than only asset identity.

---

## TASK-054 — Alert Aggregation

Support:

```text
Immediate Alerts
Digest Alerts
Muted/ignored Events
```

Low-value repetitive changes should be aggregatable.

---

# 20. Phase 17 — Scan Profiles

## TASK-055 — Implement Scan Profiles

Minimum profiles:

### Passive

```text
Passive subdomain discovery
DNS
Historical URLs
Technology correlation
CVE correlation
```

### Balanced

```text
Passive
HTTP probing
Katana
JS analysis
Targeted validation
```

### Active

```text
Balanced
Port scanning
Content discovery
Optional active subdomain discovery
```

### Full

```text
All configured capabilities
```

Each profile must clearly show which tools/capabilities it enables.

---

# 21. Phase 18 — Scope and Safety Hardening

## TASK-056 — Scope Enforcement at Every Stage

Validate scope before:

```text
DNS operations
IP operations
Port scanning
HTTP requests
URL crawling
Content discovery
JS analysis
Nuclei validation
```

Do not assume that a discovered related asset is automatically in scope.

---

## TASK-057 — TLS Configuration

Do not silently disable certificate validation.

Make insecure TLS behavior explicit and configurable.

Recommended:

```text
verify_tls = true
```

by default.

If disabled, display the setting in scan configuration and logs.

---

## TASK-058 — Secret and Credential Hygiene

Ensure:

- API keys are never logged
- tool command output does not expose secrets unnecessarily
- Discord/webhook credentials are not stored in frontend code
- environment variables remain server-side
- reports redact sensitive values where required

---

# 22. Phase 19 — Performance and Reliability

## TASK-059 — Celery Task Isolation

Every background task must carry:

```text
target_id
scan_run_id
```

Do not infer target context from global state.

---

## TASK-060 — Idempotency

Running the same scan twice must not create uncontrolled duplicates.

Use:

```text
unique constraints
natural fingerprints
upserts
observation IDs
```

where appropriate.

---

## TASK-061 — Retry Policy

Retries must distinguish:

```text
transient failure
permanent failure
scope rejection
tool missing
invalid input
```

Do not endlessly retry invalid jobs.

---

## TASK-062 — Concurrency Safety

Test two targets scanning simultaneously.

Expected:

```text
Target A results → Target A only
Target B results → Target B only
```

No shared mutable scan state.

---

# 23. Phase 20 — Testing

## TASK-063 — Unit Tests

Cover:

- normalization
- fingerprints
- DNS diff
- HTTP diff
- URL normalization
- API classification
- JS diff
- technology normalization
- CVE matching
- event generation
- priority calculation
- scope validation

---

## TASK-064 — Target Isolation Tests

Mandatory tests:

```text
Target A asset must never appear in Target B query
Target A event must never appear in Target B dashboard
Target A scan must never update Target B asset
Target A report must never include Target B data
Target A websocket must never receive Target B event
Target A alert must never contain Target B asset
```

---

## TASK-065 — Integration Tests

Test:

```text
Discovery
→ normalization
→ ingestion
→ state update
→ diff
→ event
→ correlation
→ notification
```

for at least one realistic target fixture.

---

## TASK-066 — Regression Tests

Every bug fixed during the refactor must have a regression test.

Do not rely on manual verification for fixed logic bugs.

---

# 24. Phase 21 — Data Migration

## TASK-067 — Migration Plan

Before changing production models:

1. inspect existing data
2. identify orphaned records
3. identify records with ambiguous target ownership
4. create migrations
5. migrate valid records
6. quarantine ambiguous records
7. verify counts
8. only then enforce stricter constraints

Do not silently assign ambiguous historical records to a target.

---

# 25. Phase 22 — Documentation

## TASK-068 — Update README

README must describe actual implemented functionality.

Never document planned capabilities as implemented.

Clearly separate:

```text
Implemented
Optional
Experimental
Planned
```

---

## TASK-069 — Update Architecture Documentation

Document:

```text
Target isolation
ScanRun
Observation
Asset graph
State engine
Event engine
Tool execution
CVE lifecycle
UI architecture
```

---

## TASK-070 — Tool Capability Documentation

Document exactly:

- which tools are supported
- which are required
- which are optional
- what each tool contributes
- what fallback exists
- what coverage is lost when a tool is unavailable

---

# 26. Phase 23 — Observability

## TASK-071 — Structured Logging

Every important operation should log:

```text
target_id
scan_run_id
task_id
operation
status
duration
```

Never log secrets.

---

## TASK-072 — Scan Metrics

Track:

```text
scan duration
tool duration
tool failure rate
assets discovered
assets changed
events generated
validation count
errors
```

---

## TASK-073 — Coverage Metrics

For every scan report:

```text
requested capabilities
executed capabilities
failed capabilities
degraded capabilities
skipped capabilities
```

Example:

```text
Coverage:
82%

Executed:
HTTP probing
DNS
Subdomains
JS

Degraded:
Port scanning

Skipped:
Active content discovery
```

---

# 27. Phase 24 — Final Application Quality

## TASK-074 — Empty States

Every page must have useful empty states.

Example:

```text
No APIs discovered yet.

Run a Balanced or Active scan to populate API intelligence.
```

Avoid blank pages.

---

## TASK-075 — Error States

Errors must explain:

```text
What failed
Why it failed when known
What the user can do
```

Avoid raw stack traces in production UI.

---

## TASK-076 — Loading States

Use appropriate:

- skeletons
- spinners
- progress indicators

Do not make the application appear frozen during scans.

---

## TASK-077 — Responsive UI

Verify:

```text
Desktop
Laptop
Tablet
Mobile
```

At minimum, the application must remain usable on common desktop/laptop resolutions.

---

# 28. Phase 25 — Final Security Audit

## TASK-078 — Authorization Audit

Check every endpoint for:

```text
authentication
authorization
target ownership
object ownership
```

Test IDOR-style access:

```text
GET /target/A
GET /target/B
```

while operating under Target A context.

Expected:

```text
Target B access denied
```

---

## TASK-079 — API Isolation Audit

Review all APIs for:

- missing target filters
- object-level authorization gaps
- unsafe query parameters
- unrestricted IDs
- pagination leakage
- export leakage

---

## TASK-080 — Websocket Authorization Audit

Verify subscription authorization and target-specific broadcasting.

---

# 29. Phase 26 — Full Recon Pipeline Validation

## TASK-081 — End-to-End Test

Create a controlled test environment.

Run:

```text
Target creation
→ scope configuration
→ passive discovery
→ DNS
→ IP
→ ports
→ HTTP
→ URLs
→ APIs
→ JS
→ technologies
→ CVE candidates
→ targeted validation
→ events
→ alerts
→ dashboard
→ report
```

Verify every stage.

---

# 30. Phase 27 — Change Scenario Test Suite

The implementing agent MUST test these scenarios.

## Scenario A — New Subdomain

Expected:

```text
NEW_SUBDOMAIN
```

and target-local downstream analysis.

---

## Scenario B — Subdomain Removal

Expected:

```text
SUBDOMAIN_REMOVED
```

not `NEW_SUBDOMAIN`.

---

## Scenario C — IP Change

Expected:

```text
IP_CHANGED
```

with old/new values.

---

## Scenario D — New Port

Expected:

```text
NEW_OPEN_PORT
```

---

## Scenario E — Port Closure

Expected:

```text
PORT_CLOSED
```

---

## Scenario F — HTTP Status Change

Example:

```text
200 → 403
```

Expected:

```text
HTTP_SERVICE_CHANGED
```

---

## Scenario G — HTTP Technology Change

Example:

```text
nginx → Apache
```

Expected:

```text
HTTP_SERVICE_CHANGED
TECHNOLOGY_CHANGED
```

where supported by the correlation logic.

---

## Scenario H — JS Change

Expected:

```text
JS_CHANGED
```

plus semantic child changes where applicable.

---

## Scenario I — New API

Expected:

```text
NEW_API_ENDPOINT
```

---

## Scenario J — Technology Version Change

Expected:

```text
TECHNOLOGY_CHANGED
```

and possible CVE re-evaluation.

---

## Scenario K — CVE Candidate

Expected:

```text
CVE_CANDIDATE
```

then targeted validation.

Never report candidate as confirmed solely because of version matching.

---

# 31. Phase 28 — Multi-Target Isolation Test

## TASK-082 — Two-Target Concurrent Scan

Create:

```text
Target A
Target B
```

Run scans concurrently.

Make sure both have overlapping names where possible.

Example:

```text
api.target-a.example
api.target-b.example
```

Verify:

```text
No database contamination
No event contamination
No dashboard contamination
No websocket contamination
No alert contamination
No report contamination
No cache contamination
No task contamination
```

---

# 32. Phase 29 — UI Acceptance Checklist

The final application must satisfy:

### Navigation

- [ ] Target context is always visible.
- [ ] Switching target refreshes all target-specific content.
- [ ] Browser navigation preserves target context safely.
- [ ] No stale data remains after switching targets.

### Dashboard

- [ ] Metrics are target-specific.
- [ ] Recent events are target-specific.
- [ ] Scan status is target-specific.
- [ ] Findings are target-specific.
- [ ] Asset counts are target-specific.

### Tables

- [ ] Search works.
- [ ] Filtering works.
- [ ] Sorting works.
- [ ] Pagination works.
- [ ] Status is visible.
- [ ] Priority is visible.
- [ ] Empty state exists.
- [ ] Error state exists.

### Scan UI

- [ ] Progress is visible.
- [ ] Tool failures are visible.
- [ ] Degraded scans are clearly labeled.
- [ ] Coverage is visible.

### Events

- [ ] Timeline is target-specific.
- [ ] Event evidence is inspectable.
- [ ] Old/new state is visible.
- [ ] Related events can be followed.

---

# 33. Phase 30 — Final Full-System Audit

This phase is mandatory and MUST be performed after all implementation tasks.

## TASK-083 — Static Code Audit

Search the repository for:

```text
global asset queries
unsafe .objects.all()
target-less background tasks
target-less events
target-less notifications
hard-coded ports
hard-coded time windows
duplicate event logic
unused adapters
dead code
TODO
FIXME
temporary debugging
print()
console.log()
disabled security validation
```

Review every finding.

---

## TASK-084 — Data Model Audit

For every model answer:

```text
Does this belong to a target?
How is ownership enforced?
Can it reference another target's object?
Can it be queried without target context?
Does it need historical observations?
Does it need a state?
Does it need a fingerprint?
```

Document exceptions.

---

## TASK-085 — Pipeline Audit

Verify the actual implementation against the documented workflow.

Create a matrix:

| Capability | Documented | Implemented | Tested | Verified |
|---|---:|---:|---:|---:|
| Subdomain discovery | | | | |
| Active discovery | | | | |
| DNS | | | | |
| IP tracking | | | | |
| Port monitoring | | | | |
| HTTP monitoring | | | | |
| URL discovery | | | | |
| Content discovery | | | | |
| API intelligence | | | | |
| JS analysis | | | | |
| Technology detection | | | | |
| CVE correlation | | | | |
| Targeted validation | | | | |
| Change detection | | | | |
| Event correlation | | | | |
| Alerting | | | | |
| Reporting | | | | |

No capability may be marked implemented without evidence.

---

## TASK-086 — Target Isolation Audit

Perform explicit cross-target tests against:

```text
Database
Django views
APIs
Celery
Redis/cache if used
Websockets
Reports
Alerts
Frontend state
Search
Filters
Exports
```

Expected:

```text
0 cross-target leaks
```

---

## TASK-087 — Performance Audit

Measure:

```text
scan startup
scan duration
database query count
dashboard response time
large asset table performance
event loading
websocket behavior
concurrent scans
```

Fix obvious N+1 queries and unnecessary repeated processing.

---

## TASK-088 — Security Audit

Check:

```text
authentication
authorization
IDOR
CSRF
XSS
SQL injection
command injection
unsafe subprocess usage
path traversal
SSRF
secret leakage
websocket authorization
scope enforcement
TLS configuration
```

Any issue found must be fixed or explicitly documented as a known limitation.

---

# 34. Required Final Verification Report

After completing all tasks, the implementing AI MUST create:

```text
docs/FINAL_AUDIT.md
```

The report must contain:

## 1. Summary

What was changed.

## 2. Architecture Changes

What changed in:

```text
models
services
tasks
events
UI
API
```

## 3. Target Isolation

Explain how target isolation is enforced.

## 4. Test Results

Include:

```text
unit tests
integration tests
target isolation tests
concurrency tests
UI checks
security checks
```

## 5. Tool Coverage

Show:

```text
available
missing
optional
degraded
```

## 6. Pipeline Coverage

Document every stage:

```text
discovery
normalization
correlation
state
diff
event
validation
alert
report
```

## 7. Known Limitations

Do not hide limitations.

## 8. Remaining TODOs

Only real remaining work.

## 9. Final Verdict

The agent may declare the implementation complete only if:

```text
All mandatory tasks completed
AND
tests pass
AND
target isolation verified
AND
no known critical security issues remain
AND
documentation matches implementation
AND
full pipeline tested
```

---

# 35. Definition of Done

Recon Monitor is considered successfully refactored only when all of the following are true:

- [ ] Every target has an isolated application context.
- [ ] No target can see another target's reconnaissance data.
- [ ] Celery tasks carry explicit target and scan context.
- [ ] ScanRun exists and represents individual executions.
- [ ] ToolExecution records execution health.
- [ ] AssetObservation preserves historical observations.
- [ ] State transitions are explicit.
- [ ] Reconciliation correctly detects additions, removals, and changes.
- [ ] DNS changes are tracked.
- [ ] IP changes are tracked.
- [ ] Port changes are tracked.
- [ ] HTTP fingerprints detect meaningful changes.
- [ ] URL lifecycle is tracked.
- [ ] API intelligence is target-scoped.
- [ ] JS lifecycle is tracked.
- [ ] JS semantic changes are analyzed.
- [ ] Technologies contain evidence/confidence where possible.
- [ ] CVE matching is normalized.
- [ ] CVE candidates are not treated as confirmed findings.
- [ ] Nuclei validation is targeted.
- [ ] Findings have lifecycle states.
- [ ] Events have reliable fingerprints.
- [ ] Events preserve old/new state.
- [ ] Related events can be correlated.
- [ ] Alerts are target-aware.
- [ ] Duplicate alerts are controlled.
- [ ] Scan profiles are implemented.
- [ ] Tool failures are represented honestly.
- [ ] Scope is enforced at every active stage.
- [ ] UI is target-centric.
- [ ] UI is responsive and professional.
- [ ] Reports are target-specific.
- [ ] Cross-target tests pass.
- [ ] Security tests pass.
- [ ] Full pipeline tests pass.
- [ ] Documentation matches actual behavior.
- [ ] Final audit is complete.

---

# 36. AI Agent Execution Protocol

The implementing AI MUST follow this exact working loop for every task:

```text
1. Read task
2. Inspect existing implementation
3. Identify affected files
4. Identify dependencies
5. Implement smallest safe change
6. Run relevant tests/checks
7. Inspect results
8. Fix failures
9. Re-run tests
10. Mark task complete only after verification
```

For every completed task, maintain a checklist such as:

```text
TASK-010
Status: COMPLETE

Files changed:
- ...
- ...

Implementation:
- ...
- ...

Tests:
- ...
- ...

Verification:
PASS
```

Do not mark tasks complete based solely on code compilation.

---

# 37. AI Agent Final Instruction

Do not stop after making the requested changes.

After implementation:

1. Run the complete test suite.
2. Run target-isolation tests.
3. Run multi-target concurrent scans.
4. Run the full reconnaissance pipeline.
5. Inspect generated database state.
6. Inspect generated events.
7. Inspect alerts.
8. Inspect the application UI.
9. Verify that target switching cannot leak stale data.
10. Compare README/workflow against the actual implementation.
11. Search for incomplete integrations and unused adapters.
12. Search for obvious TODO/FIXME/debug remnants.
13. Perform the final security audit.
14. Fix issues found during the audit.
15. Run the tests again.
16. Generate `docs/FINAL_AUDIT.md`.
17. Only then report completion.

The final response from the implementing AI must summarize:

```text
Implemented
Tested
Verified
Known Limitations
Remaining Work
```

No feature should be described as implemented unless it has been verified in the actual repository.

---

# End of Implementation Specification
