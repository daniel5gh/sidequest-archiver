# Project Overview

This project monitors selected Sidequest apps and automatically archives APKs whenever a new release is available. The preferred deployment is intentionally minimal: a single Python script that runs periodically (cron on Linux/macOS or Task Scheduler on Windows) and performs the monitoring, download, and archival tasks.

Monitored app IDs (explicit):

- example1 (pico): 123
- example2 (oculus): 321

Reference test data: [`test-data/app-metadata-123.json`](test-data/app-metadata-123.json:1)

---

# Requirements

## Functional Requirements

- Fetch metadata for each monitored app from Sidequest API: https://api.sidequestvr.com/v2/apps/{app_id}
- Detect when a new APK/release becomes available (based on version or release identifier in metadata).
- Download APK artifact for the new release and store it in the configured archive location.
- Store metadata and APK with a clear naming scheme (appid_version_date.apk and a matching metadata.json alongside).
- Optional: send a notification (webhook or email) when a new APK is archived.

## Non-Functional Requirements (NFR)

- Implementation must be as simple and lean as possible; running a single Python file from a cronjob (or scheduled task) is sufficient.  <-- PROMINENT NFR
- The solution should have minimal runtime dependencies (prefer standard library plus 1-2 small packages such as requests).
- The monitor should be idempotent and safe to run concurrently if scheduled accidentally (use atomic file write or temp-then-rename scheme).
- Storage may be local filesystem or any S3-compatible bucket; the script should support both via simple configuration.
- Logging must be available to stdout and optionally to a rotating file for diagnostics.

---

# System Architecture

Minimal design (explicitly simple):

- Scheduler: cron (Linux/macOS) or Windows Task Scheduler — triggers the monitor periodically.
- Single Python monitor script: performs polling, comparison, download, and storage operations.
- Storage: filesystem (local path) or simple S3-compatible bucket (optional). Files are archived with deterministic names.
- Optional notification: webhook or SMTP email to alert on new archived releases.

Remove complex components: message queues, databases, microservices, or separate workers are not required for the standard deployment and are omitted here. They can be added later only if clear scaling needs emerge.

Data Flow Diagram (single-script flow):

Mermaid (recommended):

```mermaid
flowchart LR
  Scheduler[Scheduler \n(cron / Task Scheduler)] --> Monitor[Single Python monitor script]
  Monitor -->|fetch metadata| SidequestAPI[Sidequest API\n/api/v2/apps/{app_id}]
  Monitor -->|compare| LocalState[Local archive state\n(e.g., manifest files on disk)]
  Monitor -->|download APK| Storage[Storage \n(local filesystem or S3-compatible)]
  Monitor -->|write metadata| Storage
  Monitor -->|optional notify| Notification[Webhook or Email]

  subgraph MonitoredApps[Monitored App IDs]
    A123[Example App 1 - 123]
    A321[Example App 2 - 321]
    A456[Example App 3 - 456]
  end

  SidequestAPI --> MonitoredApps
```

ASCII variant (if Mermaid not available):

Scheduler (cron/task)
  |
  v
Single Python monitor script
  |-- fetch metadata from https://api.sidequestvr.com/v2/apps/{app_id}
  |   (see test data: [`test-data/app-metadata-123.json`](test-data/app-metadata-123.json:1))
  |-- compare with local archive state
  |-- download APK when new
  |-- store APK + metadata -> storage (local or S3)
  |-- optional notify -> webhook/email

---

# Implementation Plan

The following steps are written to be actionable for Code mode to implement as a single script.

1. Create single entrypoint Python script (example name: sidequest_monitor.py) with a small configuration section at top (or via environment variables):
   - MONITORED_APP_IDS = [123, 321, 456]  # Example app IDs
   - SIDEQUEST_API_TEMPLATE = "https://api.sidequestvr.com/v2/apps/{app_id}"
   - STORAGE_BACKEND = "local" or "s3"
   - LOCAL_ARCHIVE_DIR = "./archive"
   - S3_BUCKET and S3_PREFIX (if using S3)
   - NOTIFICATION_WEBHOOK_URL or SMTP settings (optional)
   - POLL_INTERVAL is irrelevant to cron (script should run, do work, exit)

2. Implement metadata fetch and parsing:
   - Use requests (or urllib) to call the API for each app id.
   - For local testing, allow loading a test-data JSON file (e.g., `test-data/app-metadata-EXAMPLE.json`) when a `--test-file` flag or environment variable is set.

3. Implement change detection:
   - Maintain a small local manifest file (JSON) per app or a single manifest mapping app_id -> last_seen_version.
   - Compare fetched metadata version (or APK identifier) to manifest.
   - If newer, proceed to download.

4. Download APK:
   - Determine APK download URL from metadata (document exact metadata fields in code comments).
   - Use safe download: stream to temporary file then rename atomically into archive directory.
   - Save metadata JSON alongside the APK using a consistent filename pattern: {appid}_{version}_{YYYYMMDD}.apk and {appid}_{version}_{YYYYMMDD}.metadata.json

5. Storage abstraction (very small):
   - Implement local filesystem writer by default.
   - Optionally support S3 with boto3 if configured (keep optional and disabled by default).

6. Notifications (optional):
   - If configured, POST a small payload to a webhook URL or send an email via SMTP containing app id, version, and archive path.

7. Idempotency and retries:
   - Retry downloads a small number of times on transient failures.
   - Ensure manifest update is performed after successful archive and is durable.

8. Logging and error handling:
   - Log start/end, detected changes, download progress, and errors to stdout and to an optional local log file.

9. Packaging/run:
   - Provide a minimal README section or script header explaining how to add a cronjob or Task Scheduler entry. Example cron: `0 * * * * /usr/bin/python3 /path/to/sidequest_monitor.py` (run hourly)

---

# Testing Strategy

- Unit tests: functions for parsing metadata and detecting version deltas. Use a generic test-data file as a fixture: [`test-data/app-metadata-EXAMPLE.json`](test-data/app-metadata-EXAMPLE.json:1).
- Integration test: run the script in a test mode that reads local test-data and writes to a temporary directory; assert files and metadata are written and manifest is updated.
- Manual acceptance: run the script once against the live Sidequest API for one app id, verify APK download and metadata storage.
- Failure scenarios: test network failures, partial downloads, and concurrent runs to ensure idempotency.

---

Notes

- This plan intentionally keeps the design minimal and operationally simple. The single-file approach is the preferred deployment model unless future needs justify moving to more complex infrastructures.
- Keep configuration, secrets, and credentials out of source control. Prefer environment variables for secrets (S3 credentials, SMTP).
- No specific app IDs or program names are hardcoded in the implementation; all are configurable at runtime.
