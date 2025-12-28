#!/usr/bin/env python3
"""
sidequest_monitor.py

Usage:
    python sidequest_monitor.py [--dry-run]

Description:
    Minimal Sidequest APK monitor. Monitors a list of Sidequest app IDs and downloads new APK
    releases into ./apks/ while maintaining a small index file at ./apks/index.json. Writes logs to
    stdout and ./sidequest_monitor.log.

Cron/Task Scheduler example:
    0 * * * * cd /path/to/repo && /usr/bin/python3 sidequest_monitor.py

Dry-run:
    Use --dry-run to avoid network calls. For a specific app ID the script will use a bundled
    test-data/app-metadata-EXAMPLE.json file. For other app IDs the script will skip network calls and
    log a warning. (This is for test/demo purposes; replace the example ID with any app ID and provide your own test data as needed.)

Notes:
    - Optional config: create monitor_config.json at project root to override app_ids and storage
      directory. See monitor_config.json.example for format. Secrets for S3 should not be stored in
      this file.
    - Optional S3 upload: if environment variables S3_BUCKET, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
      are set and boto3 is installed, the script will attempt to upload the archived APK to S3.

"""

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Use requests for HTTP; listed in requirements.txt
try:
    import requests
except Exception:  # pragma: no cover - runtime fallback
    requests = None

# Optional S3 support via boto3 (only used if available and env vars present)
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception:
    boto3 = None

# Defaults
DEFAULT_APP_IDS = []  # No default app IDs; monitor_config.json is mandatory
API_URL_TEMPLATE = "https://api.sidequestvr.com/v2/apps/{app_id}"
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
APKS_DIR = os.path.join(PROJECT_ROOT, "apks")
INDEX_PATH = os.path.join(APKS_DIR, "index.json")
LOG_PATH = os.path.join(PROJECT_ROOT, "sidequest_monitor.log")
MONITOR_CONFIG_PATH = os.path.join(PROJECT_ROOT, "monitor_config.json")
TEST_DATA_EXAMPLE = os.path.join(PROJECT_ROOT, "test-data", "app-metadata-EXAMPLE.json")  # Example test data file

# Basic logging to stdout and file
logger = logging.getLogger("sidequest_monitor")
DEFAULT_LOG_LEVEL = logging.INFO  # Default log level is INFO
logger.setLevel(DEFAULT_LOG_LEVEL)
fmt = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(fmt)
logger.addHandler(sh)
fh = logging.FileHandler(LOG_PATH)
fh.setFormatter(fmt)
logger.addHandler(fh)

# Helper to set log level for both stdout and file handlers
# This ensures both handlers respect the chosen log level

def set_log_level(level):
    logger.setLevel(level)
    for handler in logger.handlers:
        handler.setLevel(level)

# Helper: load optional monitor config
def load_config() -> Dict[str, Any]:
   if not os.path.exists(MONITOR_CONFIG_PATH):
       logger.error("monitor_config.json is required but was not found. Please create it from monitor_config.json.example.")
       sys.exit(1)
   try:
       with open(MONITOR_CONFIG_PATH, "r", encoding="utf-8") as f:
           return json.load(f)
   except Exception as e:
       logger.error("Failed to load monitor_config.json: %s", e)
       sys.exit(1)

# Helper: safe filename slug
def slugify(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[\s]+", "-", s)
    s = re.sub(r"[^A-Za-z0-9.\-]+", "", s)
    return s

# Helper: compute a short hash for fallback version token
def short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:12]

# Atomic file write helper
import tempfile
import shutil

def atomic_write_file(dest_path: str, writer, mode: str = "wb") -> None:
    """
    Atomically write to a file using a streaming approach.
    Accepts a callback or context manager that receives a writable file object and streams data to it.
    Args:
        dest_path: Final file path.
        writer: Callable[[file], None] or context manager yielding file. Writes data to the file object.
        mode: File mode, 'wb' for binary, 'w' for text.
    """
    dest_dir = os.path.dirname(dest_path)
    os.makedirs(dest_dir, exist_ok=True)
    base_name = os.path.basename(dest_path)
    fd, tmp_path = tempfile.mkstemp(prefix=base_name + ".", suffix=".tmp", dir=dest_dir)
    try:
        with os.fdopen(fd, mode) as f:
            logger.debug(f"[atomic_write_file] Streaming write to temp file {tmp_path}")
            writer(f)
        logger.info(f"Atomic write: moving temp file {tmp_path} to {dest_path}")
        if os.path.exists(dest_path):
            logger.warning(f"Destination file {dest_path} already exists and will be replaced atomically")
        os.replace(tmp_path, dest_path)
        logger.info(f"Atomic move complete: {tmp_path} -> {dest_path}")
    except Exception as e:
        logger.error(f"Atomic write failed, cleaning up temp file: {tmp_path}")
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        raise

# Load or initialize index.json
def load_index() -> Dict[str, List[Dict[str, Any]]]:
    if not os.path.exists(INDEX_PATH):
        return {}
    try:
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("Failed to read index.json: %s", e)
        return {}

def save_index(index: Dict[str, List[Dict[str, Any]]]) -> None:
    os.makedirs(APKS_DIR, exist_ok=True)
    # Use atomic_write_file for index.json (streaming)
    def writer(f):
        f.write(json.dumps(index, indent=2, sort_keys=True).encode("utf-8"))
    atomic_write_file(INDEX_PATH, writer, mode="wb")

# Hardcoded headers from provided curl example
# These will be used for all Sidequest API and APK requests

def load_agent_headers() -> Dict[str, str]:
    return {
        "accept": "application/json",
        "accept-language": "en-US,en;q=0.9",
        "content-type": "application/json",
        "if-none-match": "W/\"c16-c8YoyiW+l73rqXabzkmmFA0SgPg\"",
        "origin": "https://sidequestvr.com",
        "priority": "u=1, i",
        "referer": "https://sidequestvr.com/",
        "sec-ch-ua": '"Microsoft Edge";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36 Edg/143.0.0.0",
        "x-sq-sid": "c00c88e9-e205-4d9b-9b25-0fea51c640f2",
        "x-sq-tid": "2f2b26cd-34c1-4cf5-ad16-efaf1b613e6d"
    }

# Global headers - will be initialized in main()
AGENT_HEADERS: Dict[str, str] = {}

# Parse metadata to find apk download URL and version
def extract_apk_info(metadata: Dict[str, Any]) -> Optional[Dict[str, str]]:
   app_name = metadata.get("name") or metadata.get("title") or metadata.get("appName") or "unknown"
   candidates = []

   # Existing heuristics
   for key in ("apks", "apks_list", "downloads", "files", "releases", "versions"):
       val = metadata.get(key)
       if isinstance(val, list):
           for item in val:
               if isinstance(item, dict):
                   for url_key in ("url", "downloadUrl", "apkUrl", "fileUrl"):
                       u = item.get(url_key)
                       if u:
                           candidates.append((u, item))
                   nested = item.get("apk")
                   if isinstance(nested, dict):
                       for url_key in ("url", "downloadUrl", "apkUrl", "fileUrl"):
                           u = nested.get(url_key)
                           if u:
                               candidates.append((u, nested))

   for url_key in ("downloadUrl", "apkUrl", "apk_download_url", "url"):
       u = metadata.get(url_key)
       if u:
           candidates.append((u, metadata))

   # NEW: handle Sidequest's "urls" field with embedded JSON
   urls_list = metadata.get("urls")
   if isinstance(urls_list, list):
       for entry in urls_list:
           if isinstance(entry, dict):
               link_url = entry.get("link_url")
               if link_url:
                   # If link_url is a JSON string, parse it
                   if link_url.strip().startswith('{'):
                       try:
                           link_obj = json.loads(link_url)
                           for v in link_obj.values():
                               if isinstance(v, str) and v.lower().endswith('.apk') and v.startswith('http'):
                                   candidates.append((v, entry))
                       except Exception:
                           pass
                   elif link_url.lower().endswith('.apk') and link_url.startswith('http'):
                       candidates.append((link_url, entry))

   # Fallback: search all strings for .apk URLs
   def find_urls(obj):
       found = []
       def _search(o):
           if isinstance(o, dict):
               for v in o.values():
                   _search(v)
           elif isinstance(o, list):
               for v in o:
                   _search(v)
           elif isinstance(o, str):
               if o.lower().endswith('.apk') and o.startswith('http'):
                   found.append(o)
       _search(obj)
       return found

   fallback = find_urls(metadata)
   if fallback:
       for url in fallback:
           candidates.append((url, metadata))

   # Pick first candidate
   if not candidates:
       return None

   apk_url, ctx = candidates[0]

   # Determine version string
   version = None
   for key in ("versionname", "version", "version_name", "verName", "v"):
       v = ctx.get(key) or metadata.get(key)
       if v:
           version = str(v)
           break
   if not version:
       # try numeric code fields
       for key in ("versionCode", "version_code", "build", "buildNumber"):
           v = ctx.get(key) or metadata.get(key)
           if v:
               version = str(v)
               break
   if not version:
       # try release id / id
       for key in ("id", "releaseId", "release_id"):
           v = ctx.get(key) or metadata.get(key)
           if v:
               version = str(v)
               break
   if not version:
       # fallback to hash of url + metadata snippet
       small = json.dumps(metadata, sort_keys=True)
       version = short_hash(apk_url + small)

   return {"app_name": app_name, "apk_url": apk_url, "version": version}

# Download helper
def download_file(url: str, dest_path: str) -> None:
    """
    Download a file from the given URL to dest_path using atomic_write_file.
    Ensures that incomplete downloads do not leave partial/corrupt files in the archive.
    This is robust and cross-platform (Windows and Unix).
    """
    # Ensure requests is available; the script previously required requests
    if requests is None:
        raise RuntimeError("requests library is required to download files")
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    logger.info("Downloading %s -> %s (atomic write)", url, dest_path)
    logger.debug("Download headers: %r", AGENT_HEADERS)
    r = requests.get(url, stream=True, timeout=60, headers=AGENT_HEADERS)
    logger.debug("HTTP status: %s", r.status_code)
    logger.debug("HTTP response headers: %r", r.headers)
    # Trace first 1024 bytes of content for debugging
    first_bytes = b""
    for chunk in r.iter_content(chunk_size=1024):
        if chunk:
            first_bytes += chunk
            break
    logger.debug("First 1024 bytes of response: %r", first_bytes)
    r.raise_for_status()
    # Write all content to file atomically
    def content_generator():
        yield first_bytes
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                yield chunk
    # Use atomic_write_file with streaming writer for APK
    def writer(f):
        for chunk in content_generator():
            f.write(chunk)
    atomic_write_file(dest_path, writer, mode="wb")

# Optional S3 upload (only if boto3 installed and env vars present)
def maybe_upload_to_s3(local_path: str, s3_key: str) -> None:
    bucket = os.environ.get("S3_BUCKET")
    access = os.environ.get("AWS_ACCESS_KEY_ID")
    secret = os.environ.get("AWS_SECRET_ACCESS_KEY")
    if not (bucket and access and secret and boto3):
        # silently skip if not configured or boto3 not installed
        return
    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=access,
            aws_secret_access_key=secret,
        )
        logger.info("Uploading %s to s3://%s/%s", local_path, bucket, s3_key)
        s3.upload_file(local_path, bucket, s3_key)
        logger.info("Upload complete")
    except (BotoCoreError, ClientError, Exception) as e:
        logger.warning("S3 upload failed: %s", e)

# Query Sidequest API (or read test-data in dry-run)
def fetch_metadata(app_id: int, dry_run: bool = False) -> Optional[Dict[str, Any]]:
   # Example: use test-data for a specific app ID in dry-run mode (for demonstration; adjust as needed)
   if dry_run and app_id == 12345:
       try:
           with open(TEST_DATA_EXAMPLE, "r", encoding="utf-8") as f:
               logger.info("Using local test-data for app %s", app_id)
               return json.load(f)
       except Exception as e:
           logger.error("Failed to read test-data for app 12345: %s", e)
           return None
   if dry_run:
       logger.warning("Dry-run: skipping network fetch for app %s", app_id)
       return None
   if requests is None:
       logger.error("requests not available; cannot perform network fetch")
       return None
   url = API_URL_TEMPLATE.format(app_id=app_id)
   try:
       logger.info("Fetching metadata for app %s from %s", app_id, url)
       logger.debug("API request headers: %r", AGENT_HEADERS)
       r = requests.get(url, timeout=30, headers=AGENT_HEADERS)
       logger.debug("HTTP status: %s", r.status_code)
       logger.debug("HTTP response headers: %r", r.headers)
       # Trace first 1024 bytes of content for debugging
       logger.debug("First 1024 bytes of response: %r", r.content[:1024])
       r.raise_for_status()
       return r.json()
   except Exception as e:
       logger.error("Failed to fetch metadata for app %s: %s", app_id, e)
       return None

# Main logic
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Sidequest APK monitor")
    parser.add_argument("--dry-run", action="store_true", help="Do not perform network requests; use test-data where available")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Set log level for both stdout and file logging (default: INFO)"
    )
    parser.add_argument(
        "--cron",
        action="store_true",
        help="Cron mode: log only to file, not stdout/stderr (for use in cronjobs)"
    )
    args = parser.parse_args(argv)

    # Set log level from CLI option
    log_level = getattr(logging, args.log_level.upper(), DEFAULT_LOG_LEVEL)
    set_log_level(log_level)

    # Handler logic for cron and non-cron modes
    # In --cron mode, remove all StreamHandlers (stdout/stderr) but keep FileHandler
    # In non-cron mode, both handlers are active
    if args.cron:
        removed_stream = False
        for handler in list(logger.handlers):
            # Only remove StreamHandlers, but never remove FileHandler
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                logger.removeHandler(handler)
                removed_stream = True
        logger.info("[Handler] Running in --cron mode: StreamHandlers removed, only FileHandler remains.")
        if not removed_stream:
            logger.info("[Handler] No StreamHandlers found to remove in --cron mode.")
    else:
        logger.info("[Handler] Running in non-cron mode: Both StreamHandler and FileHandler are active.")

    cfg = load_config()
    app_ids = cfg.get("app_ids", DEFAULT_APP_IDS)
    global APKS_DIR
    APKS_DIR = cfg.get("storage_dir", APKS_DIR) or APKS_DIR
    global INDEX_PATH
    INDEX_PATH = os.path.join(APKS_DIR, "index.json")
    os.makedirs(APKS_DIR, exist_ok=True)

    index = load_index()

    any_error = False

    # Initialize agent headers from AGENTS.md (or fallback) and log the User-Agent
    global AGENT_HEADERS
    AGENT_HEADERS = load_agent_headers()
    # Log the User-Agent being used so dry-run executions show the headers in logs
    ua = AGENT_HEADERS.get("User-Agent") or AGENT_HEADERS.get("user-agent")
    logger.info("Using Agent User-Agent: %s", ua)

    for app_id in app_ids:
        try:
            meta = fetch_metadata(int(app_id), dry_run=args.dry_run)
            if not meta:
                logger.info("No metadata for app %s; skipping", app_id)
                continue
            info = extract_apk_info(meta)
            if not info:
                logger.warning("Could not find APK info for app %s", app_id)
                continue
            app_name = info["app_name"]
            apk_url = info["apk_url"]
            version = info["version"]
            safe_name = slugify(app_name)

            # Compose filenames for APK and metadata
            # APK filename and metadata filename now both use the scheme: {app_name}-{app_id}-{version}.ext
            # This ensures only one metadata file is saved per version, matching the APK filename scheme.
            apk_filename = f"{safe_name}-{app_id}-{version}.apk"
            metadata_filename = f"{safe_name}-{app_id}-{version}.metadata.json"
            apk_path = os.path.join(APKS_DIR, apk_filename)
            metadata_path = os.path.join(APKS_DIR, metadata_filename)
            logger.debug(f"APK filename: {apk_filename}, Metadata filename: {metadata_filename}")

            
            archived_versions = index.get(str(app_id), [])
            # Check existence of APK and metadata independently
            apk_exists = os.path.exists(apk_path)
            metadata_exists = os.path.exists(metadata_path)

            # Check if this version is already indexed for this app (by version only)
            already_indexed = any(
                entry.get("version") == version
                for entry in archived_versions
            )

            # If both files exist and version is indexed, skip
            if already_indexed and apk_exists and metadata_exists:
                logger.info("Version %s for app %s already archived with metadata and APK; skipping", version, app_id)
                continue

            # Download APK only if missing
            if not apk_exists:
                try:
                    logger.info(f"APK missing for app {app_id} version {version}, downloading to {apk_path}")
                    download_file(apk_url, apk_path)
                except Exception as e:
                    logger.error("Failed to download APK for app %s: %s", app_id, e)
                    any_error = True
                    continue
            else:
                logger.info(f"APK already exists for app {app_id} version {version}, skipping download")

            # Save metadata only if missing
            import tempfile, shutil
            if not metadata_exists:
                try:
                    logger.info(f"Metadata missing for app {app_id} version {version}, saving to {metadata_path} (atomic write)")
                    def writer(f):
                        f.write(json.dumps(meta, indent=2, sort_keys=True).encode("utf-8"))
                    atomic_write_file(metadata_path, writer, mode="wb")
                    logger.info(f"Metadata saved atomically to {metadata_path}")
                except Exception as e:
                    logger.error(f"Failed to save metadata for app {app_id}: {e}")
                    any_error = True
                    continue
            else:
                logger.info(f"Metadata already exists for app {app_id} version {version}, skipping save")

            # Remove any existing entry for this version (ensure only one metadata file per version)
            archived_versions = [e for e in archived_versions if e.get("version") != version]

            # Add or update entry in index.json
            entry = {
                "version": version,
                # Store the APK filename scheme and new metadata filename in the index
                "apk_path": os.path.relpath(apk_path, PROJECT_ROOT),
                "metadata_path": os.path.relpath(metadata_path, PROJECT_ROOT),
                # Use timezone-aware UTC timestamp per Python 3.11+ deprecation of utcnow()
                # This ensures ISO8601 format with explicit UTC indication ("Z")
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source_url": apk_url,
            }
            archived_versions.append(entry)
            index[str(app_id)] = archived_versions
            save_index(index)
            # Optionally upload to S3 (only if APK was downloaded or exists)
            s3_key = os.path.basename(apk_path)
            try:
                maybe_upload_to_s3(apk_path, s3_key)
            except Exception:
                logger.exception("S3 upload attempt raised unexpected exception")

            logger.info(f"Archived APK and/or metadata for app {app_id} version {version}")
        except Exception as e:
            logger.exception("Unexpected error processing app %s: %s", app_id, e)
            any_error = True

    if any_error:
        logger.error("Completed with errors")
        return 1
    logger.info("Completed successfully")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        logger.exception("Fatal error: %s", e)
        sys.exit(1)

#
# Logging:
#   By default, log level is INFO. Use --log-level to set to DEBUG, WARNING, or ERROR.
#   Example: python sidequest_monitor.py --log-level DEBUG
#   This affects both stdout and file logging.
