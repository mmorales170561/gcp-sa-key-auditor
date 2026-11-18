#!/usr/bin/env python3
"""Audit GCP service-account keys older than a threshold (default 90 days).

Google recommends rotating user-managed service-account keys every 90 days.
A key that has sat in someone's downloads folder for a year is one leak away
from a breach — this tool finds those keys before an attacker does.

Usage:
    python sa_key_auditor.py --project my-project-123456
    python sa_key_auditor.py --project my-project-123456 --max-age-days 30
    python sa_key_auditor.py --project my-project-123456 --format json

Exit codes:
    0  No stale keys found.
    1  One or more stale keys found.
    2  Error (missing credentials, bad project, insufficient permissions).

Authentication: uses Application Default Credentials — run
`gcloud auth application-default login` first, or set
GOOGLE_APPLICATION_CREDENTIALS to a service-account key file.

Required IAM permissions on the project:
    iam.serviceAccounts.list, iam.serviceAccountKeys.list
(e.g. roles/iam.securityReviewer).
"""

import argparse
import json
import sys
from datetime import datetime, timezone

DEFAULT_MAX_AGE_DAYS = 90


# ---------------------------------------------------------------------------
# Pure helpers (no GCP calls — unit-testable without credentials)
# ---------------------------------------------------------------------------

def to_datetime(value):
    """Convert a GCP Timestamp (or datetime) to an aware UTC datetime.

    Returns None when the value is missing or unusable. Handles the three
    shapes the IAM client can surface: datetime, protobuf Timestamp, and
    anything exposing a ``seconds`` attribute.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if hasattr(value, "ToDatetime"):
        dt = value.ToDatetime()
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    if hasattr(value, "seconds"):
        seconds = int(value.seconds)
        if seconds <= 0:
            return None
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    return None


def key_age_days(valid_after, now=None):
    """Whole days since a key became valid. None when the date is unknown."""
    created = to_datetime(valid_after)
    if created is None:
        return None
    now = now or datetime.now(timezone.utc)
    age = (now - created).days
    return age if age >= 0 else 0


def is_stale(age_days, max_age_days):
    """True when a key's age exceeds the threshold (unknown age: not stale)."""
    return age_days is not None and age_days > max_age_days


def extract_key_id(key_name):
    """Short key id from a full resource name (last path segment)."""
    return key_name.rsplit("/", 1)[-1] if key_name else ""


def summarize(records, max_age_days):
    """Roll up per-key records into counts."""
    stale = [r for r in records if r["stale"]]
    unknown = [r for r in records if r["age_days"] is None]
    return {
        "max_age_days": max_age_days,
        "service_accounts_checked": len({r["service_account"] for r in records}),
        "keys_checked": len(records),
        "stale_keys": len(stale),
        "unknown_age_keys": len(unknown),
    }


# ---------------------------------------------------------------------------
# GCP audit
# ---------------------------------------------------------------------------

def _enum_name(value, default="UNKNOWN"):
    """Readable name for a proto enum value (or the raw value as a string)."""
    if value is None:
        return default
    name = getattr(value, "name", None)
    return name if name else str(value)


def audit_project(project_id, max_age_days, include_disabled=False,
                  include_system_managed=False, client=None, now=None):
    """List every service-account key in a project and flag the stale ones.

    Returns a list of record dicts, one per key found. ``client`` is an
    injectable IAM client (used by tests); when omitted, a real client is
    built from Application Default Credentials.
    """
    # Google libraries are imported lazily, and only when a real client is
    # needed, so --help, argument errors, and tests with an injected fake
    # client all work with no Google libraries installed.
    key_types = None
    if client is None:
        from google.cloud import iam_admin_v1

        client = iam_admin_v1.IAMClient()
        key_types = [iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
        if include_system_managed:
            key_types.append(
                iam_admin_v1.ListServiceAccountKeysRequest.KeyType.SYSTEM_MANAGED)

    parent = f"projects/{project_id}"
    records = []
    now = now or datetime.now(timezone.utc)
    for sa in client.list_service_accounts(parent=parent):
        response = client.list_service_account_keys(
            name=sa.name, key_types=key_types)
        for key in response.keys:
            if key.disabled and not include_disabled:
                continue
            age = key_age_days(key.valid_after_time, now)
            created = to_datetime(key.valid_after_time)
            records.append({
                "service_account": sa.email,
                "key_id": extract_key_id(key.name),
                "key_type": _enum_name(key.key_type),
                "key_algorithm": _enum_name(key.key_algorithm),
                "created": created.isoformat() if created else None,
                "age_days": age,
                "disabled": bool(key.disabled),
                "stale": is_stale(age, max_age_days),
            })
    records.sort(key=lambda r: (r["service_account"],
                                r["age_days"] is None,
                                -(r["age_days"] or 0)))
    return records


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def format_table(records, summary):
    """Human-readable table, stale keys first within each account."""
    stale = [r for r in records if r["stale"]]
    lines = []
    if not records:
        lines.append("No user-managed service-account keys found.")
    else:
        header = f"{'SERVICE ACCOUNT':<42} {'KEY ID':<42} {'CREATED':<12} {'AGE':>5}  STATUS"
        lines.append(header)
        lines.append("-" * len(header))
        for r in records:
            created = (r["created"] or "unknown")[:10]
            age = str(r["age_days"]) if r["age_days"] is not None else "?"
            status = "STALE" if r["stale"] else ("DISABLED" if r["disabled"] else "OK")
            lines.append(
                f"{r['service_account']:<42} {r['key_id']:<42} "
                f"{created:<12} {age:>5}  {status}")
    lines.append("")
    lines.append(
        f"Checked {summary['keys_checked']} key(s) across "
        f"{summary['service_accounts_checked']} service account(s); "
        f"{summary['stale_keys']} stale (older than "
        f"{summary['max_age_days']} days).")
    if summary["unknown_age_keys"]:
        lines.append(
            f"Note: {summary['unknown_age_keys']} key(s) have no usable "
            f"creation date and could not be aged.")
    if stale:
        lines.append(
            "Rotate stale keys: create a replacement, update the workload, "
            "then delete the old key.")
    return "\n".join(lines)


def format_json(records, summary):
    """Machine-readable output for CI / ticketing."""
    return json.dumps(
        {"summary": summary, "keys": records}, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Audit GCP service-account keys older than a threshold "
                    f"(default {DEFAULT_MAX_AGE_DAYS} days).")
    parser.add_argument("--project", required=True,
                        help="GCP project ID to audit (e.g. my-project-123456)")
    parser.add_argument("--max-age-days", type=int, default=DEFAULT_MAX_AGE_DAYS,
                        help="Flag keys older than this many days "
                             f"(default: {DEFAULT_MAX_AGE_DAYS})")
    parser.add_argument("--format", choices=["table", "json"], default="table",
                        help="Output format (default: table)")
    parser.add_argument("--include-disabled", action="store_true",
                        help="Include disabled keys (skipped by default)")
    parser.add_argument("--include-system-managed", action="store_true",
                        help="Include Google-managed keys (user-managed only "
                             "by default)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.max_age_days < 0:
        print("error: --max-age-days must be 0 or more",
              file=sys.stderr)
        return 2
    try:
        records = audit_project(
            args.project, args.max_age_days,
            include_disabled=args.include_disabled,
            include_system_managed=args.include_system_managed)
    except ImportError:
        print("error: google-cloud-iam is not installed.\n"
              "Install it with: pip install -r requirements.txt",
              file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 — mapped to friendly errors below
        print(f"error: {friendly_error(exc)}", file=sys.stderr)
        return 2

    summary = summarize(records, args.max_age_days)
    if args.format == "json":
        print(format_json(records, summary))
    else:
        print(format_table(records, summary))
    return 1 if summary["stale_keys"] else 0


def friendly_error(exc):
    """Translate common GCP failures into plain, actionable messages."""
    exc_type = type(exc).__name__
    message = str(exc)
    if exc_type == "DefaultCredentialsError" or "default credentials" in message.lower():
        return ("no Google Cloud credentials found. Run "
                "'gcloud auth application-default login' or set "
                "GOOGLE_APPLICATION_CREDENTIALS to a service-account key file.")
    if exc_type == "NotFound" or "not found" in message.lower():
        return ("project not found or not visible to these credentials — "
                "check the project ID and that the account has access.")
    if exc_type in ("PermissionDenied", "Forbidden"):
        return ("permission denied — the credentials need "
                "iam.serviceAccounts.list and iam.serviceAccountKeys.list "
                "on this project (e.g. roles/iam.securityReviewer).")
    if exc_type == "Unauthenticated":
        return ("credentials were rejected — re-authenticate with "
                "'gcloud auth application-default login'.")
    return f"{exc_type}: {message}" if message else exc_type


if __name__ == "__main__":
    sys.exit(main())
