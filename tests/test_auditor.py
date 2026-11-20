"""Tests for sa_key_auditor.py.

Everything here runs against a fake IAM client — no Google credentials,
no network, no real project. The audit path is exercised end to end
through audit_project() with the injectable ``client`` argument.
"""

import json
from datetime import datetime, timezone

import pytest

import sa_key_auditor as auditor


NOW = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fakes standing in for google.cloud.iam_admin_v1 responses
# ---------------------------------------------------------------------------

class EnumLike:
    """Mimics a proto enum value: _enum_name() reads .name."""
    def __init__(self, name):
        self.name = name


class SecondsTimestamp:
    """Mimics a protobuf Timestamp surfaced as a .seconds attribute."""
    def __init__(self, seconds):
        self.seconds = seconds


class ProtoTimestamp:
    """Mimics a protobuf Timestamp with a ToDatetime() method."""
    def __init__(self, dt):
        self._dt = dt

    def ToDatetime(self):
        return self._dt


class FakeKey:
    def __init__(self, key_id, valid_after_time, disabled=False,
                 key_type="USER_MANAGED", key_algorithm="KEY_ALG_RSA_2048"):
        self.name = f"projects/p/serviceAccounts/a@x.iam.gserviceaccount.com/keys/{key_id}"
        self.valid_after_time = valid_after_time
        self.disabled = disabled
        self.key_type = EnumLike(key_type)
        self.key_algorithm = EnumLike(key_algorithm)


class FakeKeysResponse:
    def __init__(self, keys):
        self.keys = keys


class FakeServiceAccount:
    def __init__(self, email):
        self.name = f"projects/p/serviceAccounts/{email}"
        self.email = email


class FakeClient:
    """Fake IAM client.

    ``pages`` is a list of lists of FakeServiceAccount — list_service_accounts
    yields them one page at a time, so the audit must drain the whole
    iterable (pagination smoke check), not just read the first page.
    ``keys_by_email`` maps an SA email to its FakeKey list.
    """
    def __init__(self, pages, keys_by_email):
        self._pages = pages
        self._keys_by_email = keys_by_email
        self.listed_key_types = []

    def list_service_accounts(self, parent=None):
        for page in self._pages:
            yield from page

    def list_service_account_keys(self, name=None, key_types=None):
        self.listed_key_types.append(key_types)
        email = name.rsplit("/", 1)[-1]
        return FakeKeysResponse(self._keys_by_email.get(email, []))


def days_ago(n, now=NOW):
    from datetime import timedelta
    return now - timedelta(days=n)


# ---------------------------------------------------------------------------
# to_datetime / key_age_days / is_stale / extract_key_id
# ---------------------------------------------------------------------------

def test_to_datetime_none_is_none():
    assert auditor.to_datetime(None) is None


def test_to_datetime_naive_datetime_gets_utc():
    dt = auditor.to_datetime(datetime(2026, 1, 1, 0, 0, 0))
    assert dt == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_to_datetime_aware_datetime_passes_through():
    dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert auditor.to_datetime(dt) is dt


def test_to_datetime_protobuf_to_datetime():
    dt = auditor.to_datetime(ProtoTimestamp(datetime(2026, 3, 1, tzinfo=timezone.utc)))
    assert dt == datetime(2026, 3, 1, tzinfo=timezone.utc)


def test_to_datetime_seconds_attribute():
    dt = auditor.to_datetime(SecondsTimestamp(1760956800))  # 2025-10-20 10:40 UTC
    assert dt == datetime(2025, 10, 20, 10, 40, tzinfo=timezone.utc)


def test_to_datetime_zero_seconds_is_none():
    assert auditor.to_datetime(SecondsTimestamp(0)) is None


def test_to_datetime_garbage_is_none():
    assert auditor.to_datetime("2026-01-01") is None
    assert auditor.to_datetime(12345) is None


def test_key_age_days_exact():
    assert auditor.key_age_days(datetime(2026, 1, 1, tzinfo=timezone.utc), NOW) == 323


def test_key_age_days_unknown_is_none():
    assert auditor.key_age_days(None, NOW) is None


def test_key_age_days_future_key_is_zero_not_negative():
    assert auditor.key_age_days(datetime(2026, 12, 1, tzinfo=timezone.utc), NOW) == 0


def test_is_stale_boundary():
    assert auditor.is_stale(90, 90) is False   # exactly at threshold: OK
    assert auditor.is_stale(91, 90) is True
    assert auditor.is_stale(0, 0) is False     # --max-age-days 0: fresh key OK
    assert auditor.is_stale(1, 0) is True      # --max-age-days 0: 1-day key stale
    assert auditor.is_stale(None, 90) is False  # unknown age: never stale


def test_extract_key_id():
    assert auditor.extract_key_id("projects/p/serviceAccounts/a@x/keys/abc123") == "abc123"
    assert auditor.extract_key_id("") == ""
    assert auditor.extract_key_id(None) == ""


# ---------------------------------------------------------------------------
# summarize
# ---------------------------------------------------------------------------

def test_summarize_counts():
    records = [
        {"service_account": "a@x", "age_days": 100, "stale": True},
        {"service_account": "a@x", "age_days": 10, "stale": False},
        {"service_account": "b@x", "age_days": None, "stale": False},
    ]
    summary = auditor.summarize(records, 90)
    assert summary == {
        "max_age_days": 90,
        "service_accounts_checked": 2,
        "keys_checked": 3,
        "stale_keys": 1,
        "unknown_age_keys": 1,
    }


def test_summarize_empty_project():
    assert auditor.summarize([], 90) == {
        "max_age_days": 90,
        "service_accounts_checked": 0,
        "keys_checked": 0,
        "stale_keys": 0,
        "unknown_age_keys": 0,
    }


# ---------------------------------------------------------------------------
# audit_project with the fake client
# ---------------------------------------------------------------------------

def _client_with_one_sa():
    sa = FakeServiceAccount("deployer@proj.iam.gserviceaccount.com")
    keys = [
        FakeKey("stale1", days_ago(200)),
        FakeKey("fresh1", days_ago(10)),
        FakeKey("nodate1", None),               # no valid_after_time at all
        FakeKey("disabled1", days_ago(400), disabled=True),
    ]
    return FakeClient([[sa]], {sa.email: keys})


def test_audit_flags_stale_and_ages_unknown():
    records = auditor.audit_project("proj", 90, client=_client_with_one_sa(), now=NOW)
    by_id = {r["key_id"]: r for r in records}
    assert by_id["stale1"]["stale"] is True
    assert by_id["stale1"]["age_days"] == 200
    assert by_id["fresh1"]["stale"] is False
    assert by_id["nodate1"]["age_days"] is None
    assert by_id["nodate1"]["created"] is None
    assert by_id["nodate1"]["stale"] is False  # unknown age is never stale


def test_audit_skips_disabled_by_default():
    records = auditor.audit_project("proj", 90, client=_client_with_one_sa(), now=NOW)
    assert "disabled1" not in {r["key_id"] for r in records}


def test_audit_includes_disabled_when_asked():
    records = auditor.audit_project(
        "proj", 90, include_disabled=True, client=_client_with_one_sa(), now=NOW)
    by_id = {r["key_id"]: r for r in records}
    assert by_id["disabled1"]["disabled"] is True
    assert by_id["disabled1"]["stale"] is True


def test_audit_sorts_oldest_first_within_account_unknown_last():
    records = auditor.audit_project("proj", 90, client=_client_with_one_sa(), now=NOW)
    assert [r["key_id"] for r in records] == ["stale1", "fresh1", "nodate1"]


def test_audit_empty_project_returns_no_records():
    records = auditor.audit_project("proj", 90, client=FakeClient([[]], {}), now=NOW)
    assert records == []


def test_audit_drains_all_pages():
    """Pagination smoke check: SAs spread across two pages are all audited."""
    page1 = [FakeServiceAccount("a@proj.iam.gserviceaccount.com")]
    page2 = [FakeServiceAccount("b@proj.iam.gserviceaccount.com")]
    keys = {
        "a@proj.iam.gserviceaccount.com": [FakeKey("ka", days_ago(100))],
        "b@proj.iam.gserviceaccount.com": [FakeKey("kb", days_ago(5))],
    }
    records = auditor.audit_project("proj", 90, client=FakeClient([page1, page2], keys), now=NOW)
    assert {r["key_id"] for r in records} == {"ka", "kb"}
    assert {r["service_account"] for r in records} == set(keys)


def test_audit_max_age_days_zero():
    sa = FakeServiceAccount("a@proj.iam.gserviceaccount.com")
    keys = [FakeKey("today", NOW), FakeKey("yesterday", days_ago(1))]
    records = auditor.audit_project(
        "proj", 0, client=FakeClient([[sa]], {sa.email: keys}), now=NOW)
    by_id = {r["key_id"]: r for r in records}
    assert by_id["today"]["stale"] is False
    assert by_id["yesterday"]["stale"] is True


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def test_format_table_marks_statuses_and_notes_unknown():
    records = auditor.audit_project("proj", 90, client=_client_with_one_sa(), now=NOW)
    summary = auditor.summarize(records, 90)
    table = auditor.format_table(records, summary)
    assert "STALE" in table
    assert "OK" in table
    assert "could not be aged" in table
    assert "Checked 3 key(s) across 1 service account(s); 1 stale" in table
    assert "Rotate stale keys" in table


def test_format_table_empty_project():
    table = auditor.format_table([], auditor.summarize([], 90))
    assert "No user-managed service-account keys found." in table
    assert "Checked 0 key(s)" in table


def test_format_json_is_parseable_and_keys_sorted():
    records = auditor.audit_project("proj", 90, client=_client_with_one_sa(), now=NOW)
    summary = auditor.summarize(records, 90)
    raw = auditor.format_json(records, summary)
    parsed = json.loads(raw)
    assert parsed["summary"]["stale_keys"] == 1
    assert len(parsed["keys"]) == 3
    # sort_keys=True: "keys" sorts before "summary" at the top level.
    assert raw.index('"keys"') < raw.index('"summary"')


# ---------------------------------------------------------------------------
# CLI validation and friendly errors
# ---------------------------------------------------------------------------

def test_main_rejects_negative_max_age_days(capsys):
    assert auditor.main(["--project", "proj", "--max-age-days", "-1"]) == 2
    assert "must be 0 or more" in capsys.readouterr().err


def test_main_requires_project():
    with pytest.raises(SystemExit) as exc:
        auditor.main([])
    assert exc.value.code == 2


def test_main_help_exits_zero():
    with pytest.raises(SystemExit) as exc:
        auditor.main(["--help"])
    assert exc.value.code == 0


def _exc_with_name(name, message):
    return type(name, (Exception,), {})(message)


def test_friendly_error_missing_credentials():
    exc = _exc_with_name("DefaultCredentialsError", "could not load default credentials")
    assert "gcloud auth application-default login" in auditor.friendly_error(exc)


def test_friendly_error_not_found():
    exc = _exc_with_name("NotFound", "404 project not found")
    assert "project not found" in auditor.friendly_error(exc)


def test_friendly_error_permission_denied():
    exc = _exc_with_name("PermissionDenied", "403 forbidden")
    assert "iam.serviceAccounts.list" in auditor.friendly_error(exc)


def test_friendly_error_unauthenticated():
    exc = _exc_with_name("Unauthenticated", "401 bad credentials")
    assert "re-authenticate" in auditor.friendly_error(exc)


def test_friendly_error_generic_keeps_type_and_message():
    assert auditor.friendly_error(ValueError("boom")) == "ValueError: boom"
