# GCP Service-Account Key Auditor

[![CI](https://github.com/mmorales170561/gcp-sa-key-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/mmorales170561/gcp-sa-key-auditor/actions/workflows/ci.yml)

Finds Google Cloud service-account keys older than a threshold (default 90 days)
across a whole project — the stale keys most likely to be sitting in someone's
downloads folder, one leak away from a breach.

Google recommends rotating user-managed service-account keys every 90 days.
This tool lists every user-managed key in a project, ages it, and flags the
ones past the threshold. Exit code 1 when stale keys exist, so it drops
straight into CI or a scheduled check.

## Install

```bash
git clone https://github.com/mmorales170561/gcp-sa-key-auditor.git
cd gcp-sa-key-auditor
pip install -r requirements.txt
```

Requires Python 3.9+.

## Authenticate

The tool uses Application Default Credentials:

```bash
gcloud auth application-default login
```

or point `GOOGLE_APPLICATION_CREDENTIALS` at a service-account key file.

The credentials need these permissions on the audited project:

- `iam.serviceAccounts.list`
- `iam.serviceAccountKeys.list`

`roles/iam.securityReviewer` covers both.

## Usage

```bash
# Flag keys older than 90 days (the default)
python sa_key_auditor.py --project my-project-123456

# Stricter threshold
python sa_key_auditor.py --project my-project-123456 --max-age-days 30

# Machine-readable output for CI / ticketing
python sa_key_auditor.py --project my-project-123456 --format json

# Also report disabled keys and Google-managed keys
python sa_key_auditor.py --project my-project-123456 --include-disabled --include-system-managed
```

## Example output

```
$ python sa_key_auditor.py --project my-project-123456
SERVICE ACCOUNT                            KEY ID                                     CREATED        AGE  STATUS
----------------------------------------------------------------------------------------------------------------
backup@my-project-123456.iam.gserviceaccount.com c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4   2025-11-30     353  STALE
deployer@my-project-123456.iam.gserviceaccount.com a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2   2026-02-14     277  STALE
deployer@my-project-123456.iam.gserviceaccount.com b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3   2026-10-02      47  OK

Checked 3 key(s) across 2 service account(s); 2 stale (older than 90 days).
Rotate stale keys: create a replacement, update the workload, then delete the old key.
```

Exit codes: `0` = no stale keys, `1` = stale keys found, `2` = error
(missing credentials, bad project, insufficient permissions).

## What it does not do

- It never downloads, prints, or modifies a private key — it reads key
  metadata (creation date, type, disabled state) only.
- It does not rotate or delete keys. Rotation is a deliberate act: create a
  replacement, update the workload, then delete the old key.

## License

MIT — see [LICENSE](LICENSE).
