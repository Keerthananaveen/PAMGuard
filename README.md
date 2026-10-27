# PAMGuard

PAMGuard is a local Python and SQLite lab for privileged access workflows and
security-event investigation. The account vault, password rotation, and
session-brokering behaviors are simulations. PAMGuard does not connect to
CyberArk, Splunk, Windows endpoints, or production infrastructure.

## Requirements

- Python 3.10 or later
- No third-party Python packages; the project uses the standard library

## Set up

Run commands from the project root:

```powershell
python --version
python -m app.main --init-db
python -m app.main --seed
python -m app.main --users
```

The seed command adds demo users, roles, safes, and platforms. Create a
privileged account and access policy through the interactive CLI before
requesting access:

```powershell
python -m app.main --create-account
python -m app.main --create-policy
```

Then use `--request-access`, `--approve`, `--checkout`, `--sessions`, and
`--checkin` to walk through a local access session. These commands prompt for
the required identifiers and approval details.

## Analyze sample logs

The files in `logs/` are demo inputs with private-range example IP addresses.
They are included to make the analyzers reproducible. Confirm that all account
and hostname labels are safe to publish before sharing the repository; do not
replace these examples with organization logs.

```powershell
python scripts/analyze_linux_logs.py
python scripts/analyze_windows_logs.py
```

The analyzers write reports under `reports/`. Windows incidents are also
correlated with local PAM accounts and sessions and ingested into the SQLite
event store. A session correlation requires matching account and source IP
and an event timestamp inside the PAM session window. Account/IP matches outside
the window are labeled `ACCOUNT_AND_IP_MATCH_OUTSIDE_SESSION`.

## Monitor, search, and export

```powershell
python -m app.main --watch-once
python -m app.main --watch-logs
python -m app.main --siem-search administrator
python -m app.main --siem-severity HIGH
python -m app.main --siem-export
```

The monitor polls only the configured Windows CSV input; stop continuous
monitoring with Ctrl+C. The local SQLite ingestion, search, and JSON export are
SIEM-style demonstrations, not a Splunk integration. Export output is written
to `reports/siem/events.json`.

## Simulated components and safeguards

- The Vault-like safe groups local privileged-account records. The database
  stores credential hashes, not retrievable plaintext passwords.
- CPM-like password rotation changes the simulated credential hash and records
  the rotation and audit events.
- PSM-like brokering creates time-limited local session records. It does not
  open or proxy a remote terminal session.
- Bounded response actions can write an investigation record, disable a
  simulated account, or expire a simulated session. Successful actions are
  recorded in the audit log; they do not change real operating-system accounts
  or sessions.

For example, to create an investigation record:

```powershell
python -m app.main --response investigate --incident-id WIN-0001
```

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Data and reports

The SQLite database (`database/pamguard.db`) and generated reports are local
runtime data and are excluded from version control. The schema, seed SQL, and
synthetic log inputs are source/demo material. Choose a license before making
the repository public; no license is included by default.
