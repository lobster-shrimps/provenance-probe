# Pilot quickstart: fleet rollup in three steps

*The copy-pasteable turnkey run. For the why, see [PILOT-BRIEF.md](PILOT-BRIEF.md);
for a rendered result, see [sample-report.txt](sample-report.txt).*

Everything here uses the shipped `provenance-probe` (v0.40.1+). Install:

```sh
pip install llm-provenance-probe        # CLI is `provenance-probe`
provenance-probe fleet-scan --print rollup-quickstart   # this runbook, from the CLI
```

Nothing here makes a network call during aggregation, writes to a scanned host, or
sends your prompts anywhere. The per-machine scan is read-only host forensics; the
rollup only *reads* the files you gathered.

## Step 1 — deliver a per-machine scan (pick your channel)

Each scheduled scan writes a small local SQLite DB carrying the machine's id + scan
time. A clean machine (zero findings) still writes a row, so it is **still counted**.
The tool prints the unit for your delivery channel — pipe it into place:

```sh
# macOS (launchd), Linux (systemd/cron), Windows (schtasks)
provenance-probe fleet-scan --print launchd   > com.provenance-probe.fleet-scan.plist
provenance-probe fleet-scan --print systemd   # emits .service + .timer
provenance-probe fleet-scan --print cron
provenance-probe fleet-scan --print schtasks

# MDM / EDR fleets
provenance-probe fleet-scan --print intune      # PowerShell deploy script
provenance-probe fleet-scan --print tanium      # Tanium recipe
provenance-probe fleet-scan --print osquery-atc # osquery ATC config (reads the DB)
```

Each generated unit runs, in effect:

```sh
provenance-probe fleet-scan --allowlist allow.txt \
    --sqlite ~/.provenance-probe/fleet/fleet.db
```

Start your allowlist from the template (list the AI hosts you sanction):

```sh
provenance-probe fleet-scan --print allowlist-template > allow.txt
```

Set an explicit inventory id with `--machine-id <asset-tag>` if the hostname isn't
the name you track. Use host identifiers (asset tags / hostnames) as machine ids —
never usernames or paths.

## Step 2 — gather one file per machine into a directory

Pull each machine's `fleet.db` back via your MDM/EDR, a SIEM export, or `scp`, and
drop them in one directory. The filename stem is used as the machine id when a file
doesn't already carry one:

```
fleet-rollup/
  eng-laptop-01.db
  eng-laptop-02.db
  research-laptop-08.db
  vdi-07.json        # a `fleet-scan --json --out report.json` report works too
```

Only top-level `*.db` / `*.json` files are read (non-recursive). Unreadable files
are skipped and counted, never fatal. Alternatively point `--rollup` at a single
collector-merged DB whose rows carry a `machine` column (e.g. a SIEM export).

## Step 3 — roll it up

```sh
# console posture report + gate (exit 3 on any exposure)
provenance-probe fleet-scan --rollup fleet-rollup/ --fail-on any

# machine-by-finding CSV for a spreadsheet / SIEM import
provenance-probe fleet-scan --rollup fleet-rollup/ --format csv > fleet.csv

# structured JSON for a dashboard / automation
provenance-probe fleet-scan --rollup fleet-rollup/ --format json
```

`--fail-on {prc|drift|any|none}` decides when the command gates:

- `prc` — at least one PRC-origin finding.
- `drift` — at least one off-allowlist finding (attributed or unattributed).
- `any` — `prc` OR `drift` (`--fail-on-exposure` is an alias for this).
- `none` — never gate (default; report only).

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Clean — a successful report (including an empty 0-machine one), or exposure present but not matched by `--fail-on`. |
| `2`  | **Error** — missing/unreadable path, corrupt DB, or a directory whose only files are unusable. Error outranks exposure. |
| `3`  | **Exposure matched** the `--fail-on` criterion. The full report still prints; only the exit code changes. |

Every run emits a greppable trailing line: `EXPOSURE: prc=<n> drift=<n>
(fail-on=<mode> -> FAIL|ok)`. Distinguish *"found shadow AI"* (`3`) from *"the scan
broke"* (`2`) — never treat them the same in an alert rule.

## Cron (nightly alert)

```sh
provenance-probe fleet-scan --rollup /siem/fleet-merged.db --fail-on any \
  || mail -s "shadow-AI exposure in fleet" ciso@example.com < /dev/null
```

## CI gate (block the pipeline on fleet drift)

```sh
# exits 3 on exposure -> the step fails and blocks the pipeline
provenance-probe fleet-scan --rollup fleet-rollup/ --fail-on any
```

## Offline DNS / SNI log (one command)

Log-only mode. It does not scan the machine it runs on, and it does not open
a socket. Destinations are classified on the `imported-log` tier.
Corpus-attributed hosts print first. Names the corpus does not know are a
count on the headline, not one finding each.

```sh
provenance-probe fleet-scan --allowlist allow.txt --dns-log ssl.log --fail-on prc
```

Exit 3 when the trailing line says `fail-on=prc -> FAIL`. A gateway, proxy,
or via column with no destination stays unresolved and is not that failure.
The same read is on the live probe page from `provenance-probe serve`.

## See it now (synthetic)

Regenerate the exact [sample-report.txt](sample-report.txt) from this repo:

```sh
python3 docs/pilot/make-sample-fixture.py /tmp/pilot-fixture
provenance-probe fleet-scan --rollup /tmp/pilot-fixture --fail-on any
```

The full rollup runbook, terminology, redaction rules, and back-compat notes live
in [../fleet-rollup.md](../fleet-rollup.md).
