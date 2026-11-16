#!/usr/bin/env python3
"""Standalone Veracode Container / IaC / Secrets findings tracker with mitigations.

Follows findings over time and records approved mitigations. Veracode access and file output are implemented
in this repository under tracker/; it has no dependency on Veracode-IaC-Extract.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import os
import re
import sys
import tempfile
from collections import Counter
from typing import Any, Callable, Iterable, Optional

try:
    from tracker import veracode as vx
    from tracker import output as out
except ModuleNotFoundError:  # direct execution from tracker/ (GitHub Actions and local CLI)
    import veracode as vx
    import output as out

SEVERITY_RANK = vx.SEVERITY_RANK
SEVERITY_LABEL = vx.SEVERITY_LABEL
read_csv_file = out.read_csv_file
finding_key = vx.finding_key
write_output = out.write_output
OutputLocked = out.OutputLocked
ExtractError = vx.VeracodeError
BASE_COLUMNS = vx.REPORT_COLUMNS
order_columns = lambda seen, base, keep_empty, _unused=None: vx.report_columns(seen, base, keep_empty)
save_output = out.save_output
xlsx_too_big = out.xlsx_too_big
map_credential_env = vx.map_credential_env


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# Mitigation types
# ---------------------------------------------------------------------------
# Mitigations for these findings are not available on the Veracode Platform. The tracker keeps
# approved mitigations in mitigations.yml (see the Mitigation rules section below).

MITIGATION_TYPES = {
    "false-positive": "Not a real issue (Potential False Positive in Static Analysis).",
    "by-design": "Deliberate and approved, or the design already handles it (Mitigate by Design).",
    "network-environment": "A network control handles it: WAF, security group, private network.",
    "os-environment": "The OS or runtime handles it: hardened host, read-only file system, no shell.",
    "accept-risk": "The business accepts the risk for a limited time. Needs an expiry date.",
}
NOT_IN_EXPORT = "Not in export"  # status of carried-over rows in old tracking files (migration only)
EXPIRY_WARN_DAYS = 30
_RE_MKEY = re.compile(r"^mk-[0-9a-f]{12}$")


def parse_expiry(text: str) -> tuple[Optional[dt.date], str]:
    """YYYY-MM-DD, or a date a spreadsheet rewrote (31/12/2027, 12/31/2027) when it is unambiguous."""
    t = text.strip()
    m = re.fullmatch(r"(\d{4})[-/.](\d{1,2})[-/.](\d{1,2})(?:[ T].*)?", t)
    if m:
        y, mo, d = map(int, m.groups())
    else:
        m = re.fullmatch(r"(\d{1,2})[-/.](\d{1,2})[-/.](\d{4})(?: .*)?", t)
        if not m:
            return None, f"'{t}' is not a date. Use YYYY-MM-DD"
        a, b, y = map(int, m.groups())
        if a > 12 and b <= 12:
            d, mo = a, b
        elif b > 12 and a <= 12:
            mo, d = a, b
        elif a == b:
            d = mo = a
        else:
            return None, f"'{t}' could be day/month or month/day. Use YYYY-MM-DD"
    try:
        return dt.date(y, mo, d), ""
    except ValueError:
        return None, f"'{t}' is not a valid date"


# ---------------------------------------------------------------------------
# Findings tracker (--track DIR)
# ---------------------------------------------------------------------------
# DIR/findings.csv is the baseline: one row per open finding. DIR/fixed.csv logs the fixed ones.
# A finding is identified by its Asset ID plus its Finding Key (line-independent, see
# tracker.veracode.finding_key), so a moved line or a new image tag does not make it a new finding.

NEW, OPEN, REOPENED, ASSET_MISSING = "New", "Open", "Reopened", "Asset Missing"
ASSET_MISSING_DAYS = 30
TRACK_MITIGATION_COLUMNS = ["Mitigation Status", "Mitigation Type", "Mitigation Reason", "Mitigation Approved By",
                            "Mitigation Expires", "Mitigation Ref"]
TRACK_COLUMNS = ["Status", "Severity", "Finding Type", "Finding ID", "Title", "Asset Name", "Location",
                 "Fixed Versions", "First Seen", "Last Seen", "Days Open", *TRACK_MITIGATION_COLUMNS,
                 "Veracode Link", "Asset ID", "Finding Key", "Mitigation ID", "File Path", "Scan Type", "Scan ID",
                 "Scan Date", "Detected On", "Reopened On", "Asset Missing Since"]
FIXED_COLUMNS = ["Fixed On", "Fixed Reason", "Days Open", "Severity", "Finding Type", "Finding ID", "Title",
                 "Asset Name", "Location", "First Seen", "Last Seen", "Mitigation Status", "Mitigation ID",
                 "Veracode Link", "Asset ID", "Finding Key", "Fixed By Scan"]
# Finding-level filters are refused with --track: findings filtered out would look fixed.
EXPORT_ONLY_FLAGS = ("--severity", "--min-severity", "--type", "--finding-type", "--id", "--cve", "--finding-id",
                     "--library", "--file", "--rule", "--category", "--fixable", "--cvss", "--min-cvss", "--search",
                     "--grep", "--where", "--all-scans", "--track-history", "--scan-id", "--list-scans", "--columns",
                     "--compact", "--summary-csv", "--match-apps")


def asset_key(asset_id: Any, name: Any) -> str:
    aid = str(asset_id or "").strip()
    return aid if aid else "name:" + str(name or "").strip().lower()


def finding_ident(row: dict[str, Any]) -> tuple[str, str]:
    return asset_key(row.get("Asset ID"), row.get("Asset Name")), str(row.get("Finding Key") or "")


def severity_rank(label: Any) -> int:
    return SEVERITY_RANK.get(str(label or "").strip().lower(), 0)


def day_of(value: Any) -> Optional[dt.date]:
    try:
        return dt.date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def tracker_row(row: dict[str, Any]) -> dict[str, Any]:
    """The tracker's compact view of a finding row."""
    out = {c: row.get(c, "") for c in ("Severity", "Finding Type", "Finding ID", "Title", "Asset Name",
                                       "Fixed Versions", "Veracode Link", "Asset ID", "Finding Key", "File Path",
                                       "Scan Type", "Scan ID", "Scan Date")}
    out["Location"] = row.get("Location") or ""
    if str(row.get("Finding Type") or "").lower() == "vulnerability" and row.get("Library"):
        out["Location"] = row["Library"]
    out["_legacy"] = finding_key(row, legacy=True)
    return out


def sort_track_rows(rows: Iterable[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (-severity_rank(r.get("Severity")), str(r.get("Asset Name") or "").lower(),
                                       str(r.get("Finding Key") or ""), str(r.get("Asset ID") or "")))


def fixed_entry(old: dict[str, Any], fixed_on: str, reason: str, scan_id: str = "") -> dict[str, Any]:
    row = {c: old.get(c, "") for c in FIXED_COLUMNS}
    first, fixed = day_of(old.get("First Seen")), day_of(fixed_on)
    row.update({"Fixed On": fixed_on, "Fixed Reason": reason, "Fixed By Scan": scan_id,
                "Days Open": (fixed - first).days if first and fixed else ""})
    return row


def update_lifecycle(baseline: list[dict], fixed_log: list[dict], current: list[dict],
                     scanned: dict[tuple[str, str], tuple[str, str]], known_assets: set[str], today: dt.date,
                     seed: Optional[dict[str, str]] = None) -> tuple[list[dict], list[dict], Counter]:
    """Moves the baseline forward with this run's findings. Returns (open rows, newly fixed rows, counts).

    scanned: (asset key, scan type) -> (scan date, scan ID) for every scan read in full in this run.
    known_assets: asset keys of every scan in the tenant (to tell a deleted asset from a filtered one).
    seed: Finding Key -> First Seen, from a migrated tracking file."""
    today_s = today.isoformat()
    prev = {finding_ident(r): r for r in baseline}
    was_fixed = {finding_ident(r): r for r in fixed_log}
    counts: Counter = Counter()
    out: dict[tuple[str, str], dict] = {}
    for cur in sorted(current, key=lambda r: -severity_rank(r.get("Severity"))):
        ident = finding_ident(cur)
        if ident in out:
            continue
        legacy = (ident[0], str(cur.get("_legacy") or ""))
        old = prev.pop(ident, None)
        if old is None and legacy[1] and legacy != ident:
            old = prev.pop(legacy, None)  # baseline written before the code_hash fix
        row = dict(cur)
        seen = str(cur.get("Scan Date") or "")[:10] or today_s
        row["Last Seen"] = seen
        row["Asset Missing Since"] = ""
        if old is not None:
            for c in ("First Seen", "Detected On", "Reopened On"):
                row[c] = old.get(c, "")
            fresh = old.get("Status") in (NEW, REOPENED) and old.get("Detected On") == today_s
            row["Status"] = old["Status"] if fresh else OPEN
        elif ident in was_fixed or legacy in was_fixed:
            gone = was_fixed.get(ident) or was_fixed[legacy]
            row.update({"Status": REOPENED, "First Seen": gone.get("First Seen") or seen,
                        "Reopened On": today_s, "Detected On": today_s})
            counts["reopened"] += 1
        elif seed and (ident[1] in seed or legacy[1] in seed):
            row.update({"Status": OPEN, "First Seen": seed.get(ident[1]) or seed.get(legacy[1]) or seen,
                        "Detected On": ""})
            counts["seeded"] += 1
        else:
            row.update({"Status": NEW, "First Seen": seen, "Detected On": today_s})
            counts["new"] += 1
        out[ident] = row

    fixed_rows: list[dict] = []
    for ident, old in prev.items():
        akey = ident[0]
        stype = str(old.get("Scan Type") or "").lower()
        if stype:
            newer = scanned.get((akey, stype))
        else:  # no scan type recorded: only when every scan read for the asset is newer
            dates = [v for (a, _), v in scanned.items() if a == akey]
            newer = min(dates) if dates else None
        if newer and newer[0] > str(old.get("Scan Date") or ""):
            fixed_rows.append(fixed_entry(old, newer[0][:10], "fixed", newer[1]))
            counts["fixed"] += 1
            continue
        row = dict(old)
        if akey not in known_assets:
            since = old.get("Asset Missing Since") or today_s
            since_day = day_of(since) or today
            if (today - since_day).days >= ASSET_MISSING_DAYS:
                fixed_rows.append(fixed_entry(old, today_s, "asset-removed"))
                counts["removed"] += 1
                continue
            row["Status"], row["Asset Missing Since"] = ASSET_MISSING, since
        elif row.get("Status") == ASSET_MISSING:
            row["Status"], row["Asset Missing Since"] = OPEN, ""
        elif row.get("Status") in (NEW, REOPENED) and row.get("Detected On") != today_s:
            row["Status"] = OPEN
        out[ident] = row
    return sort_track_rows(out.values()), fixed_rows, counts


def refresh_days_open(rows: list[dict], today: dt.date) -> None:
    for row in rows:
        first = day_of(row.get("First Seen"))
        row["Days Open"] = (today - first).days if first else ""


def track_paths(folder: str) -> dict[str, str]:
    return {"findings": os.path.join(folder, "findings.csv"), "fixed": os.path.join(folder, "fixed.csv"),
            "run": os.path.join(folder, "last-run.json")}


def load_track_files(paths: dict[str, str]) -> tuple[list[dict], list[dict], Optional[str]]:
    """(baseline, fixed log, error). Missing files are empty: the first run creates them."""
    out = []
    for name in ("findings", "fixed"):
        path = paths[name]
        rows: list[dict] = []
        if os.path.exists(path):
            try:
                rows = read_csv_file(path)
            except (OSError, csv.Error) as exc:
                return [], [], f"cannot read {path}: {exc}"
            if rows and "Finding Key" not in rows[0]:
                return [], [], f"{path} has no Finding Key column; it was not written by --track"
        out.append(rows)
    return out[0], out[1], None


def read_json_file(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def atomic_write_text(path: str, text: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def github_output(**values: Any) -> None:
    """Step outputs for GitHub Actions (only our own computed values, never user text)."""
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            for k, v in values.items():
                fh.write(f"{k}={v}\n")


def step_summary(text: str) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def merge_fixed(fixed_log: list[dict], new_rows: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for row in fixed_log + new_rows:
        key = (str(row.get("Asset ID") or ""), str(row.get("Finding Key") or ""), str(row.get("Fixed On") or ""))
        if key not in seen:
            seen.add(key)
            out.append(row)
    return out


def track_totals(rows: list[dict]) -> Counter:
    c: Counter = Counter()
    for r in rows:
        ms = r.get("Mitigation Status") or ""
        if ms in ("Mitigated", "Expiring"):
            c["mitigated"] += 1
        else:
            c[str(r.get("Severity") or "Unknown")] += 1
        if ms == "Expiring":
            c["expiring"] += 1
        if ms == "Expired":
            c["expired"] += 1
        if r.get("Status") in (NEW, REOPENED):
            c["new today"] += 1
    return c


def write_track_outputs(paths: dict[str, str], rows: list[dict], fixed_all: list[dict]) -> Optional[str]:
    """Writes findings.csv and fixed.csv (each atomically). Returns an error message or None."""
    try:
        write_output(paths["findings"], "csv", TRACK_COLUMNS, rows, raw_cells=False)
        write_output(paths["fixed"], "csv", FIXED_COLUMNS, fixed_all, raw_cells=False)
    except OutputLocked as exc:
        os.remove(exc.path)
        return f"{exc.target} is locked by another program"
    except OSError as exc:
        return f"cannot write the tracking files: {exc}"
    return None


def finish_track(args: argparse.Namespace, paths: dict[str, str], rows: list[dict], fixed_log: list[dict],
                 fixed_new: list[dict], counts: Counter, run_info: dict, now: dt.datetime,
                 rules: Optional["Rules"] = None, notes: Optional[list[str]] = None) -> int:
    today = now.date()
    for row in rows:
        if rules:
            rules.apply(row)
        else:
            clear_mitigation(row)
    refresh_days_open(rows, today)
    fixed_all = merge_fixed(fixed_log, fixed_new)
    err = write_track_outputs(paths, rows, fixed_all)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    run_info = dict(run_info, updated=now.strftime("%Y-%m-%dT%H:%M:%SZ"))
    atomic_write_text(paths["run"], json.dumps(run_info, indent=2, sort_keys=True) + "\n")
    dashboard = args.dashboard or os.path.join(os.path.dirname(os.path.abspath(args.track)), "FINDINGS.md")
    repo_url = resolve_repo_url(args.repo_url)
    if args.repo_url and not repo_url:
        print("  WARNING: --repo-url must look like https://github.com/<org>/<repo>; Mitigate links left out")
    rel = os.path.relpath(os.path.abspath(args.track), os.path.dirname(os.path.abspath(dashboard)))
    atomic_write_text(dashboard, render_dashboard(rows, fixed_all, run_info, now, repo_url, rel))
    t = track_totals(rows)
    sev = ", ".join(f"{SEVERITY_LABEL[r]} {t[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0)
                    if t[SEVERITY_LABEL[r]])
    lines = [f"New {counts['new']}, reopened {counts['reopened']}, fixed {counts['fixed']}"
             + (f", asset removed {counts['removed']}" if counts["removed"] else ""),
             f"Open (not mitigated): {sev or 'none'}",
             f"Mitigated {t['mitigated']}, expiring {t['expiring']}, expired {t['expired']}"]
    print("\n" + "\n".join("  " + ln for ln in lines))
    for msg in (notes or [])[:10]:
        print(f"  NOTE: {msg}")
    print(f"\nWrote {len(rows)} open finding(s) to {paths['findings']}")
    step_summary("### Veracode findings tracker\n\n" + "\n".join(f"- {ln}" for ln in lines))
    github_output(new=counts["new"], reopened=counts["reopened"], fixed=counts["fixed"] + counts["removed"],
                  open=len(rows))
    return 0


def clear_mitigation(row: dict[str, Any]) -> None:
    for c in TRACK_MITIGATION_COLUMNS + ["Mitigation ID"]:
        row[c] = ""


# FINDINGS.md: the dashboard GitHub shows next to the code. Every value is escaped with md_safe.
DASHBOARD_LIMIT = 500_000
DASHBOARD_ROWS = 300
DASHBOARD_DETAIL_ROWS = 25
MITIGATIONS_DOC = "docs/MITIGATIONS.md"
_RE_REPO_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:\d+)?/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def resolve_repo_url(explicit: Optional[str]) -> str:
    """https://github.com/<org>/<repo> from --repo-url or GitHub Actions; '' when unknown (no Mitigate links)."""
    url = explicit or ""
    if not url and os.environ.get("GITHUB_REPOSITORY"):
        url = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/") + "/" + \
            os.environ["GITHUB_REPOSITORY"]
    url = url.strip().rstrip("/")
    return url if _RE_REPO_URL.match(url) else ""


def mitigate_url(repo_url: str, row: dict[str, Any]) -> str:
    """Link to the mitigation request issue form, pre-filled with this finding."""
    from urllib.parse import quote, urlencode
    if not repo_url:
        return ""
    fid, asset = str(row.get("Finding ID") or ""), str(row.get("Asset Name") or "")
    params = {"template": "mitigation.yml", "title": f"Mitigate: {fid} in {asset}"[:200],
              "finding_key": row.get("Finding Key") or "", "finding_id": fid[:200], "asset": asset[:300]}
    return f"{repo_url}/issues/new?{urlencode(params, quote_via=quote)}"


def dashboard_table(columns: list[str], rows: list[dict], cell: Callable[[dict, str], str], budget: int,
                    more_note: str) -> tuple[list[str], int]:
    """Markdown table lines, at most DASHBOARD_ROWS rows and `budget` characters."""
    if not rows:
        return ["None."], 5
    lines = ["| " + " | ".join(columns) + " |", "|" + " --- |" * len(columns)]
    used = sum(len(x) + 1 for x in lines)
    shown = 0
    for r in rows[:DASHBOARD_ROWS]:
        line = "| " + " | ".join(cell(r, c) for c in columns) + " |"
        if used + len(line) + 1 > budget:
            break
        lines.append(line)
        used += len(line) + 1
        shown += 1
    if shown < len(rows):
        note = f"\n_Showing {shown} of {len(rows)}. {more_note}_"
        lines.append(note)
        used += len(note) + 1
    return lines, used


def dashboard_asset_summary(rows: Iterable[dict]) -> list[dict[str, Any]]:
    """One compact row per tracked asset for a large set of findings."""
    grouped: dict[str, tuple[str, str, Counter]] = {}
    for row in rows:
        name = str(row.get("Asset Name") or "Unknown asset")
        asset_id = str(row.get("Asset ID") or "")
        identity = asset_key(asset_id, name)
        if identity not in grouped:
            grouped[identity] = (name, asset_id, Counter())
        counts = grouped[identity][2]
        counts["Findings"] += 1
        counts["New"] += 1 if row.get("Status") == NEW else 0
        counts["Reopened"] += 1 if row.get("Status") == REOPENED else 0
        severity = str(row.get("Severity") or "").title()
        if severity in ("Critical", "High", "Medium", "Low"):
            counts[severity] += 1
    name_counts = Counter(name.lower() for name, _, _ in grouped.values())
    summary = []
    for name, asset_id, counts in grouped.values():
        label = name if name_counts[name.lower()] == 1 or not asset_id else f"{name} ({asset_id})"
        summary.append({"Asset Name": label, "Findings": counts["Findings"], "New": counts["New"],
                        "Reopened": counts["Reopened"], "Critical": counts["Critical"],
                        "High": counts["High"], "Medium": counts["Medium"], "Low": counts["Low"]})
    return sorted(summary, key=lambda r: (-r["Critical"], -r["High"], -r["Medium"], -r["Low"],
                                           r["Asset Name"].lower()))


def render_dashboard(rows: list[dict], fixed_all: list[dict], run_info: dict, now: dt.datetime,
                     repo_url: str, track_rel: str = "tracking") -> str:
    track_rel = track_rel.replace("\\", "/").strip("/")
    track_rel = track_rel if re.fullmatch(r"[A-Za-z0-9_./-]+", track_rel) else "tracking"
    # docs/ sits next to the tracking folder (the repository root in the template)
    docs_rel = "/".join([p for p in track_rel.split("/")[:-1]] + [MITIGATIONS_DOC])
    today = now.date()
    t = track_totals(rows)
    fixed_on = [(day_of(r.get("Fixed On")), r) for r in fixed_all]
    recent = sorted(((d, r) for d, r in fixed_on if d and 0 <= (today - d).days <= 30),
                    key=lambda dr: (dr[0], severity_rank(dr[1].get("Severity"))), reverse=True)
    days = sorted(int(r["Days Open"]) for r in rows if str(r.get("Days Open", "")).lstrip("-").isdigit())
    median = "" if not days else (days[len(days) // 2] if len(days) % 2 else
                                  (days[len(days) // 2 - 1] + days[len(days) // 2]) / 2)
    if isinstance(median, float) and median.is_integer():
        median = int(median)
    assets = run_info.get("assets", len({finding_ident(r)[0] for r in rows}))
    last = "never (offline only)"
    if run_info.get("run"):
        last = (f"{str(run_info['run']).replace('T', ' ').rstrip('Z')} UTC, +{run_info.get('new', 0)} new, "
                f"{run_info.get('reopened', 0)} reopened, -{int(run_info.get('fixed', 0)) + int(run_info.get('removed', 0))}"
                " fixed")
    out = ["# Veracode findings", "",
           f"> Updated: {now.strftime('%Y-%m-%d %H:%M')} UTC · Assets: {md_safe(assets)} · Last run: {md_safe(last)}",
           "> Full data: "
           f"[{track_rel}/findings.csv]({track_rel}/findings.csv) · "
           f"[{track_rel}/fixed.csv]({track_rel}/fixed.csv)",
           f"> Mitigations: use a Mitigate link below. Rules: [{MITIGATIONS_DOC}]({docs_rel}).",
           "", "## Risk snapshot", "",
           "| Critical | High | Medium | Low | Mitigated | Expiring (≤30d) | Expired | New today | Fixed (7d) "
           "| Fixed (30d) | Median days open |",
           "|" + " --- |" * 11,
           f"| {t['Critical']} | {t['High']} | {t['Medium']} | {t['Low']} | {t['mitigated']} | {t['expiring']} | "
           f"{t['expired']} | {t['new today']} | {sum(1 for d, _ in recent if (today - d).days <= 7)} | "
           f"{len(recent)} | {median} |", ""]
    if not repo_url:
        out += ["_Mitigate links are off: run in GitHub Actions or pass --repo-url._", ""]

    def cell(r: dict, c: str) -> str:
        if c == "Title":
            return md_safe(r.get("Title"), 80)
        if c == "Mitigation":
            st = r.get("Mitigation Status") or ""
            if not st:
                return ""
            ref = r.get("Mitigation Ref") or ""
            mid = md_link(md_safe(r.get("Mitigation ID")), ref) or md_safe(r.get("Mitigation ID"))
            return f"{md_safe(st)} ({md_safe(r.get('Mitigation Type'))}, {mid})"
        if c == "Links":
            links = [md_link("Veracode", r.get("Veracode Link"))]
            if r.get("Mitigation Status") != "Mitigated":
                links.append(md_link("Mitigate", mitigate_url(repo_url, r)))
            return " ".join(x for x in links if x)
        if c == "Asset":
            return md_safe(r.get("Asset Name"), 120)
        return md_safe(r.get(c), 160)

    open_rows = [r for r in rows if r.get("Mitigation Status") not in ("Mitigated", "Expiring")]
    new_rows = [r for r in rows if r.get("Status") in (NEW, REOPENED)]
    if len(new_rows) > DASHBOARD_DETAIL_ROWS:
        new_section = ("New findings by asset", ["Asset", "New", "Reopened", "Critical", "High", "Medium", "Low"],
                       dashboard_asset_summary(new_rows), len(new_rows))
    else:
        new_section = ("New since last run", ["Status", "Severity", "Finding ID", "Title", "Asset", "Location",
                                                "Days Open", "Mitigation", "Links"], new_rows, len(new_rows))
    if len(open_rows) > DASHBOARD_DETAIL_ROWS:
        open_section = ("Open findings by asset", ["Asset", "Findings", "Critical", "High", "Medium", "Low"],
                        dashboard_asset_summary(open_rows), len(open_rows))
    else:
        open_section = ("Open findings", ["Severity", "Finding ID", "Title", "Asset", "Location", "Days Open",
                                            "Mitigation", "Links"], open_rows, len(open_rows))
    sections = [
        new_section,
        ("Expiring or expired mitigations", ["Severity", "Finding ID", "Title", "Asset", "Mitigation Expires",
                                             "Mitigation", "Links"],
         [r for r in rows if r.get("Mitigation Status") in ("Expiring", "Expired")],
         sum(1 for r in rows if r.get("Mitigation Status") in ("Expiring", "Expired"))),
        open_section,
        ("Fixed in the last 30 days", ["Fixed On", "Severity", "Finding ID", "Title", "Asset", "Location",
                                       "Days Open", "Fixed Reason"], [r for _, r in recent], len(recent)),
    ]
    used = sum(len(x) + 1 for x in out)
    for i, (title, cols, srows, total) in enumerate(sections):
        budget = (DASHBOARD_LIMIT - used - 2000) // (len(sections) - i)
        out += [f"## {title} ({total})", ""]
        used += len(title) + 20
        if title.endswith("by asset"):
            out += ["_Grouped by asset because this section has more than 25 findings._", ""]
            used += 70
        lines, n = dashboard_table(cols, srows, cell, budget,
                                   f"Full list in {track_rel}/" + ("fixed.csv" if i == 3 else "findings.csv") + ".")
        out += lines + [""]
        used += n
    return "\n".join(out)


def run_track(args: argparse.Namespace, now: dt.datetime, minter: Optional[Callable[[], str]]) -> int:
    paths = track_paths(args.track)
    baseline, fixed_log, err = load_track_files(paths)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    rules, notes = None, []
    if args.mitigations:
        rules, notes, rc = load_rules_for_run(args.mitigations, now.date())
        if rules is None:
            return rc
    if args.offline:  # refresh the derived columns only; no Veracode access
        return finish_track(args, paths, sort_track_rows(baseline), fixed_log, [], Counter(),
                            read_json_file(paths["run"]), now, rules, notes)
    try:
        scans, found, failures = vx.collect_latest(
            args.base_url, args.link_base, asset=args.asset, exclude_asset=args.exclude_asset,
            scan_type=args.scan_type, asset_type=args.asset_type, scanned_by=args.scanned_by, policy=args.policy,
            since=args.since, until=args.until, workers=args.max_workers, rps=args.rps,
            max_attempts=args.max_attempts, timeout=args.timeout, ca_cert=args.ca_cert, minter=minter, now=now)
    except ExtractError as exc:
        print(f"error: {exc}" + ("\nNothing was changed." if exc.exit_code == 1 else ""), file=sys.stderr)
        return exc.exit_code
    current = [tracker_row(fr) for fr in found]
    # -o: every column except the raw code, which can hold the secret itself
    full = [{k: v for k, v in fr.items() if k != "Code Lines"} for fr in found] if args.output else []
    scanned = {(asset_key(r.get("Asset ID"), r.get("Asset Name")), str(r.get("Scan Type") or "").lower()):
               (str(r.get("Scan Date") or ""), str(r.get("Scan ID") or "")) for r in scans if r.get("_read")}
    if failures:
        print(f"\nINCOMPLETE: {len(failures)} failure(s):", file=sys.stderr)
        for scope, detail in failures[:20]:
            print(f"  - {scope}: {detail[:160]}", file=sys.stderr)
        print("Nothing was changed: findings are never marked fixed from partial data.", file=sys.stderr)
        return 1
    known = {asset_key(r.get("Asset ID"), r.get("Asset Name")) for r in scans} | \
        {asset_key("", r.get("Asset Name")) for r in scans}
    seed: Optional[dict[str, str]] = None
    rules_path = args.mitigations or "mitigations.yml"
    old_file = args.migrate or os.path.join(os.path.dirname(os.path.abspath(args.track)), OLD_TRACKING_FILE)
    if args.migrate or (os.path.exists(old_file) and not os.path.exists(paths["findings"])):
        seed, err = migrate_old_file(old_file, rules_path, now.date())
        if err:
            print(f"error: {err}\nNothing was changed.", file=sys.stderr)
            return 2
    if (args.mitigations and os.path.exists(rules_path) and remap_legacy_rules(rules_path, current)) \
            or seed is not None:
        rules, more, rc = load_rules_for_run(rules_path, now.date())
        if rules is None:
            return rc
        notes = more
    rows, fixed_new, counts = update_lifecycle(baseline, fixed_log, current, scanned, known, now.date(), seed)
    run_info = {"run": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "assets": len({a for a, _ in scanned}),
                **{k: counts[k] for k in ("new", "reopened", "fixed", "removed")}}
    rc = finish_track(args, paths, rows, fixed_log, fixed_new, counts, run_info, now, rules, notes)
    if rc == 0 and args.output:
        rc = write_track_report(args, rows, full)
    return rc


def write_track_report(args: argparse.Namespace, rows: list[dict], full: list[dict]) -> int:
    """-o with --track: every current finding with all its columns plus Status and Mitigation (no Code Lines)."""
    by_ident = {finding_ident(r): r for r in rows}
    seen: Counter = Counter()
    for fr in full:
        t = by_ident.get(finding_ident(fr), {})
        for c in ["Status", "First Seen", "Last Seen"] + EXPORT_MITIGATION_COLUMNS:
            fr[c] = t.get(c, "")
        seen.update(k for k, v in fr.items() if v not in ("", None))
    fmt = args.format or {".json": "json", ".jsonl": "jsonl", ".ndjson": "jsonl", ".xlsx": "xlsx"}.get(
        os.path.splitext(args.output)[1].lower(), "csv")
    too_big = xlsx_too_big(fmt, len(full))
    if too_big:
        print(f"error: {too_big}", file=sys.stderr)
        return 2
    base = ["Status", "Mitigation Status"] + [c for c in BASE_COLUMNS if c not in ("Code Lines", "Seen In Scans")] \
        + EXPORT_MITIGATION_COLUMNS[1:]
    columns = order_columns(seen, base, args.keep_empty_columns)
    full.sort(key=lambda r: (-int(r.get("Severity Rank") or 0), str(r.get("Asset Name") or "").lower()))
    n, path, locked = save_output(args.output, fmt, columns, full, args.no_csv_safe,
                                     xlsx_style=MITIGATION_XLSX_STYLE)
    print(f"Wrote {n} finding(s) to {path}")
    return 1 if locked else 0


# ---------------------------------------------------------------------------
# Mitigation rules (mitigations.yml)
# ---------------------------------------------------------------------------
# Approved mitigations live in mitigations.yml: a list of rules recorded by the approval workflow or
# added through a pull request. A rule matches findings by Finding ID / CVE / Finding Key, optionally
# narrowed to assets and files. Mitigations affect the tracker only, not the Veracode Platform.

RULE_FIELDS = ("id", "finding", "asset", "file", "type", "reason", "approved_by", "approved_on", "expires", "ref",
               "requested_by", "notes", "allow_broad")
RULE_REQUIRED = ("id", "finding", "type", "reason", "approved_by")
RULE_PATTERNS = ("finding", "asset", "file")
RULE_TEXT_MAX = 2000
RULE_PATTERN_MAX = 300
EXPORT_MITIGATION_COLUMNS = TRACK_MITIGATION_COLUMNS + ["Mitigation ID"]
MITIGATION_XLSX_STYLE = {"wrap": {"Mitigation Reason"}, "dates": {"Mitigation Expires"},
                         "fills": {"Mitigation Status": {"Mitigated": "C6EFCE", "Expiring": "FFEB9C",
                                                         "Expired": "F8CBAD"}}}
_RE_RULE_ID = re.compile(r"^M-(\d{4,})$")
_RE_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_RE_UNPRINTABLE = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029\ufeff\ufffe\uffff\ud800-\udfff]")
_GLOBS: dict[str, Any] = {}


def require_yaml() -> Any:
    try:
        import yaml
    except ImportError:
        raise SystemExit("mitigations.yml needs PyYAML: pip install PyYAML")
    return yaml


def glob_match(pattern: str, value: Any) -> bool:
    """Whole-value match, case-insensitive. * is any text, ? one character; nothing else is special."""
    rx = _GLOBS.get(pattern)
    if rx is None:
        rx = _GLOBS[pattern] = re.compile("".join(
            ".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern.strip()), re.I | re.S)
    return bool(rx.fullmatch(str(value or "").strip()))


def is_broad(pattern: str) -> bool:
    return not pattern.replace("*", "").replace("?", "").strip()


def rule_date(value: Any) -> tuple[Optional[dt.date], str]:
    if isinstance(value, dt.datetime):
        return value.date(), ""
    if isinstance(value, dt.date):
        return value, ""
    text = str(value).strip()
    if not _RE_ISO_DATE.match(text):
        return None, f"'{text[:40]}' is not a date. Use YYYY-MM-DD"
    try:
        return dt.date.fromisoformat(text), ""
    except ValueError:
        return None, f"'{text}' is not a valid date"


def validate_rules(data: Any, today: dt.date) -> tuple[list[dict], list[str], list[str]]:
    """Normalises the parsed YAML. Returns (entries, errors, warnings). Every mapping that has an id is
    returned (with _valid False when it has problems) so a diff can still show it."""
    if data is None:
        data = []
    if not isinstance(data, list):
        return [], ["the file must be a list of entries, each starting with '- id:'"], []
    entries: list[dict] = []
    errors: list[str] = []
    warnings: list[str] = []
    ids: dict[str, int] = {}
    for n, item in enumerate(data, 1):
        if not isinstance(item, dict):
            errors.append(f"entry {n}: must be a mapping (id: ..., finding: ..., ...)")
            continue
        raw_id = item.get("id")
        where = f"entry {n}" + (f" ({raw_id})" if isinstance(raw_id, str) and raw_id.strip() else "")
        problems: list[str] = []
        for key in item:
            if key not in RULE_FIELDS:
                problems.append(f"unknown key '{str(key)[:40]}'. Allowed: {', '.join(RULE_FIELDS)}")
        e: dict[str, Any] = {"_n": n, "_where": where}
        for f in RULE_FIELDS:
            v = item.get(f)
            if f == "allow_broad":
                if v is not None and not isinstance(v, bool):
                    problems.append("allow_broad must be true or false")
                e[f] = v is True
                continue
            if v is None:
                e[f] = ""
            elif isinstance(v, (dt.date, dt.datetime)):
                e[f] = (v.date() if isinstance(v, dt.datetime) else v).isoformat()
            elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
                e[f] = str(v).strip()
            else:
                problems.append(f"{f} must be text")
                e[f] = ""
            limit = RULE_PATTERN_MAX if f in RULE_PATTERNS or f in ("id", "approved_by", "requested_by", "ref") \
                else RULE_TEXT_MAX
            if len(e[f]) > limit:
                problems.append(f"{f} is longer than {limit} characters")
            if f in RULE_PATTERNS and ("\n" in e[f] or "\r" in e[f]):
                problems.append(f"{f} must be one line")
        for f in RULE_REQUIRED:
            if not e[f]:
                problems.append(f"{f} is required")
        if e["id"]:
            if not _RE_RULE_ID.match(e["id"]):
                problems.append(f"id '{e['id'][:40]}' must look like M-0001")
            elif e["id"] in ids:
                problems.append(f"duplicate id {e['id']} (also entry {ids[e['id']]})")
            else:
                ids[e["id"]] = n
        if e["type"] and e["type"] not in MITIGATION_TYPES:
            problems.append(f"type '{e['type'][:40]}' must be one of {', '.join(MITIGATION_TYPES)}")
        e["_expires"] = None
        for f in ("expires", "approved_on"):
            if e[f]:
                day, err = rule_date(item.get(f))
                if err:
                    problems.append(f"{f}: {err}")
                else:
                    e[f] = day.isoformat()
                    if f == "expires":
                        e["_expires"] = day
        if e["type"] == "accept-risk" and not e["expires"]:
            problems.append("accept-risk needs expires (YYYY-MM-DD)")
        if e["finding"] and is_broad(e["finding"]) and all(not e[f] or is_broad(e[f]) for f in ("asset", "file")) \
                and not e["allow_broad"]:
            problems.append("finding matches everything and there is no asset or file scope. Narrow it, or add "
                            "allow_broad: true if this is intended")
        if e["ref"].lower().startswith("http") and not e["ref"].startswith("https://"):
            problems.append("ref must be an https:// link or plain text")
        e["_valid"] = not problems
        errors += [f"{where}: {p}" for p in problems]
        if e["_expires"] and e["_expires"] < today and not problems:
            warnings.append(f"{where}: expired on {e['_expires']}; the findings count as open again. "
                            "Renew it or remove the entry")
        entries.append(e)
    return entries, errors, warnings


def load_rules(path: str, today: dt.date) -> tuple[list[dict], list[str], list[str]]:
    """Reads and validates mitigations.yml. A missing file is an empty list."""
    if not os.path.exists(path):
        return [], [], []
    yaml = require_yaml()
    try:
        with open(path, encoding="utf-8-sig") as fh:
            data = yaml.safe_load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        return [], [f"cannot read {path}: {exc}"], []
    except yaml.YAMLError as exc:
        return [], [f"{path} is not valid YAML: {str(exc)[:300]}"], []
    return validate_rules(data, today)


class Rules:
    def __init__(self, entries: list[dict], today: dt.date) -> None:
        self.entries = [e for e in entries if e.get("_valid")]
        self.today = today

    def status(self, e: dict) -> str:
        exp = e.get("_expires")
        if exp and exp < self.today:
            return "Expired"
        if exp and (exp - self.today).days <= EXPIRY_WARN_DAYS:
            return "Expiring"
        return "Mitigated"

    def match(self, row: dict[str, Any]) -> Optional[dict]:
        """The first rule that matches and has not expired; else the first expired one."""
        expired = None
        for e in self.entries:
            if rule_matches(e, row):
                if self.status(e) != "Expired":
                    return e
                expired = expired or e
        return expired

    def apply(self, row: dict[str, Any]) -> str:
        """Fills the Mitigation columns. Returns the Mitigation Status ('' when not mitigated)."""
        e = self.match(row)
        if e is None:
            clear_mitigation(row)
            return ""
        st = self.status(e)
        row.update({"Mitigation Status": st, "Mitigation Type": e["type"], "Mitigation Reason": e["reason"],
                    "Mitigation Approved By": e["approved_by"], "Mitigation Expires": e["expires"],
                    "Mitigation Ref": e["ref"] if e["ref"].startswith("https://") else e["id"],
                    "Mitigation ID": e["id"]})
        return st


def rule_matches(e: dict, row: dict[str, Any]) -> bool:
    if not any(glob_match(e["finding"], row.get(c)) for c in ("Finding ID", "Finding Key", "CVE ID", "_legacy")
               if row.get(c)):
        return False
    if e["asset"] and not any(glob_match(e["asset"], row.get(c)) for c in ("Asset Name", "Asset ID")):
        return False
    if e["file"] and not any(glob_match(e["file"], row.get(c)) for c in ("File Path", "Location") if row.get(c)):
        return False
    return True


def load_rules_for_run(path: str, today: dt.date, must_exist: bool = False) -> tuple[Optional[Rules], list[str], int]:
    """(rules, warnings, exit code). rules is None when the run must stop."""
    if must_exist and not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return None, [], 2
    try:
        entries, errors, warnings = load_rules(path, today)
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return None, [], 2
    if errors:
        for msg in errors:
            print(f"error: {path} {msg}", file=sys.stderr)
        print(f"Nothing was changed. Fix {path} (see --check-mitigations) and run again.", file=sys.stderr)
        return None, [], 2
    return Rules(entries, today), warnings, 0


# Markdown for pull request comments, issue comments and FINDINGS.md. Everything that came from a
# scan, a file or a person goes through md_safe: no HTML, no comments, no mentions, no table breaks.
REPORT_LIMIT = 60_000
_RE_MD_SPECIAL = re.compile(r"([\\`*_\[\]~|])")


def md_safe(value: Any, limit: Optional[int] = None) -> str:
    s = "" if value is None else str(value)
    s = _RE_UNPRINTABLE.sub(" ", s.replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("\t", " "))
    while "<!--" in s or "-->" in s:
        s = s.replace("<!--", "").replace("-->", "")
    if limit and len(s) > limit:
        s = s[:limit - 1].rstrip() + "…"
    s = html.escape(s, quote=False)
    s = _RE_MD_SPECIAL.sub(r"\\\1", s)
    return s.replace("@", "&#64;")


def md_link(text: str, url: Any) -> str:
    """[text](url) for https links only; the URL is percent-encoded so it cannot break the Markdown."""
    u = str(url or "").strip()
    if not u.startswith("https://"):
        return ""
    from urllib.parse import quote
    return f"[{text}]({quote(u, safe=':/?#=&%~.-_+,;!$*')})"


def severity_counts(rows: Iterable[dict]) -> str:
    c = Counter(str(r.get("Severity") or "Unknown") for r in rows)
    total = sum(c.values())
    if not total:
        return "0"
    parts = ", ".join(f"{SEVERITY_LABEL[r]} {c[SEVERITY_LABEL[r]]}" for r in (5, 4, 3, 2, 1, 0)
                      if c[SEVERITY_LABEL[r]])
    return f"{total} ({parts})"


DIFF_FIELDS = ("finding", "asset", "file", "type", "reason", "approved_by", "expires")
OTHER_FIELDS = ("notes", "ref", "requested_by", "approved_on", "allow_broad")


def rule_changes(base: list[dict], new: list[dict]) -> list[tuple[str, Optional[dict], Optional[dict]]]:
    def key(e: dict) -> str:
        return e["id"] or f"(entry {e['_n']})"
    b = {key(e): e for e in base}
    n = {key(e): e for e in new}
    out: list[tuple[str, Optional[dict], Optional[dict]]] = []
    for k, cur in n.items():
        old = b.get(k)
        if old is None:
            out.append(("Added", None, cur))
        elif any(old[f] != cur[f] for f in DIFF_FIELDS + OTHER_FIELDS):
            out.append(("Changed", old, cur))
    out += [("Removed", old, None) for k, old in b.items() if k not in n]
    return out


def rule_report(path: str, entries: list[dict], errors: list[str], warnings: list[str], base: list[dict],
                baseline: Optional[list[dict]]) -> str:
    """Markdown for the pull request comment, capped at REPORT_LIMIT characters."""
    valid = sum(1 for e in entries if e["_valid"])
    head = ["## Veracode mitigations", "",
            f"**{md_safe(path)}: {len(errors)} problem(s). Fix them before merging.**" if errors
            else f"**{md_safe(path)}: {valid} rule(s), all valid.**", "",
            "### Changes compared with the base branch", ""]
    changes = rule_changes(base, entries)
    cols = ["Change", "ID", "Finding", "Asset", "File", "Type", "Reason", "Approved By", "Expires", "Other"]
    if baseline is not None:
        cols.append("Open findings matched")
    rows: list[str] = []
    for change, old, cur in changes:
        e = cur or old
        assert e is not None

        def cell(f: str) -> str:
            if change == "Changed" and old and cur and old[f] != cur[f]:
                return f"~~{md_safe(old[f], 200) or '(empty)'}~~ {md_safe(cur[f], 200) or '(empty)'}"
            return md_safe(e[f], 200)
        other = []
        for f in OTHER_FIELDS:
            if change == "Changed" and old and cur and old[f] != cur[f]:
                other.append(f"{f}: ~~{md_safe(old[f], 80) or '(empty)'}~~ {md_safe(cur[f], 80) or '(empty)'}")
            elif change == "Added" and e[f] not in ("", False):
                other.append(f"{f}: {md_safe(e[f], 80)}")
        cells = [change, md_safe(e["id"] or "(no id)", 40)] + [cell(f) for f in DIFF_FIELDS] + ["; ".join(other)]
        if baseline is not None:
            cells.append(severity_counts(r for r in baseline if rule_matches(e, r)) if cur and cur["finding"]
                         else "")
        rows.append("| " + " | ".join(cells) + " |")
    tail: list[str] = []
    if errors:
        tail += ["", "### Problems", ""] + [f"- {md_safe(m, 500)}" for m in errors[:200]]
        if len(errors) > 200:
            tail.append(f"- ...and {len(errors) - 200} more")
    if warnings:
        tail += ["", "### Warnings", ""] + [f"- {md_safe(m, 500)}" for m in warnings[:100]]
    tail_text = "\n".join(tail)[:REPORT_LIMIT // 3]
    budget = REPORT_LIMIT - len(tail_text) - 500
    body: list[str] = []
    if rows:
        body = ["| " + " | ".join(cols) + " |", "|" + " --- |" * len(cols)]
        used = sum(len(x) + 1 for x in head + body)
        for i, r in enumerate(rows):
            if used + len(r) + 1 > budget:
                body.append(f"\n_{len(rows) - i} more change(s) not shown. Run --check-mitigations locally "
                            "for the full list._")
                break
            body.append(r)
            used += len(r) + 1
    else:
        body = ["No mitigation changes."]
    return ("\n".join(head + body) + "\n" + tail_text + "\n")[:REPORT_LIMIT]


def check_mitigations(path: str, against: Optional[str] = None, track_dir: Optional[str] = None) -> int:
    """--check-mitigations: validate mitigations.yml and list its rules. No Veracode access.
    With --against BASE: Markdown of the rules added, changed or removed, for a pull request comment.
    With --track DIR: also how many open findings in DIR/findings.csv each added or changed rule matches."""
    if not os.path.exists(path):
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    today = utcnow().date()
    try:
        entries, errors, warnings = load_rules(path, today)
    except SystemExit as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if against is not None:
        base: list[dict] = []
        if os.path.exists(against) and os.path.getsize(against):
            base, _, _ = load_rules(against, today)
        baseline = None
        if track_dir:
            fpath = track_paths(track_dir)["findings"]
            baseline = read_csv_file(fpath) if os.path.exists(fpath) else []
        print(rule_report(path, entries, errors, warnings, base, baseline))
        return 2 if errors else 0
    for e in entries:
        if not e["_valid"]:
            continue
        scope = "".join(f", {f} {e[f]}" for f in ("asset", "file") if e[f])
        extra = f", expires {e['expires']}" if e["expires"] else ""
        print(f"OK       {e['id']} {e['finding']}{scope}: {e['type']}, approved by {e['approved_by']}{extra}. "
              f"{e['reason']}")
    for msg in errors:
        print(f"ERROR    {msg}")
    for msg in warnings:
        print(f"WARNING  {msg}")
    if errors:
        print(f"\n{path}: {len(errors)} problem(s). Fix them before merging.")
        return 2
    print(f"{path}: {sum(1 for e in entries if e['_valid'])} rule(s), all valid.")
    return 0


# ---------------------------------------------------------------------------
# Approving a mitigation request issue (--approve-issue)
# ---------------------------------------------------------------------------
# The approval workflow passes the issue (as JSON in a file, never through the shell) when an
# approver adds the `approved` label. The issue body is the Markdown GitHub renders from the issue
# form: "### <field label>" followed by the value.

ISSUE_FORM_FIELDS = {"Finding Key": "finding_key", "Finding ID": "finding_id", "Asset": "asset", "File": "file",
                     "Type": "type", "Reason": "reason", "Expires": "expires", "Notes / ticket": "notes"}
NO_RESPONSE = "_No response_"
NOT_APPROVER = 3  # exit code: the person who added the label is not in MITIGATION_APPROVERS
MITIGATIONS_HEADER = (f"# Approved mitigations for the Veracode findings tracker. See {MITIGATIONS_DOC}.\n"
                      "# The approval workflow appends entries here; you can also add or remove them in a pull "
                      "request.\n")
_RE_LOGIN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}(\[bot\])?$")
_RE_ISSUE_URL = re.compile(r"^https://[^\s/]+/[^\s/]+/[^\s/]+/issues/\d+$")


def parse_issue_form(body: Any) -> tuple[dict[str, str], list[str]]:
    """Issue-form Markdown -> {field id: value}. A field heading that appears twice is an error (someone
    typed '### Type' inside another answer)."""
    text = str(body or "").replace("\x0d\n", "\n").replace("\x0d", "\n")
    values: dict[str, str] = {}
    errors: list[str] = []
    current: Optional[str] = None
    buf: list[str] = []

    def flush() -> None:
        if current is not None and current not in values:
            value = "\n".join(buf).strip()
            values[current] = "" if value == NO_RESPONSE else value

    for line in text.split("\n"):
        hit = re.fullmatch(r"###[ \t]+(.+?)[ \t]*", line)
        if hit and hit.group(1) in ISSUE_FORM_FIELDS:
            flush()
            current, buf = ISSUE_FORM_FIELDS[hit.group(1)], []
            if current in values:
                errors.append(f"the section '{hit.group(1)}' appears more than once")
            continue
        if current is not None:
            buf.append(line)
    flush()
    return values, errors


def parse_approvers(text: Optional[str]) -> set[str]:
    return {x.lstrip("@").lower() for x in re.split(r"[\s,]+", text or "") if x.strip().lstrip("@")}


def next_rule_id(entries: list[dict]) -> str:
    nums = [int(mt.group(1)) for e in entries if (mt := _RE_RULE_ID.match(str(e.get("id") or "")))]
    return f"M-{max(nums, default=0) + 1:04d}"


def yaml_value(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, dt.date):
        return v.isoformat()
    return json.dumps(_RE_UNPRINTABLE.sub(" ", str(v)), ensure_ascii=False)  # a JSON string is valid YAML


def render_rule(entry: dict[str, Any]) -> str:
    lines = [f"- id: {entry['id']}"]
    for k in RULE_FIELDS[1:]:
        v = entry.get(k)
        if v not in (None, "", False):
            lines.append(f"  {k}: {v if k == 'type' else yaml_value(v)}")
    return "\n".join(lines) + "\n"


def append_rules(path: str, new: list[dict[str, Any]], today: dt.date) -> Optional[str]:
    """Appends entries to mitigations.yml as text (comments and layout stay) and writes it atomically.
    Returns an error message, or None."""
    yaml = require_yaml()
    text = MITIGATIONS_HEADER
    if os.path.exists(path):
        with open(path, encoding="utf-8-sig") as fh:
            text = fh.read()
    try:
        current = yaml.safe_load(text) or []
    except yaml.YAMLError as exc:
        return f"{path} is not valid YAML: {str(exc)[:200]}"
    if not current:  # "[]" (the template's empty list) cannot be followed by block entries
        text = re.sub(r"(?m)^[ \t]*\[[ \t]*\][ \t]*(#.*)?$\n?", "", text)
    if text and not text.endswith("\n"):
        text += "\n"
    text += "".join(render_rule(e) for e in new)
    try:
        entries, errors, _ = validate_rules(yaml.safe_load(text), today)
    except yaml.YAMLError as exc:
        return f"{path} could not be extended ({str(exc)[:200]}). Rewrite it as a block list ('- id: ...')"
    tail = entries[-len(new):] if new else []
    if errors or len(tail) != len(new) or any(
            got[k] != str(want.get(k) or "") for got, want in zip(tail, new)
            for k in ("id", "finding", "asset", "file", "reason", "approved_by", "notes", "ref")):
        return f"{path} could not be extended safely: " + "; ".join(errors[:5])
    atomic_write_text(path, text)
    return None


def approve_issue(issue_path: str, rules_path: str, approver: Optional[str], approvers: Optional[str],
                  today: dt.date, track_dir: Optional[str] = None) -> int:
    """--approve-issue: turn an approved mitigation request issue into a mitigations.yml entry.
    Exit 0 recorded (or already recorded), 2 invalid request, 3 not an approver."""
    def fail(msgs: list[str], code: int = 2) -> int:
        for msg in msgs:  # the workflow posts these on the issue: keep them Markdown-safe
            print(f"- {md_safe(msg, 500)}", file=sys.stderr)
        return code

    login = (approver or "").strip()
    if not _RE_LOGIN.match(login):
        return fail(["--approver must be the GitHub login of the person who added the label"])
    allowed = parse_approvers(approvers)
    if not allowed:
        return fail(["the repository variable MITIGATION_APPROVERS is empty, so nobody can approve"], NOT_APPROVER)
    if login.lower() not in allowed:
        return fail([f"{login} is not an approver (repository variable MITIGATION_APPROVERS)"], NOT_APPROVER)
    try:
        with open(issue_path, encoding="utf-8") as fh:
            issue = json.load(fh)
    except (OSError, ValueError) as exc:
        return fail([f"cannot read the issue JSON: {exc}"])
    if not isinstance(issue, dict):
        return fail(["the issue JSON must be an object"])
    if str(issue.get("state") or "open").lower() != "open":
        return fail(["the issue is closed; reopen it to approve"])
    url = str(issue.get("url") or "")
    if not _RE_ISSUE_URL.match(url):
        return fail(["the issue JSON has no valid url"])
    author = issue.get("author") if isinstance(issue.get("author"), dict) else {}
    requested_by = str(author.get("login") or "")
    try:
        entries, errors, _ = load_rules(rules_path, today)
    except SystemExit as exc:
        return fail([str(exc)])
    if errors:
        return fail([f"{rules_path} has problems; fix them first:"] + errors[:20])
    done = next((e for e in entries if e["ref"] == url), None)
    if done:
        print(f"Already recorded as {done['id']}")
        github_output(id=done["id"], matches=count_matches(done, track_dir))
        return 0

    fields, problems = parse_issue_form(issue.get("body"))
    f = {k: _RE_UNPRINTABLE.sub(" ", fields.get(k, "")).strip() for k in ISSUE_FORM_FIELDS.values()}
    key = f["finding_key"].lower()
    if not _RE_MKEY.match(key):
        problems.append("Finding Key must look like mk-0123456789ab (use the Mitigate link in FINDINGS.md)")
    for k in ("finding_key", "finding_id", "asset", "file", "expires"):
        if "\n" in f[k]:
            problems.append(f"{k.replace('_', ' ')} must be one line")
    wider = any(ch in f["asset"] for ch in "*?") or bool(f["file"])
    if wider and not f["finding_id"]:
        problems.append("Finding ID is required when Asset has a wildcard or File is set")
    mtype = (f["type"].split() or [""])[0].lower()
    if f["expires"]:
        day, err = rule_date(f["expires"])
        if err:
            problems.append(f"Expires: {err}")
        elif day and day < today:
            problems.append(f"Expires: {day} is in the past")
    entry = {"id": next_rule_id(entries), "finding": f["finding_id"] if wider else key, "asset": f["asset"],
             "file": f["file"], "type": mtype, "reason": f["reason"], "approved_by": login, "approved_on": today,
             "expires": f["expires"], "ref": url, "requested_by": requested_by, "notes": f["notes"]}
    _, errs, _ = validate_rules([{k: v for k, v in entry.items() if v not in ("", None)}], today)
    problems += [e.split(": ", 1)[1] for e in errs]
    if problems:
        return fail(problems)
    err = append_rules(rules_path, [entry], today)
    if err:
        return fail([err])
    n = count_matches(entry, track_dir)
    print(f"Approved as {entry['id']}, applied to {n} finding(s)")
    github_output(id=entry["id"], matches=n)
    return 0


def count_matches(entry: dict[str, Any], track_dir: Optional[str]) -> int:
    """Open findings in DIR/findings.csv that the rule matches (0 without a baseline)."""
    if not track_dir:
        return 0
    path = track_paths(track_dir)["findings"]
    if not os.path.exists(path):
        return 0
    e = {k: str(entry.get(k) or "") for k in RULE_PATTERNS}
    return sum(1 for r in read_csv_file(path) if rule_matches(e, r))


# ---------------------------------------------------------------------------
# Migration from the old tracking CSV (veracode-findings.csv, --mitigations FILE.csv in older versions)
# ---------------------------------------------------------------------------

OLD_TRACKING_FILE = "veracode-findings.csv"


def migrate_old_file(path: str, rules_path: str, today: dt.date) -> tuple[Optional[dict[str, str]], Optional[str]]:
    """Turns every mitigated row of an old tracking CSV into a mitigations.yml entry (finding = its key,
    ref 'migrated') and returns {Finding Key: First Seen} to seed the baseline. Running it twice adds nothing.
    Returns (seed, error)."""
    if not os.path.exists(path):
        return None, f"{path} not found"
    try:
        old = read_csv_file(path)
    except (OSError, csv.Error) as exc:
        return None, f"cannot read {path}: {exc}"
    if old and "Mitigation Key" not in old[0]:
        return None, f"{path} has no Mitigation Key column; it is not an old tracking file"
    try:
        entries, errors, _ = load_rules(rules_path, today)
    except SystemExit as exc:
        return None, str(exc)
    if errors:
        return None, f"{rules_path} has problems; fix them first: " + "; ".join(errors[:5])
    done = {e["finding"].lower() for e in entries if e["ref"] == "migrated"}
    seed: dict[str, str] = {}
    new: list[dict[str, Any]] = []
    problems: list[str] = []
    next_n = int(next_rule_id(entries)[2:])
    for line, row in enumerate(old, 2):
        key = str(row.get("Mitigation Key") or "").strip().lower()
        valid_key = bool(_RE_MKEY.match(key))
        if valid_key and row.get("Mitigation Status") != NOT_IN_EXPORT:
            first = day_of(row.get("First Seen") or row.get("Scan Date"))
            seed[key] = first.isoformat() if first else ""
        mtype = str(row.get("Mitigation Type") or "").strip().lower()
        if not mtype:
            continue
        where = f"{path} row {line} ({row.get('Finding ID') or key or '?'})"
        if not valid_key:
            problems.append(f"{where}: Mitigation Key is missing or changed")
            continue
        if key in done:
            continue
        expires = str(row.get("Mitigation Expires") or "").strip()
        if expires:
            day, err = parse_expiry(expires)
            if err:
                problems.append(f"{where}: Mitigation Expires: {err}")
                continue
            expires = day.isoformat() if day else ""
        entry = {"id": f"M-{next_n:04d}", "finding": key, "type": mtype,
                 "reason": str(row.get("Mitigation Reason") or "").strip(),
                 "approved_by": str(row.get("Mitigation Approved By") or "").strip(), "expires": expires,
                 "notes": str(row.get("Mitigation Notes") or "").strip(), "ref": "migrated"}
        _, errs, _ = validate_rules([{k: v for k, v in entry.items() if v}], today)
        if errs:
            problems += [f"{where}: {e.split(': ', 1)[1]}" for e in errs]
            continue
        new.append(entry)
        done.add(key)
        next_n += 1
    if problems:
        return None, "cannot migrate the old tracking file:\n  " + "\n  ".join(problems[:50])
    if new:
        err = append_rules(rules_path, new, today)
        if err:
            return None, err
    print(f"Migrated {len(new)} mitigation(s) from {path} to {rules_path}"
          + (f" ({new[0]['id']} to {new[-1]['id']})" if new else "")
          + f"; {len(seed)} finding(s) keep their First Seen. {path} is no longer used and can be deleted.")
    return seed, None


def remap_legacy_rules(rules_path: str, current: list[dict]) -> bool:
    """Rules written with a Finding Key from before the code_hash fix get the current key. True if changed."""
    legacy = {str(r.get("_legacy")): str(r.get("Finding Key")) for r in current
              if r.get("_legacy") and r.get("_legacy") != r.get("Finding Key")}
    if not legacy:
        return False
    with open(rules_path, encoding="utf-8-sig") as fh:
        text = fh.read()
    changed = text
    for old, new in legacy.items():
        changed = re.sub(rf"(?i)\b{re.escape(old)}\b", new, changed)
    if changed == text:
        return False
    atomic_write_text(rules_path, changed)
    print(f"Updated old Finding Keys in {rules_path} to the current ones")
    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Track Veracode Container / IaC / Secrets findings over time and apply approved mitigations.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s --track tracking --mitigations mitigations.yml
  %(prog)s --track tracking --mitigations mitigations.yml --asset "my-org/*" -o findings.xlsx
  %(prog)s --track tracking --offline --mitigations mitigations.yml
  %(prog)s --check-mitigations mitigations.yml

Exports with finding filters are not supported by this tracker.""")

    g = p.add_argument_group("findings tracker (see README.md)")
    g.add_argument("--track", metavar="DIR",
                   help="Update the findings baseline in DIR (findings.csv, fixed.csv): New, Open, Reopened and "
                        "Fixed findings of the latest scan per asset. Scan filters apply; finding filters are "
                        "refused. Any failed request changes nothing (exit 1).")
    g.add_argument("--offline", action="store_true",
                   help="With --track: refresh Days Open and the Mitigation columns from the existing baseline, "
                        "without calling Veracode.")
    g.add_argument("--dashboard", metavar="FILE",
                   help="With --track: where to write the Markdown dashboard (default FINDINGS.md next to DIR).")
    g.add_argument("--repo-url", metavar="URL",
                   help="With --track: https://github.com/<org>/<repo>, for the Mitigate links in the dashboard. "
                        "Default: from GITHUB_SERVER_URL and GITHUB_REPOSITORY in GitHub Actions.")
    g.add_argument("--migrate", metavar="OLD_CSV",
                   help="With --track: copy the mitigations of an old tracking CSV (veracode-findings.csv) into "
                        "--mitigations and keep its First Seen dates. Done automatically on the first run when "
                        f"{OLD_TRACKING_FILE} sits next to DIR.")
    g.add_argument("-o", "--output", metavar="FILE",
                   help="With --track: also write every current finding with all columns, Status and Mitigation "
                        "(no code lines). Format from the extension: .xlsx, .csv, .json, .jsonl.")
    g.add_argument("--format", choices=("csv", "json", "jsonl", "xlsx"), help="Force the format of -o.")
    g.add_argument("--keep-empty-columns", action="store_true", help="-o: keep columns with no values.")
    g.add_argument("--no-csv-safe", action="store_true",
                   help="-o: do not prefix cells starting with = + - @ (formula-injection guard).")

    g = p.add_argument_group("scan filters (with --track)")
    g.add_argument("--asset", action="append", metavar="PATTERN",
                   help="Asset to include. Matches asset name, asset ID or source.")
    g.add_argument("--exclude-asset", action="append", metavar="PATTERN", help="Asset to exclude.")
    g.add_argument("--scan-type", action="append", metavar="LIST", help="e.g. container, iac")
    g.add_argument("--asset-type", action="append", metavar="LIST", help="image, repo, archive, directory")
    g.add_argument("--scanned-by", action="append", metavar="PATTERN", help="User that ran the scan.")
    g.add_argument("--policy", choices=("failed", "passed", "not-assessed"), help="Scan policy result.")
    g.add_argument("--since", metavar="DATE|Nd",
                   help="Only scans on/after this (YYYY-MM-DD, YYYYMMDD, ISO datetime, 30d, 12h, 2w).")
    g.add_argument("--until", metavar="DATE|Nd", help="Only scans on/before this (a bare date is inclusive).")

    g = p.add_argument_group(f"mitigations (see {MITIGATIONS_DOC})")
    g.add_argument("--mitigations", metavar="FILE",
                   help="Mitigation rules file (mitigations.yml). Fills the Mitigation columns (Status, Type, "
                        "Reason, Approved By, Expires, Ref) of --track.")
    g.add_argument("--check-mitigations", metavar="FILE",
                   help="Validate and list the rules in this mitigations.yml, then exit (0 valid, 2 invalid). "
                        "No Veracode access needed.")
    g.add_argument("--against", metavar="BASE",
                   help="With --check-mitigations: print Markdown of the rules added, changed or removed compared "
                        "with BASE (for pull requests). Add --track DIR to show how many open findings in "
                        "DIR/findings.csv each rule matches.")
    g.add_argument("--approve-issue", metavar="ISSUE_JSON",
                   help="Record an approved mitigation request: read the issue (JSON with number, title, body, "
                        "url, author, from the approval workflow), validate it and append the next M-NNNN entry "
                        "to --mitigations. Exit 2 if invalid, 3 if --approver is not in MITIGATION_APPROVERS.")
    g.add_argument("--approver", metavar="LOGIN",
                   help="With --approve-issue: GitHub login that added the approved label. Must be listed in the "
                        "MITIGATION_APPROVERS environment variable (comma or space separated).")

    g = p.add_argument_group("Veracode connection")
    g.add_argument("--max-workers", type=int, default=4, help="Concurrent requests (default 4).")
    g.add_argument("--rps", type=float, default=2.0, help="Max requests per second (default 2).")
    g.add_argument("--max-attempts", type=int, default=6, help="Tries per request (default 6).")
    g.add_argument("--timeout", type=int, default=90, help="Seconds per request (default 90).")
    g.add_argument("--ca-cert", metavar="FILE", help="Custom CA bundle (.pem), e.g. behind SSL inspection.")
    g.add_argument("--base-url", default=os.environ.get("VERACODE_IAC_BASE_URL"),
                   help="Container scan query API base. Default: derived from the region of your API credentials "
                        "(US commercial or EU; required for FedRAMP).")
    g.add_argument("--link-base", default=os.environ.get("VERACODE_IAC_LINK_BASE"),
                   help="Base of the Veracode Link column. Default: derived like --base-url.")
    return p


def main(argv: Optional[list[str]] = None, minter: Optional[Callable[[], str]] = None) -> int:
    p = build_parser()
    args, unknown = p.parse_known_args(argv)
    if unknown:
        refused = [f for f in dict.fromkeys(u.split("=", 1)[0] for u in unknown) if f in EXPORT_ONLY_FLAGS]
        if refused and args.track:
            print(f"error: --track cannot be combined with {', '.join(refused)}: findings filtered out would look "
                  "fixed. Use scan filters (--asset, --scan-type, --asset-type, ...) only", file=sys.stderr)
            return 2
        p.error(f"unrecognized arguments: {' '.join(unknown)}")
    if args.rps <= 0:
        p.error("--rps must be greater than 0")
    map_credential_env()
    now = utcnow()
    if args.offline and not args.track:
        print("error: --offline needs --track DIR", file=sys.stderr)
        return 2
    if args.against and not args.check_mitigations:
        print("error: --against needs --check-mitigations FILE", file=sys.stderr)
        return 2
    if args.check_mitigations:
        return check_mitigations(args.check_mitigations, args.against, args.track)
    if args.approve_issue:
        if not args.mitigations:
            print("error: --approve-issue needs --mitigations FILE", file=sys.stderr)
            return 2
        return approve_issue(args.approve_issue, args.mitigations, args.approver,
                             os.environ.get("MITIGATION_APPROVERS"), now.date(), args.track)
    if not args.track:
        print("error: use --track DIR, --check-mitigations FILE or --approve-issue ISSUE_JSON (see --help)",
              file=sys.stderr)
        return 2
    return run_track(args, now, minter)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Nothing was changed.", file=sys.stderr)
        sys.exit(130)
