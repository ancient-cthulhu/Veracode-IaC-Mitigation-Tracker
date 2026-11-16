"""Veracode access: credentials and region, session token, HTTP client with retry and rate limit, the scan
list, the latest scan per asset, finding rows and the Finding Key.

Reads the Veracode Container Security query API (the one the Platform UI uses). Read-only.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import html
import json
import os
import random
import re
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Iterable, Optional

import requests
from requests.adapters import HTTPAdapter

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Region (from the API key ID prefix) -> (query API base, Veracode Link base).
# FedRAMP hosts are not listed: they must be given explicitly (--base-url, --link-base).
REGION_ENDPOINTS = {
    "global": ("https://ui.analysiscenter.veracode.com/container-scan-query/v1",
               "https://web.analysiscenter.veracode.com/app/container-iac-scans"),
    "eu": ("https://ui.analysiscenter.veracode.eu/container-scan-query/v1",
           "https://web.analysiscenter.veracode.eu/app/container-iac-scans"),
}
AUTH_PREFIX = "VERACODE-TOKEN vsid="
PAGE_LIMIT = 5000
MAX_PAGES = 10_000
RETRYABLE = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_BACKOFF = 90.0
MULTI_SEP = " | "

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}
SEVERITY_LABEL = {5: "Critical", 4: "High", 3: "Medium", 2: "Low", 1: "Negligible", 0: "Unknown"}

# Output column -> raw API field(s).
SCAN_FIELDS: dict[str, tuple[str, ...]] = {
    "Asset Name": ("asset_name",),
    "Asset ID": ("asset_id",),
    "Asset Type": ("asset_type",),
    "Scan Type": ("scan_type",),
    "Scan Source": ("source",),
    "Is Source Link": ("is_source_link",),
    "Scan ID": ("scan_id",),
    "Scan Date": ("scanned_at",),
    "Scan Duration": ("duration",),
    "Scan Status": ("scan_status",),
    "Scanned By": ("user_name",),
    "Policy Name": ("policy_name",),
    "Policy ID": ("policy_id",),
    "Scan Policy Status": ("policy_status",),
}
FINDING_FIELDS: dict[str, tuple[str, ...]] = {
    "Finding ID": ("id",),
    "Finding Type": ("finding_type",),
    "Severity": ("severity",),
    "CVSS": ("cvss",),
    "Exploitability Score": ("exploitability_score",),
    "Impact Score": ("impact_score",),
    "Title": ("title",),
    "Description": ("description",),
    "Suggested Fix": ("suggested_fix",),
    "Rule ID": ("rule_id",),
    "Category": ("category",),
    "Provider": ("provider",),
    "Service": ("service",),
    "Resource": ("resource",),
    "File Path": ("filepath",),
    "Start Line": ("start_line",),
    "End Line": ("end_line",),
    "Code Lines": ("code_lines",),
    "Library Name": ("library_name",),
    "Library Version": ("library_version",),
    "Fix State": ("fix_state",),
    "Fixed Versions": ("fixed_versions",),
    "References": ("reference_urls",),
    "Layer IDs": ("layer_ids",),
    "Finding Policy Status": ("policy_status",),
}
IMAGE_FIELDS = {"Image Hash": "image_hash", "Image Distro": "distro", "Image Tags": "tags",
                "Image Labels": "labels", "Image Layer IDs": "layer_ids"}
HISTOGRAM_COLUMNS = {sev: f"Scan {sev.title()}" for sev in SEVERITY_RANK}

# Column order of the full report (-o). Code Lines is never written: it can hold the secret itself.
REPORT_COLUMNS = [
    "Asset Name", "Asset ID", "Asset Type", "Scan Type", "Scan Source",
    "Severity", "Severity Rank", "CVSS", "Exploitability Score", "Impact Score",
    "Finding Type", "Finding ID", "CVE ID", "Rule ID", "Category",
    "Title", "Description", "Suggested Fix",
    "Library", "Library Name", "Library Version", "Fix Available", "Fix State", "Fixed Versions",
    "Location", "File Path", "Start Line", "End Line", "All File Paths",
    "Provider", "Service", "Resource", "References",
    "Finding Policy Status",
    "Image Tags", "Image Distro", "Image Hash", "Image Labels", "Layer IDs", "Image Layer IDs",
    "Scan ID", "Scan Date", "Scan Age Days", "Scan Duration", "Scan Status", "Scanned By",
    "Policy Name", "Policy ID", "Scan Policy Status", "Is Source Link",
    "Scan Total Findings", *HISTOGRAM_COLUMNS.values(),
    "Is Latest Scan For Asset", "First Seen", "Last Seen",
    "Finding Key", "Veracode Link",
]
# Always kept even if empty across the report.
CORE_COLUMNS = {"Asset Name", "Severity", "Finding Type", "Finding ID", "Title", "File Path", "Scan ID", "Scan Date"}
POLICY_VALUES = {"failed": "error", "passed": "success", "not-assessed": "default"}

_RE_TAG = re.compile(r"<[^>]+>")
_RE_WS = re.compile(r"\s+")
_RE_CVE = re.compile(r"\b(CVE-\d{4}-\d{3,}|GHSA(?:-[0-9a-z]{4}){3})\b", re.I)


class FetchError(Exception):
    """One request (or one paginated read) failed."""


class VeracodeError(Exception):
    """collect_latest could not run. exit_code 2: bad input; 1: Veracode could not be read."""

    def __init__(self, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.exit_code = exit_code


# ---------------------------------------------------------------------------
# Credentials, region, token
# ---------------------------------------------------------------------------

CREDENTIAL_ALIASES = (("VERACODE_API_ID", "VERACODE_API_KEY_ID"), ("VERACODE_API_KEY", "VERACODE_API_KEY_SECRET"))


def map_credential_env() -> None:
    """VERACODE_API_ID / VERACODE_API_KEY are the standard names; the signing libraries read
    VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET. Copy them over when only the standard ones are set."""
    for std, lib in CREDENTIAL_ALIASES:
        if os.environ.get(std) and not os.environ.get(lib):
            os.environ[lib] = os.environ[std]


def credential_region() -> str:
    """Region of the API key ID (env vars, else ~/.veracode/credentials and VERACODE_API_PROFILE).
    'global' when the credentials cannot be read; token minting reports that error."""
    map_credential_env()
    try:
        from veracode_api_signing.credentials import get_credentials
        from veracode_api_signing.regions import get_region_for_api_credential
        return get_region_for_api_credential(get_credentials()[0])
    except Exception:
        return "global"


def resolve_endpoints(base_url: Optional[str], link_base: Optional[str]) -> tuple[str, str]:
    """(query API base, Veracode Link base) for the credentials' region. Explicit values win."""
    if base_url and link_base:
        return base_url, link_base
    region = credential_region()
    hosts = REGION_ENDPOINTS.get(region)
    if hosts is None:
        if not base_url:
            raise VeracodeError(f"your API credentials are for the '{region}' region. Set --base-url (or "
                                "VERACODE_IAC_BASE_URL) and --link-base for that region", 2)
        hosts = (base_url, "")  # no Veracode Link unless --link-base is given
    return base_url or hosts[0], link_base or hosts[1]


def mint_principal_token() -> str:
    """Exchange HMAC credentials for a session token (region-aware via veracode_api_py)."""
    map_credential_env()
    from veracode_api_py.apihelper import APIHelper
    try:
        principal = APIHelper()._rest_request("api/authn/v2/principal", "GET")
    except Exception as exc:
        raise RuntimeError(f"Failed to retrieve principal token: {exc}") from exc
    if not isinstance(principal, dict) or not principal.get("token"):
        raise RuntimeError("Principal response did not contain a token")
    return principal["token"]


class TokenProvider:
    """Mints the session token on first use; re-mints once per expiry."""

    def __init__(self, minter: Callable[[], str]) -> None:
        self._minter = minter
        self._lock = threading.Lock()
        self._token: Optional[str] = None

    def get(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = self._minter()
            return self._token

    def refresh(self, stale: str) -> None:
        with self._lock:
            if self._token == stale:  # nobody else refreshed while we waited
                self._token = self._minter()


# ---------------------------------------------------------------------------
# HTTP: failures, rate limit, retry, pagination
# ---------------------------------------------------------------------------

class Failures:
    """Failed requests of a run, collected across the worker threads."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.items: list[tuple[str, str]] = []

    def add(self, scope: str, detail: str) -> None:
        with self._lock:
            self.items.append((scope, detail))
        print(f"    ! FAILED {scope}: {detail}", file=sys.stderr)


class RateLimiter:
    """Token bucket with a global pause so one 429 stalls every worker."""

    def __init__(self, rps: float) -> None:
        self._rps = rps
        self._cap = max(1.0, rps)  # below 1 rps the bucket must still hold one whole token
        self._tokens = self._cap
        self._last = time.monotonic()
        self._pause_until = 0.0
        self._lock = threading.Lock()

    def pause(self, seconds: float) -> None:
        seconds = min(max(0.0, seconds), MAX_BACKOFF)
        with self._lock:
            self._pause_until = max(self._pause_until, time.monotonic() + seconds)

    def acquire(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                if now < self._pause_until:
                    wait = self._pause_until - now
                else:
                    self._tokens = min(self._cap, self._tokens + (now - self._last) * self._rps)
                    self._last = now
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        return
                    wait = (1.0 - self._tokens) / self._rps
            time.sleep(wait)


def make_session(ca_cert: Optional[str]) -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=20, pool_maxsize=50, max_retries=0)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    if ca_cert:
        s.verify = ca_cert
    return s


class Client:
    def __init__(self, base_url: str, tokens: TokenProvider, limiter: RateLimiter, failures: Failures,
                 ca_cert: Optional[str], max_attempts: int, timeout: int) -> None:
        self.base = base_url.rstrip("/")
        self.tokens = tokens
        self.limiter = limiter
        self.failures = failures
        self.ca_cert = ca_cert
        self.max_attempts = max(1, max_attempts)
        self.timeout = timeout
        self._local = threading.local()

    def _session(self) -> requests.Session:
        if not hasattr(self._local, "s"):
            self._local.s = make_session(self.ca_cert)
        return self._local.s

    def get(self, url: str, params: dict[str, Any], scope: str) -> Optional[dict]:
        """GET with retry. Returns parsed JSON, or None on 404."""
        last = "unknown"
        refreshed = False
        attempt = 0
        while attempt < self.max_attempts:
            attempt += 1
            self.limiter.acquire()
            token = self.tokens.get()
            retry_after: Optional[float] = None
            try:
                resp = self._session().get(
                    url, params=params, timeout=self.timeout,
                    headers={"Authorization": AUTH_PREFIX + token, "Accept": "application/json"})
            except requests.RequestException as exc:
                last = f"{type(exc).__name__}: {str(exc)[:200]}"
            else:
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except ValueError as exc:
                        raise FetchError(f"{scope}: invalid JSON ({exc})") from exc
                    if not isinstance(data, dict):
                        raise FetchError(f"{scope}: expected a JSON object, got {type(data).__name__}")
                    return data
                if resp.status_code == 404:
                    return None
                if resp.status_code == 401 and not refreshed:
                    refreshed = True
                    try:
                        self.tokens.refresh(token)
                    except Exception as exc:
                        raise FetchError(f"{scope}: 401 and token refresh failed: {exc}") from exc
                    attempt -= 1
                    continue
                if resp.status_code not in RETRYABLE:
                    raise FetchError(f"{scope}: HTTP {resp.status_code}. {(resp.text or '')[:300]}")
                last = f"HTTP {resp.status_code}"
                try:  # capped: a huge Retry-After must not stall the run for hours
                    retry_after = min(MAX_BACKOFF, max(0.0, float(resp.headers.get("Retry-After", ""))))
                except ValueError:
                    retry_after = None
                if resp.status_code == 429:
                    self.limiter.pause(retry_after if retry_after is not None else 30.0)
            if attempt >= self.max_attempts:
                break
            delay = retry_after if retry_after is not None else min(MAX_BACKOFF, 1.5 * 2 ** (attempt - 1))
            delay += random.uniform(0, 0.3 * max(delay, 0.5))
            print(f"    retry {attempt}/{self.max_attempts - 1} [{scope}] after {last}; sleeping {delay:.1f}s",
                  file=sys.stderr)
            time.sleep(delay)
        raise FetchError(f"{scope}: exhausted {self.max_attempts} attempts. Last error: {last}")

    def paginate(self, url: str, key: str, scope: str,
                 extra: Optional[dict[str, Any]] = None) -> list[dict]:
        out: list[dict] = []
        seen: set[str] = set()
        expected: Any = None
        prev: Optional[list] = None
        page = 0
        while True:
            params = dict(extra or {})
            params.update({"page": page, "limit": PAGE_LIMIT})
            data = self.get(url, params, f"{scope} page {page}")
            if data is None:
                break
            batch = data.get(key) or []
            if page > 0 and batch and batch == prev:
                self.failures.add(scope, "API returned the same page twice; stopped to avoid duplicates")
                break
            for rec in batch:  # pages can shift while reading: never keep the same record twice
                ident = json.dumps(rec, sort_keys=True, default=str)
                if ident not in seen:
                    seen.add(ident)
                    out.append(rec)
            prev = batch
            total_pages = (data.get("pagination") or {}).get("total_pages")
            expected = (data.get("pagination") or {}).get("total_elements")
            # A short page does not mean the end: the server may cap the page size.
            if not batch:
                break
            if isinstance(total_pages, (int, float)) and page >= int(total_pages) - 1:
                break
            if isinstance(expected, int) and len(out) >= expected:
                break
            page += 1
            if page >= MAX_PAGES:
                self.failures.add(scope, f"hit {MAX_PAGES}-page safety cap; result may be incomplete")
                break
        if isinstance(expected, int) and len(out) < expected:
            self.failures.add(scope, f"API reported {expected} records but only {len(out)} were returned")
        return out


# ---------------------------------------------------------------------------
# Value helpers
# ---------------------------------------------------------------------------

def clean_text(value: Any) -> str:
    if value is None:
        return ""
    text = html.unescape(_RE_TAG.sub(" ", str(value)))
    return _RE_WS.sub(" ", text).strip()


def pick(record: dict, names: Iterable[str]) -> Any:
    for n in names:
        v = record.get(n)
        if v not in (None, "", [], {}):
            return v
    return None


def flat(value: Any) -> Any:
    """Make any JSON value fit in one cell."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            return MULTI_SEP.join(str(v) for v in value if v not in (None, ""))
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def extras(record: dict, consumed: set[str], prefix: str) -> dict[str, Any]:
    """Every raw field not already mapped, flattened one level (a.b)."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        if k in consumed or k == "detailed_findings":
            continue
        if isinstance(v, dict) and v:
            for k2, v2 in v.items():
                out[f"{prefix}: {k}.{k2}"] = flat(v2)
        else:
            out[f"{prefix}: {k}"] = flat(v)
    return out


def parse_when(value: Any) -> Optional[dt.datetime]:
    """Parse ISO 8601 or epoch (s / ms) into an aware UTC datetime."""
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)) or str(value).isdigit():
            n = float(value)
            return dt.datetime.fromtimestamp(n / 1000 if n > 1e11 else n, dt.timezone.utc)
        s = str(value).strip().replace("Z", "+00:00")
        s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # trim nanoseconds
        d = dt.datetime.fromisoformat(s)
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


# ---------------------------------------------------------------------------
# Scan filters (--asset, --scan-type, --since, ...)
# ---------------------------------------------------------------------------

def compile_pattern(pat: str) -> Callable[[str], bool]:
    """Plain text = contains. With * or ? = whole-value wildcard. 're:<regex>' = regex.
    Always case-insensitive."""
    pat = pat.strip()
    if pat.lower().startswith("re:"):
        rx = re.compile(pat[3:], re.I)
        return lambda s: bool(rx.search(s))
    if not any(ch in pat for ch in "*?"):
        needle = pat.lower()
        return lambda s: needle in s.lower()
    rx = re.compile(fnmatch.translate(pat), re.I)
    return lambda s: bool(rx.match(s))


def split_patterns(text: str) -> list[str]:
    """Comma-separated, but a 're:' pattern keeps its commas."""
    if text.strip().lower().startswith("re:"):
        return [text.strip()]
    return [p.strip() for p in text.split(",") if p.strip()]


class ScanFilter:
    """Passes a scan row when any pattern matches one of the columns (none of them when negated)."""

    def __init__(self, columns: tuple[str, ...], patterns: str, negate: bool = False) -> None:
        self.columns = columns
        self.negate = negate
        self.matchers = [compile_pattern(p) for p in split_patterns(patterns)]
        if not self.matchers:
            raise ValueError(f"Filter '{columns[0]}{'!=' if negate else '='}{patterns}' has no pattern")

    def test(self, row: dict[str, Any]) -> bool:
        parts: list[str] = []
        for column in self.columns:
            cell = str(row.get(column, ""))
            parts.append(cell)
            if MULTI_SEP in cell:
                parts.extend(cell.split(MULTI_SEP))
        return any(m(p) for m in self.matchers for p in parts) != self.negate


def scan_filters(asset: Optional[list[str]], exclude_asset: Optional[list[str]], scan_type: Optional[list[str]],
                 asset_type: Optional[list[str]], scanned_by: Optional[list[str]],
                 policy: Optional[str]) -> list[ScanFilter]:
    asset_columns = ("Asset Name", "Asset ID", "Scan Source")
    out = [ScanFilter(asset_columns, v) for v in asset or []]
    out += [ScanFilter(asset_columns, v, negate=True) for v in exclude_asset or []]
    for column, values in (("Scan Type", scan_type), ("Asset Type", asset_type), ("Scanned By", scanned_by)):
        out += [ScanFilter((column,), v) for v in values or []]
    if policy:
        out.append(ScanFilter(("Scan Policy Status",), f"re:^{POLICY_VALUES[policy]}$"))
    return out


def parse_cutoff(value: str, now: dt.datetime) -> dt.datetime:
    """'30d', '12h', '2w' (relative), YYYYMMDD, or an ISO date / datetime. Other bare numbers are rejected."""
    text = value.strip()
    m = re.fullmatch(r"(\d+)([hdw])", text.lower())
    if m:
        unit = {"h": "hours", "d": "days", "w": "weeks"}[m.group(2)]
        return now - dt.timedelta(**{unit: int(m.group(1))})
    error = ValueError(f"Unrecognised date '{value}'. Use YYYY-MM-DD, YYYYMMDD or e.g. 30d")
    if text.isdigit():
        try:
            if len(text) != 8:
                raise ValueError
            return dt.datetime.strptime(text, "%Y%m%d").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            raise error from None
    d = parse_when(text)
    if not d:
        raise error
    return d


def parse_window(since: Optional[str], until: Optional[str],
                 now: dt.datetime) -> tuple[Optional[dt.datetime], Optional[dt.datetime]]:
    """--since / --until as datetimes. A bare --until date is inclusive."""
    start = parse_cutoff(since, now) if since else None
    end = parse_cutoff(until, now) if until else None
    if end and until and re.fullmatch(r"\d{4}-?\d{2}-?\d{2}", until.strip()):
        end += dt.timedelta(days=1)
    return start, end


def in_window(scan: dict, since: Optional[dt.datetime], until: Optional[dt.datetime]) -> bool:
    when = parse_when(scan.get("scanned_at"))
    if since and (not when or when < since):
        return False
    return not (until and (not when or when > until))


# ---------------------------------------------------------------------------
# Finding Key
# ---------------------------------------------------------------------------

_RE_DIGEST = re.compile(r"@sha256:[0-9a-f]{16,}$", re.I)
_RE_LINE_NO = re.compile(r"^\s*\d+\s*[:|]\s?", re.M)
_RE_LINE_NO_LEGACY = re.compile(r"^\s*\d+\s*[:|]?\s?", re.M)  # also ate leading digits of the code itself


def stable_asset(name: Any, asset_type: Any) -> str:
    """Lower-case asset name. Images lose their tag and digest, so app:1.2 and app:1.3 match."""
    a = str(name or "").strip()
    if str(asset_type or "").strip().lower() == "image":
        a = _RE_DIGEST.sub("", a)
        head, sep, last = a.rpartition("/")
        a = head + sep + last.split(":", 1)[0]
    return a.lower()


def stable_path(path: Any) -> str:
    p = str(path or "").strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def code_hash(code: Any, legacy: bool = False) -> str:
    """Hash of the flagged code without whitespace or line numbers. The code itself is never stored.
    legacy=True reproduces the old hash (line-number prefix without a separator), to remap old keys."""
    if code in (None, "", [], {}):
        return ""
    parts: list[str] = []

    def collect(v: Any) -> None:
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, list):
            for x in v:
                collect(x)
        elif isinstance(v, dict):
            for k in sorted(v):
                collect(v[k])

    value: Any = code
    if isinstance(code, str):
        try:
            value = json.loads(code)
        except ValueError:
            value = (_RE_LINE_NO_LEGACY if legacy else _RE_LINE_NO).sub("", code)
    collect(value)
    compact = re.sub(r"\s+", "", "".join(parts))
    return hashlib.sha256(compact.encode()).hexdigest()[:16] if compact else ""


def finding_key(row: dict[str, Any], legacy: bool = False) -> str:
    """Finding Key: stays the same between scans (no line numbers, no image tags).
    The mk- prefix stops spreadsheets from turning it into a number. legacy=True gives the key
    older versions computed (only secrets with plain-text code lines differ)."""
    ftype = str(row.get("Finding Type") or "").strip().lower()
    low = lambda col: str(row.get(col) or "").strip().lower()  # noqa: E731
    path = stable_path(row.get("File Path"))
    parts = ["v1", stable_asset(row.get("Asset Name"), row.get("Asset Type")), ftype, low("Finding ID")]
    if ftype == "misconfiguration":
        parts += [low("Rule ID"), path, low("Resource")]
    elif ftype == "secret":
        parts += [low("Rule ID"), path, code_hash(row.get("Code Lines"), legacy)]
    elif ftype == "vulnerability":
        parts += [low("Library Name"), path]
    else:
        parts += [low("Rule ID"), path, low("Resource"), low("Library Name")]
    return "mk-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Rows
# ---------------------------------------------------------------------------

def scan_row(scan: dict, now: dt.datetime, link_base: str, latest_ids: set[str]) -> dict[str, Any]:
    consumed: set[str] = set()
    row: dict[str, Any] = {}
    for col, names in SCAN_FIELDS.items():
        row[col] = flat(pick(scan, names))
        consumed.update(n for n in names if n in scan)
    hist = scan.get("severity_histogram")
    if isinstance(hist, dict):
        consumed.add("severity_histogram")
        hist = {str(k).strip().lower(): v for k, v in hist.items()}
        for sev, col in HISTOGRAM_COLUMNS.items():
            row[col] = hist.get(sev, 0) or 0
        row["Scan Total Findings"] = sum(v for v in hist.values() if isinstance(v, (int, float)))
    when = parse_when(scan.get("scanned_at"))
    row["Scan Date"] = when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else flat(scan.get("scanned_at"))
    row["Scan Age Days"] = (now - when).days if when else ""
    sid = str(scan.get("scan_id") or "")
    row["Is Latest Scan For Asset"] = "true" if sid in latest_ids else "false"
    row["Veracode Link"] = f"{link_base}/{sid}/summary" if sid and link_base else ""
    row.update(extras(scan, consumed, "Scan"))
    return row


def finding_row(finding: dict, base: dict[str, Any]) -> dict[str, Any]:
    """One finding as a flat row, on top of its scan row."""
    consumed: set[str] = set()
    row = dict(base)
    for col, names in FINDING_FIELDS.items():
        val = pick(finding, names)
        consumed.update(n for n in names if n in finding)
        row[col] = flat(val)

    image = finding.get("image")
    if isinstance(image, dict):
        consumed.add("image")
        for col, key in IMAGE_FIELDS.items():
            row[col] = flat(image.get(key)) if image.get(key) not in (None, "", [], {}) else ""
        for key in image:
            if key not in IMAGE_FIELDS.values():
                row[f"Finding: image.{key}"] = flat(image[key])

    lib, ver = str(row.get("Library Name") or ""), str(row.get("Library Version") or "")
    row["Library"] = f"{lib}@{ver}" if lib and ver else lib
    state = str(row.get("Fix State") or "").strip().lower()
    if state or row.get("Fixed Versions") or lib:
        row["Fix Available"] = "true" if (row.get("Fixed Versions") or state == "fixed") else "false"

    sev = str(finding.get("severity") or "unknown").strip().lower()
    rank = SEVERITY_RANK.get(sev, 0)
    row["Severity"] = SEVERITY_LABEL[rank] if sev in SEVERITY_RANK else sev.title()
    row["Severity Rank"] = rank

    paths = pick(finding, FINDING_FIELDS["File Path"])
    paths = [str(p) for p in paths] if isinstance(paths, list) else ([str(paths)] if paths else [])
    row["File Path"] = paths[0] if paths else ""
    row["All File Paths"] = MULTI_SEP.join(paths)
    start, end = row.get("Start Line") or "", row.get("End Line") or ""
    loc = row["File Path"]
    if start and end and str(start) != str(end):
        loc += f":{start}-{end}"
    elif start:
        loc += f":{start}"
    row["Location"] = loc

    for col in ("Title", "Description", "Suggested Fix"):
        row[col] = clean_text(row.get(col))
    if not row["Title"]:
        row["Title"] = row["Description"][:120]

    fid = str(row.get("Finding ID") or "")
    ftype = str(row.get("Finding Type") or "").strip().lower()
    row["Finding Type"] = ftype.title()
    m = _RE_CVE.search(fid)
    row["CVE ID"] = m.group(1).upper() if m else (fid if ftype == "vulnerability" else "")

    row["Finding Key"] = finding_key(row)  # line-independent; the tracker's identity for a finding
    row.update(extras(finding, consumed, "Finding"))
    return row


def report_columns(seen: dict[str, int], base: list[str], keep_empty: bool) -> list[str]:
    """Columns of the full report: base order, then the extra ones; empty columns dropped unless kept."""
    extra_cols = sorted(c for c in seen if c not in base and not c.startswith("_"))
    return [c for c in base + extra_cols if keep_empty or c in CORE_COLUMNS or seen.get(c)]


# ---------------------------------------------------------------------------
# Latest scan per asset
# ---------------------------------------------------------------------------

def latest_scan_ids(scans: list[dict]) -> set[str]:
    best: dict[tuple, tuple[dt.datetime, str]] = {}
    floor = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    for s in scans:
        key = (str(s.get("asset_id") or s.get("asset_name") or "").lower(),
               str(s.get("asset_type") or "").lower(), str(s.get("scan_type") or "").lower())
        when = parse_when(s.get("scanned_at")) or floor
        sid = str(s.get("scan_id") or "")
        if key not in best or when > best[key][0]:
            best[key] = (when, sid)
    return {sid for _, sid in best.values()}


_END = object()


def bounded_map(pool: ThreadPoolExecutor, fn: Callable[[Any], Any], items: Iterable[Any], limit: int) -> Iterable[Any]:
    """Like pool.map, in input order, but with at most `limit` tasks submitted and not yet consumed."""
    pending: deque = deque()
    it = iter(items)
    for item in it:
        pending.append(pool.submit(fn, item))
        if len(pending) >= limit:
            break
    while pending:
        result = pending.popleft().result()
        nxt = next(it, _END)
        if nxt is not _END:
            pending.append(pool.submit(fn, nxt))
        yield result


def fetch_scan_findings(client: Client, scan: dict) -> Optional[list[dict]]:
    """All findings of one scan, or None (failure recorded) when they could not be read."""
    sid, name = scan.get("scan_id"), scan.get("asset_name", "Unknown")
    if not sid:
        client.failures.add(f"scan[{name}]", "record has no scan_id")
        return None
    try:
        return client.paginate(f"{client.base}/scans/{sid}/findings", "findings",
                               f"findings[{name}:{sid}]", {"sort": "severity", "direction": "desc"})
    except FetchError as exc:
        client.failures.add(f"findings[{name}:{sid}]", str(exc))
    except Exception as exc:  # unexpected: record it and carry on with the other scans
        client.failures.add(f"findings[{name}:{sid}]", f"{type(exc).__name__}: {exc}")
    return None


def collect_latest(base_url: Optional[str], link_base: Optional[str], now: dt.datetime, *,
                   asset: Optional[list[str]] = None, exclude_asset: Optional[list[str]] = None,
                   scan_type: Optional[list[str]] = None, asset_type: Optional[list[str]] = None,
                   scanned_by: Optional[list[str]] = None, policy: Optional[str] = None,
                   since: Optional[str] = None, until: Optional[str] = None, workers: int = 4, rps: float = 2.0,
                   max_attempts: int = 6, timeout: int = 90, ca_cert: Optional[str] = None,
                   minter: Optional[Callable[[], str]] = None,
                   ) -> tuple[list[dict], list[dict], list[tuple[str, str]]]:
    """Every finding of the latest scan per asset.

    base_url / link_base: None derives them from the credentials' region (give them for FedRAMP).
    asset, exclude_asset, scan_type, asset_type, scanned_by: lists of patterns. policy: failed, passed or
    not-assessed. since / until: a date or e.g. 30d. Every picked scan is read, whatever its totals say.

    Returns (scans, finding_rows, failures):
      scans         scan_row() of every scan in the tenant; "_read": True on the latest scans whose
                    findings were read in full
      finding_rows  finding_row() of every finding in those scans (Code Lines included)
      failures      (scope, detail) of every failed request; not empty means the data is incomplete
    Raises VeracodeError (exit_code 2 for bad input, 1 when the token or the scan list cannot be read)."""
    if policy is not None and policy not in POLICY_VALUES:
        raise VeracodeError(f"policy must be one of {', '.join(POLICY_VALUES)}", 2)
    if rps <= 0:
        raise VeracodeError("rps must be greater than 0", 2)
    try:
        filters = scan_filters(asset, exclude_asset, scan_type, asset_type, scanned_by, policy)
        start, end = parse_window(since, until, now)
    except (ValueError, re.error) as exc:
        raise VeracodeError(str(exc), 2) from None
    if ca_cert and not os.path.isfile(ca_cert):
        raise VeracodeError(f"CA certificate not found: {ca_cert}", 2)
    base_url, link_base = resolve_endpoints(base_url, link_base)

    failures = Failures()
    tokens = TokenProvider(minter or mint_principal_token)
    try:
        tokens.get()
    except Exception as exc:
        raise VeracodeError(str(exc), 1) from exc
    client = Client(base_url, tokens, RateLimiter(rps), failures, ca_cert, max_attempts, timeout)
    print("Fetching scan list...")
    try:
        raw = client.paginate(f"{client.base}/scans", "records", "scans")
    except FetchError as exc:
        raise VeracodeError(str(exc), 1) from exc
    latest = latest_scan_ids(raw)
    scans = [scan_row(s, now, link_base, latest) for s in raw]
    picked = [(s, r) for s, r in zip(raw, scans) if in_window(s, start, end) and all(f.test(r) for f in filters)]
    keep_ids = latest_scan_ids([s for s, _ in picked])  # the latest among the scans that passed the filters
    picked = [(s, r) for s, r in picked if str(s.get("scan_id") or "") in keep_ids]
    print(f"  {len(raw)} scans in tenant; reading the latest scan of {len(picked)} asset(s)")

    rows: list[dict] = []
    n = max(1, workers)
    with ThreadPoolExecutor(max_workers=n) as pool:
        results = bounded_map(pool, lambda sr: fetch_scan_findings(client, sr[0]), picked, 2 * n)
        for (_, base), found in zip(picked, results):
            if found is None:
                continue
            for rec in found:
                try:
                    rows.append(finding_row(rec, base))
                except Exception as exc:
                    failures.add(f"normalise[{base.get('Asset Name')}]", f"{type(exc).__name__}: {exc}")
            base["_read"] = True
    return scans, rows, list(failures.items)
