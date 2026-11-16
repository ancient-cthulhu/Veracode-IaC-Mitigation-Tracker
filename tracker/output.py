"""Files the tracker writes and reads back: CSV, JSON, JSONL and Excel tables, text files and the
GitHub Actions step outputs. Tables are written atomically; a locked target falls back to a new file.
"""

from __future__ import annotations

import csv
import datetime as dt
import io
import json
import os
import tempfile
import time
from typing import Any, Iterable, Optional

REPLACE_RETRY_DELAY = 1.0  # seconds between tries when the output file is locked (open in Excel)
XLSX_FONT = "Arial"
XLSX_MAX_ROWS = 1_048_576  # Excel sheet limit, header row included
XLSX_SHEET = "Findings"
XLSX_SEVERITY_FILL = {"Critical": ("C00000", "FFFFFF"), "High": ("FF7C80", "000000"),
                      "Medium": ("FFC000", "000000"), "Low": ("A9D08E", "000000"),
                      "Negligible": ("D9D9D9", "000000"), "Unknown": ("D9D9D9", "000000")}
XLSX_WRAP = {"Title", "Description", "Suggested Fix", "References"}


# ---------------------------------------------------------------------------
# CSV cells
# ---------------------------------------------------------------------------

def csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection from scanned content. A leading apostrophe is doubled
    so read_csv_file gives back the exact value."""
    if isinstance(value, str) and value[:1] == "'":
        return "'" + value
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\x0d"):
        try:
            float(value)
            return value
        except ValueError:
            return "'" + value
    return value


def read_csv_file(path: str) -> list[dict[str, str]]:
    """Reads a CSV saved by the tracker or by Excel: UTF-8 or Windows encoding, comma or semicolon."""
    with open(path, "rb") as fh:
        raw = fh.read()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    first = text.split("\n", 1)[0]
    delim = ";" if first.count(";") > first.count(",") else ","
    rows = []
    for r in csv.DictReader(io.StringIO(text, newline=""), delimiter=delim):
        rows.append({k: (v[1:] if isinstance(v, str) and len(v) > 1 and v[0] == "'" and v[1] in "'=+-@\t\r"
                         else (v or "")) for k, v in r.items() if k is not None})
    return rows


# ---------------------------------------------------------------------------
# Tables (csv, json, jsonl, xlsx)
# ---------------------------------------------------------------------------

class OutputLocked(PermissionError):
    """The output file could not be replaced (usually open in Excel); the data went to `path` instead."""

    def __init__(self, target: str, path: str, count: int) -> None:
        super().__init__(f"{target} is locked; wrote {path} instead")
        self.target, self.path, self.count = target, path, count


def replace_or_fallback(tmp: str, path: str) -> Optional[str]:
    """Move tmp onto path, retrying while the file is locked. Returns the fallback file used, if any."""
    for attempt in range(3):
        try:
            os.replace(tmp, path)
            return None
        except PermissionError:
            if attempt < 2:
                time.sleep(REPLACE_RETRY_DELAY)
    stem, ext = os.path.splitext(path)
    fallback = f"{stem}.{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{ext}"
    os.replace(tmp, fallback)
    return fallback


def write_output(path: str, fmt: str, columns: list[str], rows: Iterable[dict], raw_cells: bool,
                 xlsx_style: Optional[dict[str, Any]] = None) -> int:
    """Writes rows atomically as csv, json, jsonl or xlsx; returns the row count. Raises OutputLocked when
    the target is locked and the rows went to a timestamped file next to it. raw_cells: no csv_safe.
    xlsx_style (Excel only, optional): {"wrap": columns to wrap, "dates": columns holding YYYY-MM-DD dates,
    "fills": {column: {value: "RRGGBB"}} for bold, coloured cells}."""
    count = 0
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".iac_", suffix=".tmp", dir=folder)
    os.close(fd)
    try:
        if fmt == "xlsx":
            count = write_xlsx(tmp, columns, rows, xlsx_style)
        elif fmt == "csv":
            with open(tmp, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.writer(fh)
                w.writerow(columns)
                for row in rows:
                    w.writerow([row.get(c, "") if raw_cells else csv_safe(row.get(c, "")) for c in columns])
                    count += 1
        else:
            with open(tmp, "w", encoding="utf-8") as fh:
                if fmt == "json":
                    fh.write("[\n")
                for row in rows:
                    line = json.dumps({c: row.get(c, "") for c in columns}, ensure_ascii=False)
                    if fmt == "json":
                        fh.write(("," if count else "") + line + "\n")
                    else:
                        fh.write(line + "\n")
                    count += 1
                if fmt == "json":
                    fh.write("]\n")
        fallback = replace_or_fallback(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    if fallback:
        raise OutputLocked(path, fallback, count)
    return count


def save_output(path: str, *args: Any, **kwargs: Any) -> tuple[int, str, bool]:
    """write_output that reports a locked file instead of failing. Returns (rows, file written, locked)."""
    try:
        return write_output(path, *args, **kwargs), path, False
    except OutputLocked as exc:
        print(f"\n  ! {exc.target} is open in another program (Excel?) and could not be replaced. "
              f"Wrote {exc.path} instead.")
        return exc.count, exc.path, True


def xlsx_too_big(fmt: str, rows: int) -> Optional[str]:
    """Error message when `rows` data rows plus the header do not fit in one Excel sheet."""
    if fmt == "xlsx" and rows + 1 > XLSX_MAX_ROWS:
        return (f"{rows:,} rows do not fit in an Excel sheet (max {XLSX_MAX_ROWS - 1:,}). "
                "Write .csv, .json or .jsonl instead, or narrow the filters")
    return None


def xlsx_value(value: Any, column: str, date_columns: Iterable[str] = ()) -> Any:
    """Cell value for Excel: real dates in date columns, text that is never run as a formula."""
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    if value in (None, ""):
        return None
    if column in date_columns:
        if isinstance(value, (dt.date, dt.datetime)):
            return value
        try:
            return dt.date.fromisoformat(str(value).strip()[:10])
        except ValueError:
            pass
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    return ILLEGAL_CHARACTERS_RE.sub("", str(value))[:32767]


def write_xlsx(path: str, columns: list[str], rows: Iterable[dict], style: Optional[dict[str, Any]] = None) -> int:
    try:
        import openpyxl
    except ImportError:
        raise SystemExit("Excel files need openpyxl: pip install openpyxl")
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    style = style or {}
    wrap_cols = XLSX_WRAP | set(style.get("wrap") or ())
    date_cols = set(style.get("dates") or ())
    value_fills: dict[str, dict[str, str]] = style.get("fills") or {}
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = XLSX_SHEET
    fills: dict[str, Any] = {}
    fonts: dict[tuple, Any] = {}

    def fill(rgb: str) -> Any:  # one style object per colour, not one per cell
        if rgb not in fills:
            fills[rgb] = PatternFill("solid", start_color=rgb, end_color=rgb)
        return fills[rgb]

    def font(**kw: Any) -> Any:
        key = tuple(sorted(kw.items()))
        if key not in fonts:
            fonts[key] = Font(name=XLSX_FONT, **kw)
        return fonts[key]

    head_font = font(bold=True, color="FFFFFF")
    body_font = font()
    link_font = font(color="0563C1", underline="single")
    wrap = Alignment(wrap_text=True, vertical="top")
    top = Alignment(vertical="top")
    idx = {c: i + 1 for i, c in enumerate(columns)}
    widths = {c: min(max(len(c), 10), 40) for c in columns}

    head_align = Alignment(vertical="center", wrap_text=True)
    for c, i in idx.items():
        cell = ws.cell(row=1, column=i, value=c)
        cell.font = head_font
        cell.fill = fill("1F3864")
        cell.alignment = head_align
    count = 0
    for count, row in enumerate(rows, 1):
        r = count + 1
        if r > XLSX_MAX_ROWS:
            raise ValueError(f"more than {XLSX_MAX_ROWS - 1:,} rows do not fit in an Excel sheet; use CSV")
        for c, i in idx.items():
            raw = row.get(c, "")
            value = xlsx_value(raw, c, date_cols)
            cell = ws.cell(row=r, column=i, value=value)
            if isinstance(value, str) and value.startswith("="):
                cell.data_type = "s"  # scanned content must never become a formula
            cell.font = body_font
            cell.alignment = wrap if c in wrap_cols else top
            if value is not None:
                widths[c] = max(widths[c], min(len(str(raw)), 60))
            if c == "Veracode Link" and isinstance(value, str) and value.startswith("http"):
                cell.hyperlink = value
                cell.font = link_font
            elif c == "Severity" and value in XLSX_SEVERITY_FILL:
                bg, fg = XLSX_SEVERITY_FILL[value]
                cell.fill, cell.font = fill(bg), font(bold=True, color=fg)
            elif c in value_fills and isinstance(value, str) and value in value_fills[c]:
                cell.fill, cell.font = fill(value_fills[c][value]), font(bold=True)
            if c in date_cols:
                cell.number_format = "yyyy-mm-dd"

    last_row = max(count + 1, 2)
    for c, i in idx.items():
        letter = get_column_letter(i)
        ws.column_dimensions[letter].width = (min(widths[c], 50) if c in wrap_cols else widths[c]) + 2
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(columns))}{last_row}"
    ws.page_setup.orientation = "landscape"   # print: one page wide, header row on every page
    ws.sheet_properties.pageSetUpPr.fitToPage = True
    ws.page_setup.fitToWidth, ws.page_setup.fitToHeight = 1, 0
    ws.print_title_rows = "1:1"
    wb.save(path)
    return count


# ---------------------------------------------------------------------------
# Text and JSON files, GitHub Actions outputs
# ---------------------------------------------------------------------------

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


def read_json_file(path: str) -> dict:
    """The JSON object in the file; {} when it is missing or not an object."""
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


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
