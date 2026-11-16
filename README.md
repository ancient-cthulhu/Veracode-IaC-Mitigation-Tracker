# Veracode IaC Mitigation Tracker

Tracks Veracode Container, IaC, and Secrets findings over time. Create a repository from this template, add two secrets, and the tracker runs daily.

**Start here:** [mitigation workflow](docs/MITIGATIONS.md) · [example rules](examples/mitigations.example.yml) · [Spanish README](docs/es/README.md)

## Setup

1. Use this template to create a **private** repository.
2. In **Settings → Secrets and variables → Actions**, add:
   - secrets: `VERACODE_API_ID`, `VERACODE_API_KEY`
   - variable: `MITIGATION_APPROVERS`, for example `alice bob`
   - optional variable: `VERACODE_TRACK_ARGS`, for example `--asset my-org/*`
3. Run **Actions → Veracode findings tracker** once. It runs daily after that.

Use a Veracode API service account that can view Container and IaC scans. The tracker detects the commercial US or EU region from the credentials. For FedRAMP, set the connection options described by `--help`.

## What happens each run

1. Reads the latest scan for each matching asset.
2. Keeps a baseline in `tracking/findings.csv`.
3. Marks findings **New**, **Open**, **Fixed**, or **Reopened**.
4. Writes the interactive dashboard, a compact Markdown fallback, and an Excel artifact.

## Interactive dashboard

Every run writes `site/index.html`. It has asset and severity summaries, search and filters, pagination, and a **Mitigate** link for every actionable finding—no links disappear when the report is large. `FINDINGS.md` remains a compact repository summary and points to it.

The HTML stays in the repository by default. To host it with GitHub Pages, first enable **Settings → Pages → GitHub Actions**, then add the repository variable `ENABLE_FINDINGS_PAGES=true`. GitHub Pages can be public even when the repository is private; do not enable it for sensitive finding data unless the visibility is approved.

## Files

| File | Purpose |
| --- | --- |
| `site/index.html` | Interactive dashboard with every finding and its action links. |
| `FINDINGS.md` | Compact repository summary and fallback. |
| `tracking/findings.csv` | Current open findings. |
| `tracking/fixed.csv` | Findings resolved by a later scan. |
| `mitigations.yml` | Approved mitigation rules. |
| `tracker/` | Tracker, Veracode client, and report writers. |

## Mitigations

A developer selects **Mitigate** in `site/index.html` and submits the pre-filled GitHub issue. A login listed in `MITIGATION_APPROVERS` adds the `approved` label. The workflow validates the request, writes a rule to `mitigations.yml`, refreshes the dashboard, and closes the issue.

See [Mitigations](docs/MITIGATIONS.md) for rule fields, expiry handling, scopes, and examples.

## Local use

```bash
pip install -r requirements.txt
python tracker/veracode_iac_tracker.py --track tracking --mitigations mitigations.yml
```

Set `VERACODE_API_ID` and `VERACODE_API_KEY`, or use `~/.veracode/credentials`.

Useful commands:

```bash
# Validate mitigation rules without calling Veracode
python tracker/veracode_iac_tracker.py --check-mitigations mitigations.yml

# Refresh dashboard and mitigation status from existing local data
python tracker/veracode_iac_tracker.py --track tracking --offline --mitigations mitigations.yml
```

This repository is standalone. For a one-time export with finding-level filters, use [Veracode-IaC-Extract](https://github.com/ancient-cthulhu/Veracode-IaC-Extract).
