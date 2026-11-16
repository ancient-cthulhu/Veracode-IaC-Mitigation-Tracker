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
4. Writes `FINDINGS.md`, one page per asset under `findings/`, and an Excel artifact.

## Reading the report

Everything renders on GitHub, so repository permissions decide who sees it.

- `FINDINGS.md` — risk snapshot, **Needs action** (new, reopened, expiring and expired, each with its Mitigate link), one row per asset with severity counts, and what was fixed in the last 30 days.
- `findings/<asset>.md` — every finding of that asset with its Veracode and Mitigate links. Assets with more than 300 findings get numbered continuation pages, so no page is too large for GitHub to render and no link is ever dropped.

Optional HTML dashboard (search, filters, asset drill-down) for organizations on GitHub Enterprise Cloud, where GitHub Pages can be private: enable **Settings → Pages → GitHub Actions** and add the repository variable `ENABLE_FINDINGS_PAGES=true`. On other plans Pages is public, so leave it off.

## Files

| File | Purpose |
| --- | --- |
| `FINDINGS.md` | Dashboard: snapshot, needs action, assets, recently fixed. |
| `findings/` | One Markdown page per asset with every finding and its links. |
| `tracking/findings.csv` | Current open findings. |
| `tracking/fixed.csv` | Findings resolved by a later scan. |
| `mitigations.yml` | Approved mitigation rules. |
| `tracker/` | Tracker, Veracode client, report writers, optional HTML template. |

## Mitigations

A developer clicks **Mitigate** on a finding (in `FINDINGS.md` or the asset page) and submits the pre-filled GitHub issue. A login listed in `MITIGATION_APPROVERS` adds the `approved` label. The workflow validates the request, writes a rule to `mitigations.yml`, refreshes the report, and closes the issue.

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
