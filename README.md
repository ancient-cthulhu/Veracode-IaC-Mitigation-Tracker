# Veracode IaC Mitigation Tracker

Tracks Veracode Container, IaC, and Secrets findings over time. Use the template, add credentials, and it runs daily.

## Setup

1. Use this template to create a private repository.
2. In **Settings → Secrets and variables → Actions**, add:
   - `VERACODE_API_ID`
   - `VERACODE_API_KEY`
   - `MITIGATION_APPROVERS` variable, for example `alice bob`
   - optional `VERACODE_TRACK_ARGS`, for example `--asset my-org/*`
3. Run **Actions → Veracode findings tracker** once. It then runs daily.

## What it creates

- `FINDINGS.md`: dashboard with finding status and Mitigate links.
- `tracking/findings.csv`: open findings.
- `tracking/fixed.csv`: resolved findings.
- `mitigations.yml`: approved mitigation rules.

A finding moves through **New**, **Open**, **Fixed**, and **Reopened**. A developer requests a mitigation from `FINDINGS.md`; an approved reviewer adds the `approved` label, and the workflow records the rule in `mitigations.yml`.

## Local use

```bash
pip install -r requirements.txt
python tracker/veracode_iac_tracker.py --track tracking --mitigations mitigations.yml
```

Set `VERACODE_API_ID` and `VERACODE_API_KEY` locally, or use `~/.veracode/credentials`.

## Files

- `tracker/`: tracker code, Veracode API client, and report writers.
- `docs/MITIGATIONS.md`: mitigation rule format and approval flow.
- `examples/mitigations.example.yml`: example rules.

This repository is standalone. For one-time filtered exports, use [Veracode-IaC-Extract](https://github.com/ancient-cthulhu/Veracode-IaC-Extract).
