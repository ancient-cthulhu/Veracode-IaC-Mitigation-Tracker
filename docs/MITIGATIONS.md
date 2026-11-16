# Mitigations

English | [Español](es/MITIGATIONS.md)

Veracode has no mitigations for Container, IaC and Secrets findings, so this tracker keeps them in
[`mitigations.yml`](../mitigations.yml). A mitigated finding shows as **Mitigated** in `FINDINGS.md`, the team and asset
pages, `tracking/findings.csv` and the Excel report. It does **not** change anything in Veracode (see [Limits](#limits)).

## One-time setup (repository admin)

| What | Where | Notes |
| --- | --- | --- |
| Approvers | **Settings → Secrets and variables → Actions → Variables** → `MITIGATION_APPROVERS` | GitHub usernames, separated by spaces or commas: `alice bob`. It must be a **variable**, not a secret. Empty = nobody can approve |
| Approver access | **Settings → Collaborators and teams** | Approvers need at least **Triage**, or they cannot add labels |
| Labels | Created by the first tracker run | `mitigation-request` and `approved`. Do not rename them |
| Branch protection | **Settings → Branches** | The bot pushes approvals to the default branch. If protection blocks GitHub Actions, approvals fail |

## Request a mitigation (anyone)

1. Open `FINDINGS.md`, your team page or the asset page under `findings/`.
2. Click **Mitigate** on the finding. A pre-filled issue opens. Do not change **Finding Key**.
3. Fill in:
   - **Type**: see [Types](#types).
   - **Reason**: why it needs no fix. Be specific; the approver decides from this.
   - **Expires**: `YYYY-MM-DD`, in the future. Required for `accept-risk`, optional otherwise.
   - **Asset / File**: leave as they are to mitigate only this finding. See [Scope](#scope) to cover more.
4. Submit. Within a minute the bot comments the finding's details: severity, file, resource, scan, Veracode link,
   description, and how many other assets have the same finding.

No Mitigate link? The finding is already **Mitigated**, or the report was generated outside GitHub Actions.

## Approve or reject (approvers)

- **Approve:** add the label **`approved`** and keep **`mitigation-request`** on the issue (see the first row of
  [Troubleshooting](#troubleshooting)). In about a minute the bot comments `Approved as M-0001, applied to N finding(s)`,
  commits `mitigations.yml` and the updated reports, and closes the issue.
- **Reject:** close the issue without the label. Nothing is recorded.

## Types

| Type | Use when | Expires |
| --- | --- | --- |
| `false-positive` | The finding is not real | Optional |
| `by-design` | It is deliberate and approved | Optional |
| `network-environment` | A network control blocks it: WAF, security group, private network | Optional |
| `os-environment` | The OS or runtime blocks it: hardened host, read-only file system, no shell | Optional |
| `accept-risk` | The business accepts the risk for a time | **Required** |

## Scope

| Asset | File | Finding ID | Mitigates |
| --- | --- | --- | --- |
| As filled in | Empty | Any | This one finding |
| Wildcard: `acme/payments-*` or `*` | Any | **Required** | This Finding ID on every matching asset |
| Any | Pattern: `modules/status/*` | **Required** | This Finding ID in matching files |

`*` matches any text, `?` one character, case-insensitive. The details comment tells you when the same Finding ID is
open on other assets: that is when a wildcard saves requests.

## After approval

| Mitigation Status | Meaning |
| --- | --- |
| `Mitigated` | A rule matches. The finding no longer counts as open and has no Mitigate link |
| `Expiring` | Expires in 30 days or less. Listed under **Needs action** |
| `Expired` | Past `expires`. Counts as open again, listed under **Needs action**, with a Mitigate link to renew |

## Troubleshooting

| What you see | Why | Fix |
| --- | --- | --- |
| Added `approved`, **nothing happened** (the run shows *skipped*) | The issue lost the `mitigation-request` label. GitHub's label picker can untick it when you tick `approved` | Add `mitigation-request` back, remove `approved`, add `approved` again |
| Label removed, comment "is not an approver" | Your username is not in `MITIGATION_APPROVERS`, or the variable is empty or was created as a secret | Ask an admin to add you to the variable, then add the label again |
| Label removed, comment "This mitigation was not recorded" with a list | The form is invalid: no reason, wrong type, bad or past date, wildcard or File without Finding ID, Finding Key missing or malformed | Edit the issue, then add the label again |
| Label removed, "edited after the label was added" | Someone edited the issue after `approved` was added | Review the edit, then add the label again |
| Label removed, "the issue is closed" | The issue was closed when labeled | Reopen it, then add the label again |
| No details comment on the request | The issue was not opened from the Mitigate link or the form, or the finding is not tracked anymore | Open a new request from the Mitigate link. The comment says when the finding is already fixed |
| Approval run **failed**, issue still open | The bot could not push (branch protection) | Allow GitHub Actions to push to the default branch, then add the label again |
| Edited the issue after approval, nothing changed | A rule is recorded once; labeling again only says `Already recorded` | Change the rule in a pull request ([below](#change-renew-or-revoke)) |
| A mitigated finding shows as **New** again | Its Finding Key changed: file or resource renamed, or a secret's value changed | Mitigate it again, or use a rule by Finding ID with an asset or file scope |
| Still shows the old status after approval | The page was loaded before the bot's commit | Refresh. Look for the commit `Approve mitigation M-...` |

## Change, renew or revoke

Edit `mitigations.yml` in a pull request:

- **Renew:** change `expires`.
- **Widen or narrow:** change `asset` or `file` (with `finding` set to the Finding ID).
- **Revoke:** delete the entry. The findings count as open again on the next run.

The pull request gets a comment listing the rules added, changed or removed and how many open findings each matches.
The check fails if the file is invalid; make it a required check.

```yaml
- id: M-0001
  finding: AVD-AWS-0086          # Finding ID, CVE or Finding Key (mk-...)
  asset: acme/payments-*         # optional
  file: modules/status/*         # optional
  type: accept-risk
  reason: Public status page served through CloudFront
  approved_by: lead-dev
  approved_on: 2026-11-15
  expires: 2027-11-09            # required for accept-risk
  ref: https://github.com/acme/veracode-findings/issues/12
```

| Field | Required | Notes |
| --- | --- | --- |
| `id` | Yes | `M-0001` style, unique. The bot uses the next free number |
| `finding` | Yes | Finding ID, CVE or Finding Key; wildcards allowed |
| `asset`, `file` | No | Narrow the rule; wildcards allowed |
| `type`, `reason`, `approved_by` | Yes | |
| `expires` | For `accept-risk` | `YYYY-MM-DD`; the finding is open again from the next day |
| `approved_on`, `requested_by`, `ref`, `notes` | No | Set by the bot; `notes` holds the ticket number |
| `allow_broad` | No | `true` to allow a rule that matches every finding (`finding: "*"` with no narrower scope) |

When several rules match, the first unexpired one in the file wins. More examples:
[examples/mitigations.example.yml](../examples/mitigations.example.yml).

Locally:

```bash
python tracker/veracode_iac_tracker.py --check-mitigations mitigations.yml                        # validate
python tracker/veracode_iac_tracker.py --track tracking --offline --mitigations mitigations.yml   # apply, no Veracode call
```

## Limits

- Mitigations apply to this tracker and its reports only: not to the Veracode Platform, policies or pipeline gates.
- One approved issue = one rule. To cover many findings at once, use a wildcard [scope](#scope).

## Security

- Only usernames in `MITIGATION_APPROVERS` can approve; changing the variable needs admin access.
- Protect `mitigations.yml`, `teams.yml`, `.github/` and `tracker/` with [CODEOWNERS](../.github/CODEOWNERS) and
  branch protection.
- Issue text never reaches a shell, and everything shown in comments and reports is escaped.
- The pull request check runs the tracker from the base branch, so a pull request cannot change its own check.

## Existing veracode-findings.csv

If a `veracode-findings.csv` with mitigations sits next to the `tracking` folder, the first run copies its mitigations
into `mitigations.yml` (`ref: migrated`) and keeps each finding's First Seen. Delete the CSV afterwards.
