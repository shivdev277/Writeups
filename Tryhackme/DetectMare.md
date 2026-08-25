# TryHackMe — DetectMare Writeup

> **Note on disclosure:** In line with TryHackMe's rules, this writeup does not include flag values, does not reproduce any restricted challenge files, and focuses on methodology rather than answers. Flags/timestamps in this room are generated per-lab-instance, so they are not reusable between users anyway — the value here is in the *approach*.

---

## Challenge Name
DetectMare

## Category
Detection Engineering / Blue Team (Splunk + Detection-as-Code)

## Difficulty
Medium

## Description
DetectMare puts you in the seat of a Detection Engineer at THM Security Services, responding to an intrusion at the fictional Meridian Defense Research Institute. You're handed:

- A **Splunk** instance (`index="dac_lab"`) containing logs collected by CSIRT from the affected hosts.
- A **Detection-as-Code (DaC)** web application — a GitHub-style interface with a `Code` tab, a `README.md` explaining the pipeline, and five open **Pull Requests**, each containing a Sigma detection rule written in response to the incident.

Each PR's Sigma rule is intentionally broken or incomplete (missing metadata, backwards logic, missing exclusions for legitimate noise). The job is to:

1. Investigate the relevant attack technique in Splunk.
2. Understand what legitimate/benign activity in the environment would trigger false positives.
3. Fix the Sigma rule so it catches the real attack while excluding the noise.
4. Push the fix through the CI pipeline (Sigma Syntax Check → Converter → Environment Validation → Automated Red Team Test → Approve → Merge).

The five PRs map to five stages of the same intrusion:

| PR | Technique |
|----|-----------|
| PR#1 | Suspicious Office child process (initial access / macro execution) |
| PR#2 | Proxy execution via `rundll32.exe`/`regsvr32.exe` |
| PR#3 | LSASS memory access (credential dumping) |
| PR#4 | Pass-the-hash authentication + suspicious service creation (lateral movement) |
| PR#5 | Sensitive file staging and archiving (pre-exfiltration) |

## Tools Used
- **Splunk** (Search & Reporting app) — log investigation via SPL
- **Sigma** — vendor-agnostic detection rule language (YAML)
- **DaC web app** — TryHackMe's custom GitHub-style CI/CD interface for Sigma rules
- Basic understanding of **Sysmon** and **Windows Security event log** fields (EventCode 1, 10, 11, 4624, 7045)

## Methodology

The general loop for every PR was the same:

1. **Read the PR description** on the DaC site — it names the MITRE ATT&CK technique and gives context (which threat-intel doc and environment-routine doc were reviewed).
2. **Open the current Sigma rule** under "Files changed" and check for two categories of problems:
   - *Structural errors* — missing required Sigma fields (`title`, `logsource`, `detection`), which the pipeline's Sigma Syntax Check job catches immediately.
   - *Logic errors* — a `condition` that doesn't actually express "catch the bad thing, exclude the known-good things" (e.g. selecting on a legitimate tool instead of excluding it).
3. **Investigate in Splunk** using `index="dac_lab"` with a filter relevant to the technique, and **set the time range to "All time"** (the default "Last 24 hours" window returns nothing, since the incident logs are historical).
4. **Separate signal from noise** by inspecting the results table: identify which rows are known-legitimate tools/processes/accounts (named in the environment-routines documentation) versus the one row that doesn't fit any legitimate pattern.
5. **Write exclusion filters** (`filter_*` blocks in Sigma) for each legitimate pattern found, and combine them into the `condition` with `and not`.
6. **Run the pipeline checks** on the DaC site and iterate until all four checks pass.
7. **Approve and merge** the PR.

## Step-by-Step Solution (Generalized)

### PR#1 — Office child process
- **Splunk query pattern:**
  ```spl
  index="dac_lab" ParentImage="*\WINWORD.EXE" (Image="*\cmd.exe" OR Image="*\mshta.exe" OR Image="*\regsvr32.exe")
  | table _time ComputerName User ParentImage ParentCommandLine Image CommandLine
  ```
- **Finding:** A legitimate Finance/monthly-reporting macro (`MonthEnd_Template.xlsm` → `monthend_report.bat`) spawns `cmd.exe` from `EXCEL.EXE` and would false-positive against a naive rule.
- **Fix:** Add a `filter_finance` block excluding that specific parent/child command-line combination, and broaden `selection_parent`/`selection_child` to cover all Office apps and common LOLBins (`cmd.exe`, `powershell.exe`, `pwsh.exe`, `mshta.exe`, `regsvr32.exe`).

### PR#2 — Proxy execution
- **Splunk query pattern:**
  ```spl
  index="dac_lab" (Image="*\rundll32.exe" OR Image="*\regsvr32.exe") (CommandLine="*\AppData\*" OR CommandLine="*\ProgramData\Intel\*")
  ```
- **Finding:** An internal software-deployment tool (`researchdeploy.exe`) legitimately invokes `rundll32`/`regsvr32` against packages under `\ProgramData\ResearchIT\pkg`, and a license-check flow legitimately calls `regsvr32.exe ... LicenseCheck`. Both are false-positive sources.
- **Fix:** Add `filter_deploy` (excluding `ParentImage` = the internal deploy tool with that package path) and `filter_license` (excluding the `LicenseCheck` regsvr32 pattern), combined with `and not` in the condition.

### PR#3 — LSASS memory access
- **Splunk query pattern:**
  ```spl
  index="dac_lab" TargetImage="*\lsass.exe" SourceImage!="*\WerFault.exe"
  | table _time ComputerName User SourceImage TargetImage GrantedAccess CallTrace
  | sort _time
  ```
- **Finding:** Legitimate EDR and PAM agents (`ResearchEDR`, `ResearchPAM`) routinely access LSASS with high-privilege handles, and `WerFault.exe` (Windows Error Reporting) does too at a specific `GrantedAccess` value. The real attacker's access came from an unexpected process with a `CallTrace` referencing `comsvcs.dll`/`UNKNOWN(` — a known LOLBin technique for dumping LSASS memory.
- **Fix:** Rule needed a proper `title`/`logsource` (was missing both), a `selection_trace` condition on suspicious DLLs in the call stack, and three exclusion filters: WerFault's specific benign access value, and the two legitimate security-tool paths.
- **Additional finding:** Expanding the raw event for the matching row surfaced a `SourceUser` field showing the account used — this field wasn't visible in the default table view because the generic `User` field showed `NOT_TRANSLATED` (a SID that Windows couldn't resolve at the OS level). Always check the full raw event, not just the summary table, when a field looks unresolved.

### PR#4 — Pass-the-hash + service creation
- **Splunk query pattern:**
  ```spl
  index="dac_lab" EventID=4624 LogonType=3 AuthenticationPackageName="NTLM" KeyLength=0
  | table _time ComputerName TargetUserName IpAddress WorkstationName
  | sort _time
  ```
- **Finding:** `KeyLength=0` on an NTLM Type 3 logon is a well-known pass-the-hash indicator. A legacy manufacturing-execution-system account (`svc_mes` from `MES-LEGACY01`) generates this pattern legitimately, as does a clustering service account (`svc_cluster`) authenticating between two classified file servers.
- **Fix:** Rule was missing `title`/`logsource`/entirely — the detection logic itself (logon + two service-creation selections, with the MES and cluster exclusions) was already correctly drafted, it just needed valid Sigma metadata to pass the syntax check.
- **Timestamp:** For the exact-format timestamp question, expand the matching raw event and copy the literal `timestamp` field from the top of the raw text rather than relying on the `_time` column, which only displays to the second.

### PR#5 — Archive staging for exfiltration
- **Splunk query pattern:**
  ```spl
  index="dac_lab" (CommandLine="*.sldprt*" OR CommandLine="*.catpart*" OR CommandLine="*.dwg*")
  | table _time ComputerName User ParentImage Image CommandLine CurrentDirectory
  | sort _time
  ```
- **Finding:** A scheduled backup service (`svc_backup` via `researchbackup.exe`) legitimately archives design files nightly into `D:\Backups\nightly\*.7z`. SolidWorks' own autosave feature (`sldworks.exe`) also legitimately archives files into `C:\ProgramData\SOLIDWORKS\SW_AutoBackup`. The actual attacker used a password-protected RAR archive (`-hp` flag) staged to a suspicious location outside either legitimate pattern.
- **Fix:** Rule file was a near-empty stub — missing `title`, `logsource`, and the entire `detection` block. Rebuilt with selections for sensitive file extensions + archive-tool flags, and exclusions for both legitimate backup mechanisms.
- **Answer to the "which folder" question:** The folder used by the *legitimate* backup routine (`D:\Backups\nightly`) is exactly the path an attacker would want to reuse or mimic — placing a malicious binary there and invoking it in a similar way would blend into the exclusion filter and evade the rule.

## Commands Used

Splunk SPL patterns (generalized, not tied to specific flag data):
```spl
index="dac_lab" <event/field filters relevant to the technique>
| table _time ComputerName User <relevant fields>
| sort _time
```

Sigma rule structure (generalized skeleton used across all five fixes):
```yaml
title: <descriptive title>
id: <unique GUID>
status: experimental
description: <what this detects and why>
author: <name>
logsource:
  product: windows
  category: <process_creation | process_access>   # or service: security for Windows Security log events

detection:
  selection_<name>:
    <field>: <value or list>
  filter_<legit_pattern_name>:
    <field>: <value>
  condition: selection_<name> and not filter_<legit_pattern_name>
```

## Lessons Learned

1. **Always set Splunk's time range to "All time"** when investigating historical/lab data — the default window is silently the biggest source of "0 results" confusion.
2. **A Sigma rule that "selects" the wrong thing is worse than one that's incomplete** — several of the broken rules in this room weren't missing exclusions, they were *actively matching the benign tool instead of the malicious one* (e.g. selecting on WerFault.exe rather than excluding it). Read the `condition` line carefully, not just the field values.
3. **Required Sigma metadata (`title`, `logsource`, `detection`) is checked before logic is ever evaluated.** A perfectly good detection idea will still fail CI if the YAML skeleton is incomplete — read pipeline error output literally, it tells you exactly which field is missing.
4. **Tuning a detection is fundamentally about characterizing your own environment's noise**, not just the attacker's technique. Every fix in this room required identifying a specific legitimate business process (a Finance macro, an internal deploy tool, an EDR/PAM agent, a legacy service account, a nightly backup job, a CAD autosave feature) before the rule could be made both accurate and low-noise.
5. **Don't trust a summary table field blindly** — `User=NOT_TRANSLATED` in the table view didn't mean the data wasn't there; expanding the raw event revealed a separate `SourceUser` field with the actual account name. Raw events are the ground truth.
6. **Pass-the-hash has a distinctive, searchable signature**: NTLM authentication (`AuthenticationPackageName="NTLM"`), Logon Type 3 (network), and `KeyLength=0`. This combination is a reliable starting filter even before any environment-specific tuning.

---

*Writeup based on personal lab investigation. No challenge files, flag values, or restricted materials are included per TryHackMe's content policy.*