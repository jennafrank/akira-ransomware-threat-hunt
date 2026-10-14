# Detections — Hunt 22 "Harborlight" (Akira Ransomware)

Thirteen behavioral detections authored from a full-chain Akira ransomware
intrusion across three Windows hosts, hunted in Microsoft Sentinel (KQL).
Each rule maps to a step the attacker took in the telemetry.

**Three rules (D3, D6, D10) were validated by replay against the hunt dataset** —
each is shown firing on the real attacker event *and* correctly ignoring a benign
twin present in the same data. The remaining ten are proposed candidates derived
from the hunt, pending baselining. Note: the hunt report was written before this
replay, so its Section 13 lists all thirteen rules as proposed; the three below
were validated afterward.

| Status | Meaning |
|--------|---------|
| Validated | Run against the dataset in a replay; fires on the true event and suppresses the named benign twin. Reproducible with the query in the file. |
| Proposed | Logic complete and mapped; not yet validated against representative benign data. |

## Rule index

| ID | Detection | ATT&CK | Telemetry | Status |
|----|-----------|--------|-----------|--------|
| D1 | fodhelper UAC bypass via ms-settings handler hijack | T1548.002 | Sysmon 13, 1 | Proposed |
| D2 | Masqueraded Windows binary executing from C:\Users\Public | T1036.005 | Sysmon 1 | Proposed |
| **D3** | **Non-service process injecting into spoolsv / lsass** | **T1055, T1003.001** | **Sysmon 8, 10** | **Validated** |
| D4 | LSASS dump written to disk | T1003.001 | Sysmon 11 | Proposed |
| D5 | ntdsutil IFM / NTDS.dit extraction on a domain controller | T1003.003 | Sysmon 1, 11 | Proposed |
| **D6** | **Cloud exfiltration by rclone command grammar (any process name)** | **T1567.002, T1036.005** | **Sysmon 1** | **Validated** |
| D7 | rclone config written via echo (cleartext credentials) | T1567.002 | Sysmon 1 | Proposed |
| D8 | Mass event-log clearing (wevtutil cl / 1102) | T1070.001 | Sysmon 1, Security 1102 | Proposed |
| D9 | Inhibit system recovery (VSS / backup catalog / BCD) | T1490 | Sysmon 1 | Proposed |
| **D10** | **Rogue privileged account creation and group addition** | **T1136.002** | **Security 4720/4728/4732, Sysmon 1** | **Validated** |
| D11 | Non-browser connection volume to candidate C2 endpoints | T1071.001, T1090 | Sysmon 3 | Proposed |
| D12 | rundll32 loading a DLL from a non-system drive via an export | T1218.011, T1553.005 | Sysmon 1 | Proposed |
| D13 | Registry Run values pointing to suspicious staging paths | T1547.001 | Sysmon 13 | Proposed |

## Validated detections — what fired

Each result below is reproducible with the validation query in the rule file,
scoped to the attack window (2026-02-04).

**D3 — injection into spoolsv / lsass.** Fires on all three attack events —
`taskhostw.exe -> spoolsv.exe` (02:47:11), `spoolsv.exe -> lsass.exe` 0x1410 /
0x1fffff (02:49:46), and the LSASS dump access 0x1fffff (02:50:17) — while
suppressing the benign `SearchIndexer.exe -> lsass.exe` reads at mask 0x21410.
The rule catches the maskless CreateRemoteThread event via the source path, not
the access mask, so it holds even when the mask is absent.

**D6 — rclone exfiltration by grammar.** Fires on the three `copy C:\Shares
mega:HARBORLIGHT-exfil` commands even though the rclone binary was renamed
`MsMpEng.exe` (the Windows Defender process) and invoked through `cmd.exe`. The
rule keys on the rclone command grammar, so the masquerade does not help the
attacker evade it. A binary-name rule would have missed all three.

**D10 — rogue privileged account.** Fires on the full privileged-account
sequence: `svc_sql` created (`net user ... /add /domain` + Security 4720), added
to Builtin Administrators (4732) and Domain Admins (`Add-ADGroupMember` + 4728).
Correctly does not match the ransomware-branded `akira_svc` decoy, which was only
a lookup (no `/add`, no 4720).

## Validation scope

The three validated rules were run in a replay against the Harborlight hunt
dataset (the 2026-02-04 attack window) and are shown firing with the named benign
twin suppressed. This replay was done after the hunt report, which is why the
report lists all rules as proposed. The production query in each file uses
`EventTime > ago(1d)`; swap in an explicit date range to reproduce against
historical data. All thirteen rules still require representative benign baselining
before production deployment; each file carries an FP / tuning note with named
exclusion conditions.

## Field notes

- Queries filter on `EventTime` (the attack clock), not `TimeGenerated`
  (ingestion time). The schema export lists `EventID` / `EventCode` as string
  columns, but in this dataset they compare cleanly against integer literals, so
  the queries use bare numbers (e.g. `EventID == 1`).
- EventID 8/10 source and target images are extracted from `EventData_Xml`.
- IOCs are defanged where they appear in rule comments.

---

*Authored by Jenna Frank (Hot Pink Huntress) — Hunt 22 "Harborlight", Log(n) Pacific Cyber Range.*
