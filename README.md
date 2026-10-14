# Akira Ransomware Threat Hunt: Hunt 22 "Harborlight"

![Threat](https://img.shields.io/badge/threat-Akira%20ransomware-FF1493?style=flat-square&labelColor=0d1117)
![Platform](https://img.shields.io/badge/platform-Microsoft%20Sentinel-FF1493?style=flat-square&labelColor=0d1117)
![Language](https://img.shields.io/badge/query-KQL-FF1493?style=flat-square&labelColor=0d1117)
![Detections](https://img.shields.io/badge/detections-13%20authored-FF1493?style=flat-square&labelColor=0d1117)

**A small dental and insurance office got hit by ransomware overnight. I worked out exactly how, from the raw logs alone.**

## TL;DR

One employee opened a booby-trapped download dressed up as insurance claims paperwork. Over the next 17 hours the attacker spread from that one computer to the file server and the domain controller, tried to copy the company's shared files to cloud storage, ran commands to wipe the backups, and left ransomware and ransom notes on all three machines. Working only from raw Windows logs, I rebuilt the whole attack minute by minute and wrote detection rules to catch each stage next time.

📄 **[Full report (PDF)](report/Hunt22_Harborlight_Akira_Threat_Hunt_JennaFrank.pdf)**

---

## Hunt at a glance

| | |
|---|---|
| **Threat family** | Akira ransomware (TTP match, Medium confidence; not an identity attribution) |
| **Environment** | 3 Windows hosts on a flat /24 LAN, no segmentation: workstation, file server, domain controller |
| **Platform** | Microsoft Sentinel, KQL |
| **Telemetry** | Sysmon EventIDs 1, 3, 8, 10, 11, 13, 22; Windows Security 4624, 4648, 4672, 4720, 4728, 4732, 1102 |
| **Intrusion window** | ~17 hours on 4 February 2026 (first lure 01:57 UTC, implant still connecting at 18:47:29 UTC) |
| **Method** | Hypothesis-driven, intel-informed full-chain reconstruction (PEAK + TaHiTI) |

## Kill chain

| Stage | What happened (all times UTC, 4 Feb 2026) |
|---|---|
| **Entry** | Emily.Grant downloads two lure archives (invoice, then insurance claims) that unpack to ISOs; `rundll32` runs `review.dll,StartW` from the mounted drive (01:59, 02:25). |
| **Privilege escalation** | `fodhelper` UAC bypass through an `ms-settings` handler hijack; the second attempt reaches High integrity (02:42). |
| **Credential theft** | Implant injects into `spoolsv.exe`, which dumps LSASS to `lsass.dmp` (02:50). `ntdsutil` IFM is run against NTDS.dit on the DC (04:33; completion unconfirmed). |
| **Lateral movement** | SMB plus WMI from the workstation to the file server (from 02:57) and the DC (credentialed access by 04:01). |
| **Exfiltration attempt** | rclone renamed to `MsMpEng.exe` runs `copy C:\Shares` to a MEGA remote (03:57 to 04:00; volume and completion unconfirmed). |
| **Anti-recovery** | `vssadmin`, `wbadmin`, `bcdedit` and `wmic shadowcopy delete` on the file server and DC (04:04 to 04:05; success unconfirmed), plus mass event-log clearing on all three hosts. |
| **Ransomware** | Ransomware stages run (05:14); 29 `.akira` artifacts and 128 `akira_readme.txt` note writes across the estate. |
| **Persistence** | Rogue `svc_sql` account created and added to Administrators and Domain Admins (05:21 to 05:22); implant still beaconing from the DC at 18:47:29. |

## MITRE ATT&CK coverage

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing (suspected; delivering message not in telemetry) | T1566 |
| Defense Evasion | Mark-of-the-Web Bypass (suspected) | T1553.005 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Defense Evasion | Process Injection | T1055 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Privilege Escalation | Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Credential Access | OS Credential Dumping: NTDS | T1003.003 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Execution | Windows Management Instrumentation | T1047 |
| Persistence | Scheduled Task | T1053.005 |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 |
| Persistence | Create Account: Domain Account | T1136.002 |
| Persistence / Privilege Escalation | Valid Accounts | T1078 |
| Command and Control | Web Protocols (inferred) | T1071.001 |
| Command and Control | Proxy (inferred from shared CDN context) | T1090 |
| Exfiltration | Exfiltration to Cloud Storage (attempted) | T1567.002 |
| Impact | Inhibit System Recovery | T1490 |
| Impact | Data Encrypted for Impact | T1486 |

Hunted and not observed: DCSync (T1003.006, cannot be excluded without 4662), Pass-the-Hash / Pass-the-Ticket (T1550.002/.003), Exfiltration Over C2 (T1041). Confidence and limits for every row are in Section 11 of the report.

## Detections

**[detections/](detections/)** holds the KQL rules authored from this hunt.

- **13 rules authored**, one or more per kill-chain stage.
- **3 validated** against the hunt dataset: each fires on the real attack event and suppresses the named benign twin ([D3](detections/D03_injection_into_spoolsv_lsass.kql) process injection into spoolsv/lsass, [D6](detections/D06_rclone_grammar_exfiltration.kql) rclone exfiltration by command grammar, [D10](detections/D10_rogue_privileged_account.kql) rogue privileged account).
- **10 proposed**, with benign controls and false-positive rates still to be measured.

## How this maps to the real world

Huntress maps a live Akira intrusion in [Up a Creek Without a Command Line: Mapping an Akira Ransomware Attack](https://www.huntress.com/blog/mapping-akira-ransomware-attack): entry over RDP, LSASS dumped for credentials, rclone for exfiltration, shadow copies deleted, then encryption of a `Shares` folder. This hunt reconstructs the same Akira playbook from raw logs alone, with no EDR verdicts or vendor alerts to lean on, and follows it further: lateral movement to the DC, NTDS extraction, log clearing and a rogue Domain Admin account.

## About

**Jenna Frank** (Hot Pink Huntress). Threat hunting and detection engineering.
