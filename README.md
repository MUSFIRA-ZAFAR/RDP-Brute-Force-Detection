# RDP Brute Force Detection — SOC Home Lab Project

## Overview
This project simulates and detects an RDP brute-force attack in a self-built home SOC lab, using **VirtualBox**, **Kali Linux**, **Windows Server 2022**, **Sysmon**, and **Splunk Enterprise**. The goal was to build the full pipeline end-to-end — attacker tooling, victim instrumentation, log forwarding, and detection — and validate it with a real (lab-contained) attack.

## Lab Architecture

| Component | Role | Details |
|---|---|---|
| Kali Linux | Attacker / SIEM | Splunk Enterprise (indexer + search head), Hydra |
| Windows Server 2022 | Victim | Sysmon + Splunk Universal Forwarder |
| Network | Isolated | VirtualBox Host-Only network (192.168.56.0/24) |

**Data pipeline:**
```
Windows Server (Security, System, Sysmon logs)
        │  Splunk Universal Forwarder
        ▼
Kali Linux — Splunk Enterprise (receiving on :9997)
        │
        ▼
   Indexed in `windows_logs`
```

## Attack Simulation

Using **Hydra** from Kali, an RDP brute-force attack was run against the Windows Server (`192.168.56.20`) targeting the `Administrator` account with a custom password list (16 candidate passwords, including the correct one):

```bash
hydra -l Administrator -P passlist.txt rdp://192.168.56.20 -t 4 -V
```

**Result:** 15 failed login attempts followed by 1 successful authentication — a textbook brute-force-to-compromise pattern.

## Detection Logic (SPL)

**Failed logon attempts (Event ID 4625):**
```spl
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4625
| table _time, Failure_Reason, Account_Name, Source_Network_Address, Logon_type
| sort _time
```

**Successful logon following the failures (Event ID 4624):**
```spl
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4624 Account_Name=Administrator
| table _time, Account_Name, Source_Network_Address, Logon_type
```

**Failed logon volume over time (for alerting/dashboard):**
```spl
index=windows_logs sourcetype="WinEventLog:Security" EventCode=4625
| timechart span=1m count as failed_logons
```

## Dashboard

A Splunk dashboard (`RDP Brute Force Detection`) was built with four panels:
1. **Total Failed Attempts** — single-value stat
2. **Failed Logons Over Time** — timeline chart
3. **Successful Logon (Compromise Confirmed)** — the breach event
4. **Failed RDP Logon Attempts** — full detail table

*(Insert dashboard screenshot here)*

## MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Credential Access | Brute Force | [T1110](https://attack.mitre.org/techniques/T1110/) |
| Initial Access | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) |

## Key Findings / Notes
- RDP logon failure events (4625) logged the source as `127.0.0.1` due to how Windows handles RDP's Network Level Authentication internally — a known quirk. In a production environment, this would be correlated with firewall/network flow logs to recover the true external source IP.
- A high volume of 4625 events against a single account in a short time window, followed by a 4624 success, is a reliable and simple brute-force + compromise signature — suitable as a base for a Splunk alert (`| where count > threshold`).

## Skills Demonstrated
- SOC home lab build (VirtualBox, isolated networking)
- Windows log source engineering (Sysmon + SwiftOnSecurity config, Universal Forwarder)
- Splunk administration (indexes, receiving config, permissions troubleshooting)
- SPL query writing for detection engineering
- MITRE ATT&CK mapping
- Dashboard building
- Incident documentation

## Next Steps
- Add alerting (scheduled search + trigger action) for real-time notification
- Expand to a full attack chain: recon → brute force → privilege escalation → persistence
- Add a second detection: SSH brute force against a Linux victim
