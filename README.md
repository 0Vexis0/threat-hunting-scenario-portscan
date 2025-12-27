<img width="667" height="329" alt="image" src="https://github.com/user-attachments/assets/e825a280-78cc-4a99-a921-ccc4d01fcb17" />

Scenario
------
Management was notified of unusual internal network activity after security monitoring identified a high volume of failed connection attempts originating from the host cybernecromancy. The connection failures were observed in a sequential port order and targeted both the originating system and another host on the same network, indicating automated network service discovery rather than normal user behavior. Further analysis correlated this activity with the execution of a PowerShell script named portscan.ps1, which was launched at 2025‑12‑22 03:23 UTC under the local account cybermaster. Review of the script confirmed it was configured to scan multiple internal IP addresses across a wide range of common service ports. As this behavior was not authorized or expected for the system, the device was quarantined and an antivirus scan was initiated. Findings were documented and escalated to management for review and risk assessment.






# threat-hunting-scenario-portscan

🚨 PowerShell Port Scan Detection & Response

Threat Hunting Case Study (Microsoft Defender for Endpoint)

📌 Overview

This repository documents the identification, investigation, and response to suspicious PowerShell-based port scanning activity detected within a controlled virtual environment using Microsoft Defender for Endpoint (MDE). The activity originated from a host named cybernecromancy and was executed under a valid local account, indicating potential misuse of trusted credentials.

🧭 Timeline Summary
1. Initial Detection – Network Anomalies

Multiple failed network connection attempts were observed originating from the same host. These failures occurred in a sequential port order, a strong indicator of automated port scanning behavior.

Data Source: DeviceNetworkEvents

DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount

2. Focused Analysis – Suspected Host

Further inspection isolated the activity to IP address 10.0.0.136, where failed connections appeared in a descending timestamp order and targeted multiple ports sequentially.

let IPInQuestion = "10.0.0.136";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc


Finding:
The ordered progression of destination ports strongly suggested active network service discovery rather than benign misconfiguration.

3. Process-Level Correlation

Investigation pivoted to process execution telemetry around the suspected start time of the scan.

A PowerShell script named portscan.ps1 was launched at:

2025-12-22T03:23:00Z


Data Source: DeviceProcessEvents

let VMName = "cybernecromancy";
let specificTime = datetime(2025-12-22T03:23:00Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName

4. Host Investigation

Direct inspection of the affected system revealed a custom PowerShell port scanning script with the following characteristics:

Logs activity to C:\ProgramData\entropygorilla.log

Scans multiple hosts in the 10.0.0.0/24 range

Targets common service ports (e.g., 21, 22, 80, 443, 3389, 8080)

Executed by:

Device: cybernecromancy

Account: cybermaster (local account)

This behavior was deemed unusual and unauthorized for the environment.

🛑 Response Actions

✅ Device quarantined using Defender for Endpoint

✅ Antivirus scan initiated and completed

✅ Activity documented for forensic review

✅ MITRE ATT&CK techniques mapped

🧠 MITRE ATT&CK Mapping
Tactic	Technique ID	Description
Discovery	T1046	Network Service Discovery
Execution	T1059.001	Command and Scripting Interpreter: PowerShell
Privilege Escalation	TA004	Privilege Escalation
Persistence / Access	T1078.003	Valid Accounts: Local Accounts
🔍 Key Findings

Sequential failed connections are a reliable indicator of port scanning activity

PowerShell remains a high-risk LOLBin when executed by valid local accounts

Defender telemetry enables clear correlation between network and process events

Even internally generated scripts must be treated as potentially malicious without proper authorization

📁 Suggested Repository Structure
├── README.md
├── queries/
│   ├── network_detection.kql
│   ├── process_correlation.kql
├── scripts/
│   └── portscan.ps1
├── timeline/
│   └── incident_timeline.md
└── mitre/
    └── attack_mapping.md

🏁 Conclusion

This project demonstrates an end-to-end threat hunting workflow using Microsoft Defender for Endpoint—moving from anomaly detection, to telemetry correlation, to host investigation, and finally containment. It highlights how legitimate tools and accounts can be leveraged for malicious activity and why behavioral analysis is critical in modern SOC operations.

If you want, I can:

Break this into multiple repo files

Rewrite it to match WGU project rubric language

Add a non-technical executive summary

Align it for resume or portfolio presentation
