<img width="667" height="329" alt="image" src="https://github.com/user-attachments/assets/e825a280-78cc-4a99-a921-ccc4d01fcb17" />

Scenario
------
Management was notified of unusual internal network activity after security monitoring identified a high volume of failed connection attempts originating from the host cybernecromancy. The connection failures were observed in a sequential port order and targeted both the originating system and another host on the same network, indicating automated network service discovery rather than normal user behavior. Further analysis correlated this activity with the execution of a PowerShell script named portscan.ps1, which was launched at 2025‑12‑22 03:23 UTC under the local account cybermaster. Review of the script confirmed it was configured to scan multiple internal IP addresses across a wide range of common service ports. As this behavior was not authorized or expected for the system, the device was quarantined and an antivirus scan was initiated. Findings were documented and escalated to management for review and risk assessment.


## Scenario creation



# threat-hunting-scenario-portscan

High‑Level Port Scan–Related IoC Discovery Plan

Check DeviceNetworkEvents for repeated failed connection attempts and sequential destination ports, which may indicate automated network service discovery or port scanning behavior.

Check DeviceProcessEvents for execution of PowerShell or scripting activity (e.g., .ps1 files) occurring around the time of the network anomalies, with particular focus on scripts or command lines referencing scanning behavior.

Check DeviceFileEvents for the creation, modification, or execution of custom scanning scripts and related log files (e.g., portscan.ps1, entropygorilla.log) that may support or confirm malicious or unauthorized reconnaissance activity.

🚨 PowerShell Port Scan Detection & Response

Threat Hunting Case Study (Microsoft Defender for Endpoint)

📌 Overview

This repository documents the identification, investigation, and response to suspicious PowerShell-based port scanning activity detected within a controlled virtual environment using Microsoft Defender for Endpoint (MDE). The activity originated from a host named cybernecromancy and was executed under a valid local account, indicating potential misuse of trusted credentials.

Steps taken 
-----
Query used to locate Device Network events:
```kql
DeviceNetworkEvents
| where DeviceName == "cybernecromancy"
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP
| order by ConnectionCount

```

<img width="961" height="297" alt="image" src="https://github.com/user-attachments/assets/dd5ad86f-94d3-449b-b7af-1854ee561b9e" />

Query used to locate events:
```kql
// Observe all failed connections for the IP in question. Notice anything?
let IPInQuestion = "10.0.0.136";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc
```


<img width="1859" height="695" alt="image" src="https://github.com/user-attachments/assets/6645573a-b365-48ae-af0b-b508300e07f6" />

Query used to locate events:
```kql
DeviceNetworkEvents
| where DeviceName == "cybernecromancy"
| where ActionType == "ConnectionFailed"
| where RemotePort in (21,22,23,25,53,69,80,110,123,135,137,138,139,143,161,194,443,445,465,587,993,995,3306,3389,5900,8080,8443)
| summarize ConnectionCount = count() by DeviceName, LocalIP, RemotePort
| order by ConnectionCount desc
```

<img width="869" height="655" alt="image" src="https://github.com/user-attachments/assets/33ea319a-fd04-409e-9e23-dd2551c5cb8c" />


Further actions taken
-----
I maneuvered toward the DeviceProcessEvents table to see if I could see anything that was unusual around the time the port scan started. I noticed a powershell named portscan.ps1 script launching at (2025-12-22T03:23:00Z)
----


I logged into the suspected device and observed the powershell script that was used to conduct the portscan:






# Define the log file path
$logFile = "C:\ProgramData\entropygorilla.log"
$scriptName = "portscan.ps1"


# Function to log messages
function Log-Message {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp [$level] [$scriptName] $message"
    Add-Content -Path $logFile -Value $logEntry
}


# Define the range of IP addresses to scan
$startIP = 4
$endIP = 10
$baseIP = "10.0.0."


# Expanded list of common ports (well-known port numbers 0-1023 + some higher)
$commonPorts = @(21, 22, 23, 25, 53, 69, 80, 110, 123, 135, 137, 138, 139, 143, 161, 194, 443, 445, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443)




I observed the port scan script was launched by the machine cybernecromancy,account name cybermaster. This is not usual behavior, I quarantined the device and ran a antivirus scan.

<img width="669" height="511" alt="image" src="https://github.com/user-attachments/assets/3347a4fb-60c7-424d-a5b4-519483bd41ad" />

Query used to locate Device Process events:

```kql
// Observe DeviceProcessEvents for the past 10 minutes of the unusual activity found
let VMName = "cybernecromancy";
let specificTime = datetime(2025-12-22T03:23:00Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| where InitiatingProcessCommandLine contains "portscan"
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine, AccountName
```


<img width="992" height="180" alt="image" src="https://github.com/user-attachments/assets/cddc30a5-1e32-4a15-aa76-4af2b0bdc62b" />

Query used to locate Device File Events:

```kql
// Summarize file events containing "portscan" on the device
DeviceFileEvents
| where DeviceName == "cybernecromancy"
| where FileName contains "portscan"
| summarize FileEventCount = count() by DeviceName, FileName, FolderPath
| order by FileEventCount desc
```
<img width="991" height="453" alt="image" src="https://github.com/user-attachments/assets/78a16307-0415-45ac-ba39-065efcc02c91" />




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

----
🏁 Conclusion

This project demonstrates an end-to-end threat hunting workflow using Microsoft Defender for Endpoint—moving from anomaly detection, to telemetry correlation, to host investigation, and finally containment. It highlights how legitimate tools and accounts can be leveraged for malicious activity and why behavioral analysis is critical in modern SOC operations.

MITRE ATT&CK Correlated Techniques
----


T1046      – Network Service Discovery
T1059.001  – Command and Scripting Interpreter: PowerShell
TA004      – Privilege Escalation
T1078.003  – Valid Accounts: Local Accounts

