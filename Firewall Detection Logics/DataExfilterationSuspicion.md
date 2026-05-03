# *Data Exfilteration Suspicion: Unusually High Outbound Bytes to a Single External IP (High)*

## Query Information
**Why it matters:** Exfilteration can appear as large sustained upload from a workstation/server.

**Logic**: Compare current window vs a baseline average.

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| TA0010 | https://attack.mitre.org/techniques/T1020/ | https://attack.mitre.org/techniques/T1020/ |

#### Description
This detectin logics works to detect if any adversary is trying to steal data.

Exfiltration consists of techniques that adversaries may use to steal data from your network. Once they’ve collected data, adversaries often package it to avoid detection while removing it. This can include compression and encryption. Techniques for getting data out of a target network typically include transferring it over their command and control channel or an alternate channel and may also include putting size limits on the transmission.

#### Risk
The risks involved with data exfiltration are serious and will have permanent effects on the organizations. There are some prime risks that follow:

1. Data Loss: The foremost risk of data exfiltration is that it might cause a loss of some information that is irreplaceable. The data that is stolen is never retrieved and thus it is permanent, affecting all business operations and strategic moves.
2. Increased Vulnerability: An organization that has suffered a data exfiltration incident may become more susceptible to future attacks. Once attackers have gained access to a system, the backdoor for re-entry may be left open by these attackers or even shared on the dark web with stolen credentials that give them or another attacker a potential direct gateway to breach the system again.
3. Compliance Issues: Non-sensitive data leak or exfiltration can cause a significant amount of violations of the regulations of data protection such as GDPR or HIPAA. In case they are found non-compliant, the organizations will have to face gigantic fines, legal outcomes, and damage to their reputation, which would make the consequences of data exfiltration even worse.

#### Author <Optional>
- **Name: Ravi Nandan Ray**
- **Github: https://github.com/Rajaravi99**
- **Twitter:**
- **LinkedIn: www.linkedin.com/in/ravi-nandan-ray-605465163**
- **Website:**

#### References
- https://www.sentinelone.com/cybersecurity-101/cybersecurity/data-exfiltration/#risks-of-data-exfiltration
- https://attack.mitre.org/tactics/TA0010/

## Defender XDR
```KQL
let CurrentWindow = 1h;
let BaselineWindow = 7d;
let MinBytes = 500000000; // 500MB
let Multiplier = 5;

let baseline =
CommonSecurityLog
| where TimeGenerated between (ago(CurrentWindow)..ago(BaselineWindow))
| where ipv4_is_private(SourceIP) == true and ipv4_is_private(DestinationIP) == false // only outbound connections
| where DeviceAction has_any ("Allow","Allowed","Accept","Accepted","Pass") // only allowed tarffics
| summarize BaselineAvg = avg(todouble(SentBytes)) by SourceIP, DestinationIP;

let current =
CommonSecurityLog
| where TimeGenerated >= ago(CurrentWindow)
| where ipv4_is_private(SourceIP) == true and ipv4_is_private(DestinationIP) == false
| where DeviceAction has_any ("Allow","Allowed","Accept","Accepted","Pass")
| summarize CurrentBytes = sum(todouble(SentBytes)), EventCount=count() by SourceIP, DestinationIP;

current
| join kind=leftouter baseline on SourceIP, DestinationIP
| extend BaselineAvg = coalesce(BaselineAvg, 1.0)
| where CurrentBytes > MinBytes and CurrentBytes > (BaselineAvg * Multiplier)
| order by CurrentBytes desc
```

## Sentinel
```KQL
let CurrentWindow = 1h;
let BaselineWindow = 7d;
let MinBytes = 500000000; // 500MB
let Multiplier = 5;

let baseline =
CommonSecurityLog
| where TimeGenerated between (ago(CurrentWindow)..ago(BaselineWindow))
| where ipv4_is_private(SourceIP) == true and ipv4_is_private(DestinationIP) == false // only outbound connections
| where DeviceAction has_any ("Allow","Allowed","Accept","Accepted","Pass") // only allowed tarffics
| summarize BaselineAvg = avg(todouble(SentBytes)) by SourceIP, DestinationIP;

let current =
CommonSecurityLog
| where TimeGenerated >= ago(CurrentWindow)
| where ipv4_is_private(SourceIP) == true and ipv4_is_private(DestinationIP) == false
| where DeviceAction has_any ("Allow","Allowed","Accept","Accepted","Pass")
| summarize CurrentBytes = sum(todouble(SentBytes)), EventCount=count() by SourceIP, DestinationIP;

current
| join kind=leftouter baseline on SourceIP, DestinationIP
| extend BaselineAvg = coalesce(BaselineAvg, 1.0)
| where CurrentBytes > MinBytes and CurrentBytes > (BaselineAvg * Multiplier)
| order by CurrentBytes desc
```

## Furthure fine-tuning suggestions
1. Add exclusions for backup targets, software update/CDN endpoints.
2. If SentBytes isn’t populated reliably, we can pivot to Bytes in AdditionalExtensions parsing.
