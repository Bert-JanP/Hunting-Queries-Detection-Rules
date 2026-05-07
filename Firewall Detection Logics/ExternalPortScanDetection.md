# *External Port Scan / Recon against your environment (High)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1046 | Behavioral Detection Strategy for Network Service Discovery Across Platforms | https://attack.mitre.org/detectionstrategies/DET0376/ |

#### Description
Detecting external port scanning activity is a critical component of perimeter security, focusing on identifying the reconnaissance phase of an attack, where malicious actors map public-facing assets to find open ports, running services, and potential vulnerabilities. It involves analyzing inbound network traffic for patterns—such as a single IP attempting to connect to numerous ports in rapid succession—that deviate from normal user behavior.

**Why it matters:** Recon is often the first step before exploitation.
**Logic**: One external IP hits many ports and/or many internal hosts in a short time.

#### Risk
A successful port scan can provide these formation to the attacker:
1. Services that are running
2. Users who own services
3. Whether anonymous logins are allowed
4. Which network services require authentication

#### Author <Optional>
- **Name: Ravi Nandan Ray**
- **Github: https://github.com/Rajaravi99**
- **Twitter:**
- **LinkedIn: www.linkedin.com/in/ravi-nandan-ray-605465163**
- **Website:**

#### References
- https://www.fortinet.com/resources/cyberglossary/what-is-port-scan
- https://attack.mitre.org/detectionstrategies/DET0376/

## Defender XDR
```KQL
```

## Sentinel
```KQL
// The logs used for testing these detection logics belong to FortiGate, Cisco ASA, Cisco FTD
let Lookback = 10m;
let PortThreshold = 20;
let HostThreshold = 10;
CommonSecurityLog
| where TimeGenerated > ago(Lookback)
| where ipv4_is_private(DestinationIP) == true
| where ipv4_is_private(SourceIP) == false
| summarize
    TotalEvents = count(),
    UniquePorts = dcount(DestinationPort),
    UniqueHosts = dcount(DestinationIP),
    Ports = make_set(DestinationPort, 30),
    Hosts = make_set(DestinationIP, 30)
  by SourceIP, DeviceVendor, DeviceProduct
| where UniquePorts >= PortThreshold or UniqueHosts >= HostThreshold
```

## Furthure fine-tuning suggestions
1. Exclude your known scanners (Qualys/Nessus) via a watchlist.
2. Increase thresholds if your perimeter is noisy.
3. Any specific group of users or groups who are allowed to perform such acitivity for any vulnurability scanning.
