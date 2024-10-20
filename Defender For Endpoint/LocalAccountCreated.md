# Local Account Created

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1136.001 | Create Account: Local Account | https://attack.mitre.org/techniques/T1136/001/ |

#### Description
Adversaries may create local accounts to perform malicious activities. Those accounts can then be used to logon to the compromised system, without the need of persistent tools on the victims device. This query lists all the local account additions in your search window. For Defender For Endpoint the query has a filter based on the DeviceType, wheter it is a server or a workstation. The filter is not activated by default. This DeviceType is not yet supported in Sentinel, thus the query differs from the one in MDE. 

#### Risk
An actor uses a local account to perform malicious activities. Those accounts are often added to the local administrator group to perform priviliged tasks. 

#### References
- https://blog.carnal0wnage.com/2012/09/more-on-aptsim.html
- https://www.mandiant.com/resources/blog/darkside-affiliate-supply-chain-software-compromise

## Defender XDR
```
// Collect all Server IDs for filter
let Servers = DeviceInfo
     | where DeviceType == 'Server'
     | summarize make_set(DeviceId);
// Collect all Workstation IDs for filter
let WorkStations = DeviceInfo
     | where DeviceType == 'Workstation'
     | summarize make_set(DeviceId);
DeviceEvents
| where ActionType == 'UserAccountCreated'
// Extract the DeviceName without the domain name
| extend DeviceNameWithoutDomain = extract(@'(.*?)\.', 1, DeviceName)
// Filter on local additions, then the AccountDomain is equal on the 
DeviceName
| where AccountDomain =~ DeviceNameWithoutDomain
// Enable filters if you want to filter specificly on servers or workstations.
// Uncomment line below for filter on workstations
//| where DeviceId in (WorkStations)
// Uncomment line below for filter on servers
//| where DeviceId in (Servers)
// Add DeviceType
| extend DeviceType = iff(DeviceId in (WorkStations), 'WorkStation', iff(DeviceId in (Servers), 'Server', 'Other'))
| project
     Timestamp,
     DeviceName,
     DeviceType,
     ActionType,
     AccountDomain,
     AccountName,
     AccountSid
```
## Sentinel
```
// Filter is not possible because the DeviceType is missing in Sentinel. For best performance use query in MDE.
DeviceEvents
| where ActionType == 'UserAccountCreated'
// Extract the DeviceName without the domain name
| extend DeviceNameWithoutDomain = extract(@'(.*?)\.', 1, DeviceName)
// Filter on local additions, then the AccountDomain is equal on the DeviceName
| where AccountDomain =~ DeviceNameWithoutDomain
| project TimeGenerated, DeviceName, ActionType, AccountDomain, AccountName, AccountSid
```
