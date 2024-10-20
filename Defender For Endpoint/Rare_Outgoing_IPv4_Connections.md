# *Rare or low-prevalent outgoing, successful IPv4 connections from non-browser processes*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| Multiple | This one might meet multiple |Feel free to expand this one|

#### Description
Hypothesis: Attackers will eventually communicate to the external networks (Internet) where their infrastructure is located. What if that originates from a low prevalence process communicating over TCP via an uncommon port?

#### Risk
The results will contain a list of unique process names successfully establishing TCP connections using non-web ports to plain IP addresses - and observed from less than 4 endpoints given your entire fleet.
These might of course include legit, rare outgoing connections but more importantly, it may also reveal rogue, unwanted or unexpected communications such as RATs, C2 and other network covert channels.

#### Author <Optional>
- **Name:** Alex Teixeira
- **Github:** https://github.com/inodee
- **Twitter:** https://x.com/ateixei
- **LinkedIn:** https://www.linkedin.com/in/inode
- **Website:** https://detect.fyi

#### References
- [Query walkthrough at Medium](https://ateixei.medium.com/f5bfdc0d55d6?source=friends_link&sk=7f5d56cf3a85c126992ce866dd864b86)


## Defender XDR
```KQL
// Author: Alex Teixeira (alex@opstune.com)
// Query walkthrough: https://ateixei.medium.com/f5bfdc0d55d6?source=friends_link&sk=7f5d56cf3a85c126992ce866dd864b86
let ExcludedNets = datatable(ExcludedNet: string) 
    ['100.0.0.0/16', '200.200.200.0/24']; 
search in (DeviceNetworkEvents) "tcp" and "connectionsuccess" and "public" 
// Set the time scope
| where Timestamp > ago(30d)
// For this initial hunt, focus on plain IPv4 target resources only, no URLs
| where isempty(RemoteUrl)
// Consume the list of CIDRs to exclude (consider doing it after summarize as well)
| evaluate ipv4_lookup(ExcludedNets, RemoteIP, ExcludedNet, return_unmatched = true)
| where isempty(ExcludedNet)
// What if a malicious process actually matches those?
// So be sure to cover that with other use cases.
| where not(InitiatingProcessFileName matches regex @'(?i)^(msedge|chrome|firefox)\.exe$')
| where (Protocol == "Tcp" and ActionType == "ConnectionSuccess" and RemoteIPType == "Public") and InitiatingProcessFileName endswith ".exe" and not(RemotePort in (80, 443)) 
// Lower-case the process name to keep unique entries in the output
| extend InitiatingProcessFileName=tolower(InitiatingProcessFileName)
| summarize
  Hashes=make_set(InitiatingProcessMD5),
  DeviceCount=count_distinct(DeviceId),
  SampleProcess=any(InitiatingProcessCommandLine),
  SampleRemoteIP=any(RemoteIP),
  Ports=make_set(RemotePort) by InitiatingProcessFileName
// To make it even more strict, decrease the number to narrow the results
| where DeviceCount < 4
| extend RemoteIP_country = tostring(parse_json(geo_info_from_ip_address(SampleRemoteIP)).country) 
| sort by DeviceCount asc
```
## Sentinel
```KQL
// Author: Alex Teixeira (alex@opstune.com)
// Query walkthrough: https://ateixei.medium.com/f5bfdc0d55d6?source=friends_link&sk=7f5d56cf3a85c126992ce866dd864b86
let ExcludedNets = datatable(ExcludedNet: string) 
    ['100.0.0.0/16', '200.200.200.0/24']; 
search in (DeviceNetworkEvents) "tcp" and "connectionsuccess" and "public" 
// Set the time scope
| where TimeGenerated > ago(30d)
// For this initial hunt, focus on plain IPv4 target resources only, no URLs
| where isempty(RemoteUrl)
// Consume the list of CIDRs to exclude (consider doing it after summarize as well)
| evaluate ipv4_lookup(ExcludedNets, RemoteIP, ExcludedNet, return_unmatched = true)
| where isempty(ExcludedNet)
// What if a malicious process actually matches those?
// So be sure to cover that with other use cases.
| where not(InitiatingProcessFileName matches regex @'(?i)^(msedge|chrome|firefox)\.exe$')
| where (Protocol == "Tcp" and ActionType == "ConnectionSuccess" and RemoteIPType == "Public") and InitiatingProcessFileName endswith ".exe" and not(RemotePort in (80, 443)) 
// Lower-case the process name to keep unique entries in the output
| extend InitiatingProcessFileName=tolower(InitiatingProcessFileName)
| summarize
  Hashes=make_set(InitiatingProcessMD5),
  DeviceCount=count_distinct(DeviceId),
  SampleProcess=any(InitiatingProcessCommandLine),
  SampleRemoteIP=any(RemoteIP),
  Ports=make_set(RemotePort) by InitiatingProcessFileName
// To make it even more strict, decrease the number to narrow the results
| where DeviceCount < 4
| extend RemoteIP_country = tostring(parse_json(geo_info_from_ip_address(SampleRemoteIP)).country) 
| sort by DeviceCount asc
```
