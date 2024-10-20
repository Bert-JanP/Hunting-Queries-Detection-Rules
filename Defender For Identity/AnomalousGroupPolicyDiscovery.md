# Anomalous Group Policy Discovery

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1615 | Group Policy Discovery|https://attack.mitre.org/techniques/T1615|

#### Description
Adversaries may gather information on Group Policy settings to identify paths for privilege escalation, security measures applied within a domain, and to discover patterns in domain objects that can be manipulated or used to blend in the environment. Group policies may contain valueble information for an attacker. This query detects when an device performs an group policy Discovery that has not been performed from that device in the last 30 days.

Potential false positive is a new Administrator that has not performed group policy discovery before. 

#### Risk
An attacker queries Group Policy object to gain valuable information about the environment. 

## Defender For Endpoint
```KQL
let PreviousActivity = materialize (
     IdentityQueryEvents
     | where Timestamp > ago(30d)
     | where QueryType == "AllGroupPolicies"
     | summarize make_set(DeviceName)
     );
IdentityQueryEvents
| where Timestamp > ago(1d)
| where QueryType == "AllGroupPolicies"
| where not(DeviceName has_any(PreviousActivity))
```
## Sentinel
```KQL
let PreviousActivity = materialize (
     IdentityQueryEvents
     | where TimeGenerated > ago(30d)
     | where QueryType == "AllGroupPolicies"
     | summarize make_set(DeviceName)
     );
IdentityQueryEvents
| where TimeGenerated > ago(1d)
| where QueryType == "AllGroupPolicies"
| where not(DeviceName has_any(PreviousActivity))
```



