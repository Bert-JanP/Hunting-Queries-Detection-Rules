# Sentinel Workspace Disconnected

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.008 | Impair Defenses: Disable or Modify Cloud Logs | https://attack.mitre.org/techniques/T1562/008/ |

### Description
This query returns results if Sentinel workspaces have been removed from Unified XDR. These activities should be monitored to make sure that sentinel environments are not by mistakenly or purposely removed from your XDR environment.

### References
- https://kqlquery.com/posts/audit-defender-xdr/
- https://learn.microsoft.com/en-us/unified-secops/microsoft-sentinel-onboard

## Defender XDR
```KQL
CloudAppEvents
| where ActionType == "SentinelDisconnectWorkspace"
| extend WorkspaceId = tostring(RawEventData.WorkspaceId), Status = tostring(RawEventData.Status), SubscriptionId = tostring(RawEventData.SubscriptionId), ResourceGroup = tostring(RawEventData.ResourceGroup), WorkspaceType = tostring(RawEventData.WorkspaceType)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder Timestamp, InitiatedByAccountName, InitiatedByAccounttId, IPAddress, WorkspaceType, Status, WorkspaceId, ResourceGroup, SubscriptionId
```

## Sentinel
```KQL
CloudAppEvents
| where ActionType == "SentinelDisconnectWorkspace"
| extend WorkspaceId = tostring(RawEventData.WorkspaceId), Status = tostring(RawEventData.Status), SubscriptionId = tostring(RawEventData.SubscriptionId), ResourceGroup = tostring(RawEventData.ResourceGroup), WorkspaceType = tostring(RawEventData.WorkspaceType)
| project-rename InitiatedByAccountName = AccountDisplayName, InitiatedByAccounttId = AccountId
| project-reorder TimeGenerated, InitiatedByAccountName, InitiatedByAccounttId, IPAddress, WorkspaceType, Status, WorkspaceId, ResourceGroup, SubscriptionId
```
