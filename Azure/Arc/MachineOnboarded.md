# Machine Onboarded Azure Arc

## Query Information

#### Description
Lists the onboarded machines to Azure Arc. The HostName is the hostname that is used within Azure and Defender For Endpoint, this may differ from the actual hostname of the local system.

## Sentinel
```KQL
AzureActivity
| where OperationNameValue =~ "MICROSOFT.HYBRIDCOMPUTE/MACHINES/WRITE"
| where ActivityStatusValue =~ "Success"
| extend HostName = tostring(parse_json(Properties).resource)
| project-reorder TimeGenerated, Caller, HostName, ResourceGroup
```