# Net(1).exe Query Statistics

## Query Information

#### Description
This query can be used to list the statistics of the entities that have been queried in the last x days. The x is determined by the *StartTime* parameter. Only the (local)group and user query types are included in this query. This query can be used to list the user/groups that are often queried or to list rare discovery activities.

#### References
- https://learn.microsoft.com/en-us/windows/win32/winsock/net-exe-2
- https://www.trendmicro.com/en_us/research/19/f/shifting-tactics-breaking-down-ta505-groups-use-of-html-rats-and-other-techniques-in-latest-campaigns.html
- https://www.cybereason.com/blog/operation-cuckoobees-deep-dive-into-stealthy-winnti-techniques

## Defender XDR
```KQL
let StartTime = 30d;
DeviceProcessEvents
| where Timestamp > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS",
    ProcessCommandLine has "group", "GROUP",
    ProcessCommandLine has "user", "USER",
    ProcessCommandLine has "localgroup", "LOCALGROUP",
    "Other")
| where NetActionType != "Other"
| where isnotempty(AccountUpn)
| extend ExtractedParameters = split(ProcessCommandLine, " ")
| mv-apply QueriedEntity = ExtractedParameters on (
    where not(QueriedEntity has_any ("net", "net1", "user", "group", @"/do", @"/domain", @"/dom"))
    | project QueriedEntity
)
| where isnotempty(QueriedEntity)
| extend QueriedEntity = tolower(QueriedEntity)
| summarize arg_max(Timestamp, *) by ReportId
| summarize TotalQueries = count() by QueriedEntity, NetActionType
| sort by TotalQueries
```
## Sentinel
```KQL
let StartTime = 30d;
DeviceProcessEvents
| where TimeGenerated > startofday(ago(StartTime))
| where FileName in ("net.exe", "net1.exe")
| extend NetActionType = case(ProcessCommandLine has "accounts", "ACCOUNTS",
    ProcessCommandLine has "group", "GROUP",
    ProcessCommandLine has "user", "USER",
    ProcessCommandLine has "localgroup", "LOCALGROUP",
    "Other")
| where NetActionType != "Other"
| where isnotempty(AccountUpn)
| extend ExtractedParameters = split(ProcessCommandLine, " ")
| mv-apply QueriedEntity = ExtractedParameters on (
    where not(QueriedEntity has_any ("net", "net1", "user", "group", @"/do", @"/domain", @"/dom"))
    | project QueriedEntity
)
| where isnotempty(QueriedEntity)
| extend QueriedEntity = tolower(QueriedEntity)
| summarize arg_max(TimeGenerated, *) by ReportId
| summarize TotalQueries = count() by QueriedEntity, NetActionType
| sort by TotalQueries
```
