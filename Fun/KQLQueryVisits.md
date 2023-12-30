# KQLQuery Visits

## Query Information

#### Description
Visualize the visits to [KQLQuery.com](KQLQuery.com) in a columnchart.

#### References
- https://www.KQLQuery.com/

## Defender For Endpoint
```KQL
DeviceNetworkEvents
| where RemoteUrl has "kqlquery.com"
| summarize TotalDevices = dcount(DeviceId) by bin(Timestamp, 1d)
| render columnchart with(title="kqlquery.com visits", xtitle="Date", ytitle="TotalDevices")
```
## Sentinel
```KQL
DeviceNetworkEvents
| where RemoteUrl has "kqlquery.com"
| summarize TotalDevices = dcount(DeviceId) by bin(TimeGenerated, 1d)
| render columnchart with(title="kqlquery.com visits", xtitle="Date", ytitle="TotalDevices")
```