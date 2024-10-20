# KQLSearch Visits

## Query Information

#### Description
Visualize the visits to [kqlsearch.com](kqlsearch.com) in a columnchart.

#### References
- https://www.kqlsearch.com/

## Defender XDR
```KQL
DeviceNetworkEvents
| where RemoteUrl has "kqlsearch.com"
| summarize TotalDevices = dcount(DeviceId) by bin(Timestamp, 1d)
| render columnchart with(title="KQLSearch.com visits", xtitle="Date", ytitle="TotalDevices")
```
## Sentinel
```KQL
DeviceNetworkEvents
| where RemoteUrl has "kqlsearch.com"
| summarize TotalDevices = dcount(DeviceId) by bin(TimeGenerated, 1d)
| render columnchart with(title="KQLSearch.com visits", xtitle="Date", ytitle="TotalDevices")
```
