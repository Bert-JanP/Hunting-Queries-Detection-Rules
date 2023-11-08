# Antivirus Detections by day

#### Description
This query visualizes the daily antivirus detections, which can give an indication in anomalous amount of activities that are performed in your environment. 


## Defender For Endpoint
```KQL
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(Timestamp, 1d)
| render linechart with(title="Antivirus Detections by Day")
```
## Sentinel
```KQL
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(TimeGenerated, 1d)
| render linechart with(title="Antivirus Detections by Day")
```



