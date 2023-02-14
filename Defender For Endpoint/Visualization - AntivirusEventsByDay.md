# Antivirus Detections by day


### Defender For Endpoint

```
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(Timestamp, 1d)
| render linechart with(title="Antivirus Detections by Day")
```
### Sentinel
```
DeviceEvents
| where TimeGenerated > ago(30d)
| where ActionType == 'AntivirusDetection'
| summarize count() by bin(TimeGenerated, 1d)
| render linechart with(title="Antivirus Detections by Day")
```



