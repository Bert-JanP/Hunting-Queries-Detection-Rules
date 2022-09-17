# Detect the amount of ASR events that have been triggered for each device 

### Defender For Endpoint

```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
### Sentinel
```
DeviceEvents
| where ActionType startswith "Asr"
| summarize count() by DeviceName
| sort by count_
```
