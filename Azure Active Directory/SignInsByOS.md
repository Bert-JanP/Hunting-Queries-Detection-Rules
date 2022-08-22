# Sign Ins by Operating System
----
### Sentinel
```
SigninLogs
| extend
     Browser = tostring(parse_json(DeviceDetail).browser),
     OS = tostring(parse_json(DeviceDetail).operatingSystem)
| summarize count() by OS
| sort by count_
```
