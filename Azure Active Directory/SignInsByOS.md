# Sign Ins by Operating System

This query can be used to detect rare operating systems that are used to sign into your tenant. For example your company only has Windows company devices and you have sign ins with MacOS, those can ben intersting to investigate.

### Sentinel
```
SigninLogs
| extend
     Browser = tostring(parse_json(DeviceDetail).browser),
     OS = tostring(parse_json(DeviceDetail).operatingSystem)
| summarize count() by OS
| sort by count_
```
