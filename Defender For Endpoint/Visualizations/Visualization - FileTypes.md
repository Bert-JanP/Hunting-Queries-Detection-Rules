# Visualize FileTypes based on DeviceFileEvents

## Defender XDR

```
let TimeFrame = 7d;
DeviceFileEvents
| where Timestamp > ago(TimeFrame)
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
| where isnotempty(FileType)
| summarize Total = count() by FileType
| render piechart with(title="FileTypes used")
```
## Sentinel
```
let TimeFrame = 7d;
DeviceFileEvents
| where Timestamp > ago(TimeFrame)
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
| where isnotempty(FileType)
| summarize Total = count() by FileType
| render piechart with(title="FileTypes used")
```



