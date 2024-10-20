# Connected PnP types

## Query Information

#### Description
List the different Plug and Play (PnP) device types that are used in your organisation. The results are sorted by the total ammount of events seen for each type.

#### References
- https://learn.microsoft.com/en-us/powershell/module/pnpdevice/?view=windowsserver2022-ps

## Defender XDR
```KQL
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend PNPInfo = parse_json(AdditionalFields)
| extend ClassName = tostring(PNPInfo.ClassName), DeviceDescription = tostring(PNPInfo.DeviceDescription), VendorIds = tostring(PNPInfo.VendorIds), DeviceId = tostring(PNPInfo.DeviceId)
| extend PnPType = tostring(split(DeviceId, @"\", 0)[0])
| summarize Total = count() by PnPType
| sort by Total
```
## Sentinel
```KQL
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend PNPInfo = parse_json(AdditionalFields)
| extend ClassName = tostring(PNPInfo.ClassName), DeviceDescription = tostring(PNPInfo.DeviceDescription), VendorIds = tostring(PNPInfo.VendorIds), DeviceId = tostring(PNPInfo.DeviceId)
| extend PnPType = tostring(split(DeviceId, @"\", 0)[0])
| summarize Total = count() by PnPType
| sort by Total
```
