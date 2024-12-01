# List Connected USB Devices

## Query Information

#### Description
This query lists the statistics of all the connected USB devices and their description. This overview gives you an indication of what USB devices are connected to workstations/servers in your network. This can be used to create specific detections on USB connections. 

You can filter on the description by adding:
```KQL
| where DeviceDescription has "ios"
```

#### References
- https://learn.microsoft.com/en-us/powershell/module/pnpdevice/?view=windowsserver2022-ps
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/advanced-hunting-updates-usb-events-machine-level-actions-and/ba-p/824152

## Defender XDR
```KQL
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend PNPInfo = parse_json(AdditionalFields)
| extend ClassName = tostring(PNPInfo.ClassName), DeviceDescription = tostring(PNPInfo.DeviceDescription), VendorIds = tostring(PNPInfo.VendorIds), DeviceId = tostring(PNPInfo.DeviceId)
| extend PnPType = tostring(split(DeviceId, @"\", 0)[0])
| where PnPType == "USB"
| project-reorder ClassName, PnPType, DeviceDescription, VendorIds, DeviceId
| summarize TotalEvents = count() by DeviceDescription
| sort by TotalEvents
```
## Sentinel
```KQL
DeviceEvents
| where ActionType == "PnpDeviceConnected"
| extend PNPInfo = parse_json(AdditionalFields)
| extend ClassName = tostring(PNPInfo.ClassName), DeviceDescription = tostring(PNPInfo.DeviceDescription), VendorIds = tostring(PNPInfo.VendorIds), DeviceId = tostring(PNPInfo.DeviceId)
| extend PnPType = tostring(split(DeviceId, @"\", 0)[0])
| where PnPType == "USB"
| project-reorder ClassName, PnPType, DeviceDescription, VendorIds, DeviceId
| summarize TotalEvents = count() by DeviceDescription
| sort by TotalEvents
```
