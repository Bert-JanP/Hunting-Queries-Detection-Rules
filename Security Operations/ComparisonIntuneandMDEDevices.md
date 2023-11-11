# Comparison between devices in Intune and MDE

## Query Information

#### Description
This query lists the devices that are onboarded in Intune and classifies them based on the status of Defender For Endpoint. You can select your own *SearchPeriod* in this query. The MDE data is based on a process activities seen in the search window, if that is the case then the device is classified as *MDE Onboarded*. This can help determine which devices have not yet been onboarded to MDE.

### References
- https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/intunedevices

## Sentinel
```KQL
let SearchPeriod = 30d;
let MDEDevices = DeviceProcessEvents
    | where TimeGenerated > ago(SearchPeriod)
    | extend DeviceNameWithoutDomain = tostring(split(DeviceName, ".", 0)[0])
    | distinct DeviceNameWithoutDomain;
IntuneDevices
| where todatetime(LastContact) > ago(SearchPeriod)
| summarize arg_max(TimeGenerated, DeviceName, LastContact) by DeviceId
| extend MDEStatus = iff(DeviceName in~ (MDEDevices), "MDE Onboarded", "Not Onboarded")
| summarize Total = count(), Devices = make_set(DeviceName) by MDEStatus
```