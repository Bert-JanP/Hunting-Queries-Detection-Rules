# List recently found devices that can be onboarded

## Query Information

### Description
This query lists devices that can be onboarded to Defender For Endpoint and have recently been detected. You can determine what recently is by using the *RecentDetection* parameter.

#### Risk
Devices that are not onboarded can be misused without detection. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-machines-onboarding?view=o365-worldwide

## Defender For Endpoint
```KQL
let RecentDetection = 10d;
DeviceInfo
| where Timestamp > ago(RecentDetection)
| summarize arg_max(Timestamp, *) by DeviceId
| where OnboardingStatus == "Can be onboarded"
| summarize TotalDevices = dcount(DeviceId), DeviceNames = make_set(DeviceName) by OSPlatform, DeviceType
```
## Sentinel
```KQL
let RecentDetection = 10d;
DeviceInfo
| where TimeGenerated > ago(RecentDetection)
| summarize arg_max(TimeGenerated, *) by DeviceId
| where OnboardingStatus == "Can be onboarded"
| summarize TotalDevices = dcount(DeviceId), DeviceNames = make_set(DeviceName) by OSPlatform, DeviceType
```