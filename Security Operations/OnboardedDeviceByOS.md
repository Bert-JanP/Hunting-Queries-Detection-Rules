# Statistics onboarded devices (OS)

## Query Information

#### Description
This query lists how many devices have been onboarded per operating system.

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/onboard-configure?view=o365-worldwide

## Defender For Endpoint
```KQL
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId
| summarize TotalDevices = count() by OSPlatform
```
## Sentinel
```KQL
DeviceInfo
| where OnboardingStatus == "Onboarded"
| summarize arg_max(Timestamp, *) by DeviceId
| summarize TotalDevices = count() by OSPlatform
```