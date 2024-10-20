# List Tampering Attempts

## Query Information

#### Description
This query lists all the tampering attempts that have been observed by each device. This means that tampering protection acted and blocked the action. The action may be suspicious itself. The rule will generate false positives, which need filtering based on your environment. 

#### Risk
An adversary tries to disable security logging / monitoring to perform malicious activities undetected. 

#### References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection?view=o365-worldwide

## Defender XDR
```
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction), Status = tostring(parse_json(AdditionalFields).Status), Target = tostring(parse_json(AdditionalFields).Target)
| summarize TotalActions = count(), Actions = make_set(TamperingAction), Targets = make_set(Target), RegistryNames = make_set(RegistryValueName), InitatingCommandLine = make_set(InitiatingProcessCommandLine) by DeviceName
```
## Sentinel
```
DeviceEvents
| where ActionType == "TamperingAttempt"
| extend TamperingAction = tostring(parse_json(AdditionalFields).TamperingAction), Status = tostring(parse_json(AdditionalFields).Status), Target = tostring(parse_json(AdditionalFields).Target)
| summarize TotalActions = count(), Actions = make_set(TamperingAction), Targets = make_set(Target), RegistryNames = make_set(RegistryValueName), InitatingCommandLine = make_set(InitiatingProcessCommandLine) by DeviceName
```
