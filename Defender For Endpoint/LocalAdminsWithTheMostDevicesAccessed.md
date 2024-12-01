# Hunt for Local Admins with the most RemoteInteractive logins

## Query Information

#### Description
Hunt for Local Admins with the most RemoteInteractive logins

#### References
- https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types

## Defender XDR
```KQL
DeviceLogonEvents
| where IsLocalAdmin == "True"
| where LogonType == "RemoteInteractive"
| extend IsLocalLogon = tostring(todynamic(AdditionalFields).IsLocalLogon)
| summarize DevicesAccessed = make_set(DeviceName) by AccountName, AccountDomain
| extend TotalDevices = array_length(DevicesAccessed)
| sort by TotalDevices
```

## Sentinel
```KQL
DeviceLogonEvents
| where IsLocalAdmin == "True"
| where LogonType == "RemoteInteractive"
| extend IsLocalLogon = tostring(todynamic(AdditionalFields).IsLocalLogon)
| summarize DevicesAccessed = make_set(DeviceName) by AccountName, AccountDomain
| extend TotalDevices = array_length(DevicesAccessed)
| sort by TotalDevices
```
