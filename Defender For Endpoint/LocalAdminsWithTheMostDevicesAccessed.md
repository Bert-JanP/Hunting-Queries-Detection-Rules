# Hunt for Local Admins with the most RemoteInteractive logins
----
### Defender XDR

```
DeviceLogonEvents
| where IsLocalAdmin == "True"
| where LogonType == "RemoteInteractive"
| extend IsLocalLogon = tostring(todynamic(AdditionalFields).IsLocalLogon)
| summarize DevicesAccessed = make_set(DeviceName) by AccountName, AccountDomain
| extend TotalDevices = array_length(DevicesAccessed)
| sort by TotalDevices
```
### Sentinel
```
DeviceLogonEvents
| where IsLocalAdmin == "True"
| where LogonType == "RemoteInteractive"
| extend IsLocalLogon = tostring(todynamic(AdditionalFields).IsLocalLogon)
| summarize DevicesAccessed = make_set(DeviceName) by AccountName, AccountDomain
| extend TotalDevices = array_length(DevicesAccessed)
| sort by TotalDevices
```



