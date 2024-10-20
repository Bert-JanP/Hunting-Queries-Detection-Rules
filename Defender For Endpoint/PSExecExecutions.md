# PsExec Usage

## Query Information

#### Description
PsExec is a tool that can be used to execute remote commands. This can be done in a benign way by admins, however attackers can also use this tool for various techniques. This query lists all the PsExec executions by the Device that triggerd the actions. This is not a detection rule, but a hunting rule that can be the start of an investigation why a specific device uses PsExec to run remote commands. The query will list the device that has initiated the remote commands, the devices it connected to and the commands that it has executed. 

The query contains a filter for devices that are configured to support remote commands. 

#### Risk
A actor uses PsExec to remotely run commands.

#### References
- https://attack.mitre.org/software/S0029/
- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.3
- https://www.cybereason.com/blog/research/operation-soft-cell-a-worldwide-campaign-against-telecommunications-providers

## Defender XDR
```
DeviceProcessEvents
// Collect all executed psexec commands
| where ProcessCommandLine contains "psexec.exe"
// Extract the remove device
| extend RemoteDevice = extract(@'\\\\(.*)c:', 1, ProcessCommandLine)
// If in your device onboarding Enable-PsRemoting is executed filter the line below
//| where not(ProcessCommandLine has_all ('powershell -command "Enable-PsRemoting -Force"', 'psexec.exe'))
// Collect stats and lists with remote devices and executed commands
| summarize TotalRemoteDevices = dcount(RemoteDevice), RemoteDeviceList = make_set(RemoteDevice), ExecutedCommands = make_set(ProcessCommandLine) by DeviceName
| sort by TotalRemoteDevices
```

## Sentinel
```
DeviceProcessEvents
// Collect all executed psexec commands
| where ProcessCommandLine contains "psexec.exe"
// Extract the remove device
| extend RemoteDevice = extract(@'\\\\(.*)c:', 1, ProcessCommandLine)
// If in your device onboarding Enable-PsRemoting is executed filter the line below
//| where not(ProcessCommandLine has_all ('powershell -command "Enable-PsRemoting -Force"', 'psexec.exe'))
// Collect stats and lists with remote devices and executed commands
| summarize TotalRemoteDevices = dcount(RemoteDevice), RemoteDeviceList = make_set(RemoteDevice), ExecutedCommands = make_set(ProcessCommandLine) by DeviceName
| sort by TotalRemoteDevices
```
