# Visualize the devices in the defined machinegroups

In order to get results the device groups need to be defined: [MS Documentation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/machine-groups?view=o365-worldwide)

## Defender XDR

```
DeviceInfo
| summarize dcount(DeviceName) by MachineGroup
| sort by dcount_DeviceName
| render columnchart with(title="Total Devices by MachineGroup")
```
## Sentinel
```
DeviceInfo
| summarize dcount(DeviceName) by MachineGroup
| sort by dcount_DeviceName
| render columnchart with(title="Total Devices by MachineGroup")
```



