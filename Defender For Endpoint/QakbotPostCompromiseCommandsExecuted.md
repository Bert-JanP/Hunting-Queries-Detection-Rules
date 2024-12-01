# Detect when multiple Qakbot post compromise commands have been executed

## Query Information

#### Description
Detect when multiple Qakbot post compromise commands have been executed.

## Defender XDR
```KQL
let QakBotCommands = dynamic(['net view', 'cmd /c set', 'arp -a', 'ipconfig /all', 'nslookup-querytype=ALL -timeout=12', '_ldap._tcp.dc._msdcs.WORKGROUP', 'net share', 'net1 share', 'route print', 'net localgroup', 'whoami /all']); // source: https://twitter.com/1ZRR4H/status/1568395544359309312
DeviceProcessEvents
| where ProcessCommandLine has_any(QakBotCommands)
| summarize TotalCommandsFound = count(), CommandLineList = make_set(ProcessCommandLine) by DeviceName, AccountName
| extend TotalUniqueCommandsFound = array_length(CommandLineList)
| where TotalUniqueCommandsFound > 3 // Adjust to reduce false positives
| sort by TotalUniqueCommandsFound, TotalCommandsFound
```

## Sentinel
```KQL
let QakBotCommands = dynamic(['net view', 'cmd /c set', 'arp -a', 'ipconfig /all', 'nslookup-querytype=ALL -timeout=12', '_ldap._tcp.dc._msdcs.WORKGROUP', 'net share', 'net1 share', 'route print', 'net localgroup', 'whoami /all']); // source: https://twitter.com/1ZRR4H/status/1568395544359309312
DeviceProcessEvents
| where ProcessCommandLine has_any(QakBotCommands)
| summarize TotalCommandsFound = count(), CommandLineList = make_set(ProcessCommandLine) by DeviceName, AccountName
| extend TotalUniqueCommandsFound = array_length(CommandLineList)
| where TotalUniqueCommandsFound > 3 // Adjust to reduce false positives
| sort by TotalUniqueCommandsFound, TotalCommandsFound
```

