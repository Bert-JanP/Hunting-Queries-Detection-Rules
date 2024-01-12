# APT28 Commands

## Query Information

#### Description
This KQL query can be used to hunt for APT 28 commands in your environment. The *threshold* can be used to adjust the amount of unique executed APT28 commands to be found within the defined *BinSize*, the *BinSize* is the timeframe in which the *threshold* needs to be reached. All the calculations are done for each device. The more APT28 commands are found on a device, the more likely it is that the device has been compromised. 

#### Risk
APT28 has gotten access to one of your devices and executes malicious payloads. 

#### References
- https://cert.gov.ua/article/6276894

## Defender For Endpoint
```KQL
let APT28Commands = dynamic(['Get-Content', '-w hid -nop', '-windowstyle hidden -encodedCommand', 'start-process ssh.exe', 'Get-Content -Encoding', 'Compress-Archive', 'Get-WinEvent -FilterHashtable', 'net time', 'Get-ADDomainController', 'Get-DnsClientServerAddress', 'Get-NetAdapter', 'Get-NetAdapterBinding', 'Get-NetIPConfiguration', 'Resolve-DNSName', 'ipconfig /flushdns', 'net start dnscache', 'net stop dnscache']);
let Threshold = 3;
let BinSize = 1d;
DeviceProcessEvents
| where ProcessCommandLine has_any (APT28Commands)
| extend CommandParameter = case(ProcessCommandLine contains "Get-Content", "Get-Content",
                                ProcessCommandLine contains "-w hid -nop", "-w hid -nop",
                                ProcessCommandLine contains "-windowstyle hidden -encodedCommand", "-windowstyle hidden -encodedCommand",
                                ProcessCommandLine contains "start-process ssh.exe", "start-process ssh.exe",
                                ProcessCommandLine contains "Get-Content -Encoding", "Get-Content -Encoding",
                                ProcessCommandLine contains "Compress-Archive", "Compress-Archive",
                                ProcessCommandLine contains "Get-WinEvent -FilterHashtable", "Get-WinEvent -FilterHashtable",
                                ProcessCommandLine contains "net time", "net time",
                                ProcessCommandLine contains "Get-ADDomainController", "Get-ADDomainController",
                                ProcessCommandLine contains "Get-DnsClientServerAddress", "Get-DnsClientServerAddress",
                                ProcessCommandLine contains "Get-NetAdapter", "Get-NetAdapter",
                                ProcessCommandLine contains "Get-NetAdapterBinding", "Get-NetAdapterBinding",
                                ProcessCommandLine contains "Get-NetIPConfiguration", "Get-NetIPConfiguration",
                                ProcessCommandLine contains "Resolve-DNSName", "Resolve-DNSName",
                                ProcessCommandLine contains "ipconfig /flushdns", "ipconfig /flushdns",
                                ProcessCommandLine contains "net start dnscache", "net start dnscache",
                                ProcessCommandLine contains "net stop dnscache", "net stop dnscache",
                                "Other")
| summarize UniqueATP28Commands = dcount(CommandParameter), APT28CommandParameters = make_set(CommandParameter), UniqueCommands = dcount(ProcessCommandLine), Commandlines = make_set(ProcessCommandLine) by DeviceId, DeviceName, bin(Timestamp, BinSize)
| where UniqueATP28Commands >= Threshold
```
## Sentinel
```KQL
let APT28Commands = dynamic(['Get-Content', '-w hid -nop', '-windowstyle hidden -encodedCommand', 'start-process ssh.exe', 'Get-Content -Encoding', 'Compress-Archive', 'Get-WinEvent -FilterHashtable', 'net time', 'Get-ADDomainController', 'Get-DnsClientServerAddress', 'Get-NetAdapter', 'Get-NetAdapterBinding', 'Get-NetIPConfiguration', 'Resolve-DNSName', 'ipconfig /flushdns', 'net start dnscache', 'net stop dnscache']);
let Threshold = 3;
let BinSize = 1d;
DeviceProcessEvents
| where ProcessCommandLine has_any (APT28Commands)
| extend CommandParameter = case(ProcessCommandLine contains "Get-Content", "Get-Content",
                                ProcessCommandLine contains "-w hid -nop", "-w hid -nop",
                                ProcessCommandLine contains "-windowstyle hidden -encodedCommand", "-windowstyle hidden -encodedCommand",
                                ProcessCommandLine contains "start-process ssh.exe", "start-process ssh.exe",
                                ProcessCommandLine contains "Get-Content -Encoding", "Get-Content -Encoding",
                                ProcessCommandLine contains "Compress-Archive", "Compress-Archive",
                                ProcessCommandLine contains "Get-WinEvent -FilterHashtable", "Get-WinEvent -FilterHashtable",
                                ProcessCommandLine contains "net time", "net time",
                                ProcessCommandLine contains "Get-ADDomainController", "Get-ADDomainController",
                                ProcessCommandLine contains "Get-DnsClientServerAddress", "Get-DnsClientServerAddress",
                                ProcessCommandLine contains "Get-NetAdapter", "Get-NetAdapter",
                                ProcessCommandLine contains "Get-NetAdapterBinding", "Get-NetAdapterBinding",
                                ProcessCommandLine contains "Get-NetIPConfiguration", "Get-NetIPConfiguration",
                                ProcessCommandLine contains "Resolve-DNSName", "Resolve-DNSName",
                                ProcessCommandLine contains "ipconfig /flushdns", "ipconfig /flushdns",
                                ProcessCommandLine contains "net start dnscache", "net start dnscache",
                                ProcessCommandLine contains "net stop dnscache", "net stop dnscache",
                                "Other")
| summarize UniqueATP28Commands = dcount(CommandParameter), APT28CommandParameters = make_set(CommandParameter), UniqueCommands = dcount(ProcessCommandLine), Commandlines = make_set(ProcessCommandLine) by DeviceId, DeviceName, bin(TimeGenerated, BinSize)
| where UniqueATP28Commands >= Threshold
```