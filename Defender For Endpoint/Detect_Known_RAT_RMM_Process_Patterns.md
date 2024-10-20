# *Known RAT/RMM process patterns*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1219 | Remote Access Software | [Link](https://attack.mitre.org/techniques/T1219/) |

#### Description
Hypothesis: Attackers will eventually leverage legitimate desktop support and remote access tools (RATs) to establish an interactive command and control channel to target systems within networks. The patterns were based on this excelent resource and might need an update upon usage given that more patterns should have been added: https://github.com/0x706972686f/RMM-Catalogue 

Also, consider checking the additional resources and references below for getting inspired to create behavioral or anomaly based detection instead of simple pattern based, like this one.

#### Risk
The results will contain a summary table, listint the following columns: Unique RAT/RMM family, number of endpoints affected, list of those devices, processes and last time it was seen. The idea is to zoom in each family and also be able to focus on the unexpected families or most rare ones.

#### Author <Optional>
- **Name:** Alex Teixeira
- **Github:** https://github.com/inodee
- **Twitter:** https://x.com/ateixei
- **LinkedIn:** https://www.linkedin.com/in/inode
- **Website:** https://detect.fyi

#### References
- [Beyond IOCs: Contextualized Leads from Analytics-Driven Threat Hunts](https://detect.fyi/beyond-iocs-contextualized-leads-from-analytics-driven-threat-hunts-f5bfdc0d55d6)
- [RATs Race: Detecting remote access tools beyond pattern-based indicators](https://detect.fyi/rats-race-detecting-remote-access-tools-beyond-pattern-based-indicators-5c864b171892)


## Defender XDR
```KQL
// Author: Alex Teixeira (alex@opstune.com)
DeviceProcessEvents
| where Timestamp > ago(60d)
// Speed up the query by filtering most frequent processes
| where FolderPath matches regex @'(?i)^[a-z]:\\\S+\.exe' and not ((FolderPath contains "c:\\windows" and FolderPath matches regex @'(?i)microsoft\.net|softwaredistribution|system32|syswow64|ccm|servicing|winsxs') or FolderPath matches regex @'(?i)^(d:\\apps|c:\\_datas\\)')
// Normalize to frequent (known) RATs
| extend RAT=case(
  FolderPath contains "teamviewer", "TeamViewer",
  FolderPath contains "anydesk", "AnyDesk",
  FolderPath contains "rustdesk", "RustDesk",
  FolderPath contains "vnc", "VNC",
  FolderPath contains "manageengine", "ManageEngine",
  FolderPath contains "fastclient", "FastClient",
  FolderPath contains "logmein", "LogMeIn",
  FolderPath contains "bomgar", "Bomgar",
  FolderPath contains "netviewer", "NetViewer",
  FolderPath contains "ultraviewer", "UltraViewer",
  FolderPath contains "dwrcs", "Dameware",
  FolderPath contains "splashtop", "Splashtop",
  FolderPath contains "zerotier", "ZeroTier",
  FolderPath contains "supremo", "Supremo",
  "Other"
)
| summarize count(), count_distinct(DeviceName), make_set(DeviceName), max(Timestamp) by RAT, FolderPath
| extend r_1=@'(?i)[\\]+(NetWire|rport)[\\]+|Rsocx|BeAnywhere|DWservice|Fleetdeck|Itarian Endpoint Manager|Splashtop|Level\.io|ManageEngine|ScreenConnect|TrendMicro BaseCamp|Sorillus|ZeroTier|JollyFastVNC|AB Tutor|Barracuda Workplace|SolarWinds RMM|Naverisk'
| extend r_2=@'(?i)(NetSupport|TeamViewer|Anydesk|UltraViewer|realvnc|TightVNC|LogMeIn|fastclient|ultraVNC|bomgar.+scc|accessserver|aeroadmin|alitask|alpemix|ammyy|ateraagent|basupsrvc|basupsrvcupdate|basuptshelper|beamyourscreen|beanywhere|cagservice|chrome remote desktop|clientmrinit|connectwise|connectwisecontrol|crossloopservice|ctiserv|dameware|datto|domotz|dwrcs|dwservice|eratool|ericomconnnectconfigurationtool|ezhelpclient|fixmeit|fixmeitclient|fleetdeck|goverrmc|guacd|instanthousecall|intelliadmin|iperiusremote|islalwaysonmonitor|isllightservice|itarian|jumpclient|jumpdesktop|jumpservice|kaseya|landeskagentbootstrap|laplink|laplinkeverywhere|ldsensors|llrcservice|lmiignition|ltsvcmon|mgntsvc|mikogo|mionet|myivomanager|nateon|neturo|netviewer|nhostsvc|ntrntservice|orcus|pcaquickconnect|pcstarter|pcvisit|pocketcontroller|ptdskclient|pulseway|rcengmgru|rcmgrsvc|rdpwrap|remobo|remote utilities|remoteconsole|remotepass|remotepc|remotepcservice|remotesupportplayeru|remoteview|rfusclient|romfusclient|romserver|romviewer|rpaccess|rpcgrab|rpcsetup|rpcsuite|rpwhostscr|rustdesk|rutserv|rutview|rxstartsupport|screenconnect|seetrolclient|seetrolremote|serverproxyservice|showmypc|simplehelpcustomer|simpleservice|sorillus|sragent|supremo|supremohelper|syncro|tacticalrmm|take\s*control|tdp2tcp|tigervnc|trend.+basecamp|turbomeeting|ultraviewer|vncconnect|webex remote|webrdp|weezo|weezohttpd|windows admin centre|wmcsvc|zerotier|zoho assist).*\.exe$'
| extend r_3=@'(?i)\\(baseclient|BASupApp|DWAgent|ITSMAgent|level|Atera|radmin|srserver|rvagent|intouch)\.exe$'
| where (FolderPath matches regex r_1 or FolderPath matches regex r_2 or FolderPath matches regex r_3)
| extend set_DeviceName=iff(count_distinct_DeviceName>5, strcat("Too many (", count_distinct_DeviceName, ")"), set_DeviceName)
| summarize TotalEvents=sum(count_), DeviceCount=count_distinct(set_DeviceName), Devices=make_set(set_DeviceName), Processes=make_set(FolderPath), LastSeen=max(max_Timestamp) by RAT
| sort by DeviceCount desc, TotalEvents desc

```
## Sentinel
```KQL
// Author: Alex Teixeira (alex@opstune.com)
DeviceProcessEvents
| where TimeGenerated > ago(60d)
// Speed up the query by filtering most frequent processes
| where FolderPath matches regex @'(?i)^[a-z]:\\\S+\.exe' and not ((FolderPath contains "c:\\windows" and FolderPath matches regex @'(?i)microsoft\.net|softwaredistribution|system32|syswow64|ccm|servicing|winsxs') or FolderPath matches regex @'(?i)^(d:\\apps|c:\\_datas\\)')
// Normalize to frequent (known) RATs
| extend RAT=case(
  FolderPath contains "teamviewer", "TeamViewer",
  FolderPath contains "anydesk", "AnyDesk",
  FolderPath contains "rustdesk", "RustDesk",
  FolderPath contains "vnc", "VNC",
  FolderPath contains "manageengine", "ManageEngine",
  FolderPath contains "fastclient", "FastClient",
  FolderPath contains "logmein", "LogMeIn",
  FolderPath contains "bomgar", "Bomgar",
  FolderPath contains "netviewer", "NetViewer",
  FolderPath contains "ultraviewer", "UltraViewer",
  FolderPath contains "dwrcs", "Dameware",
  FolderPath contains "splashtop", "Splashtop",
  FolderPath contains "zerotier", "ZeroTier",
  FolderPath contains "supremo", "Supremo",
  "Other"
)
| summarize count(), count_distinct(DeviceName), make_set(DeviceName), max(TimeGenerated) by RAT, FolderPath
| extend r_1=@'(?i)[\\]+(NetWire|rport)[\\]+|Rsocx|BeAnywhere|DWservice|Fleetdeck|Itarian Endpoint Manager|Splashtop|Level\.io|ManageEngine|ScreenConnect|TrendMicro BaseCamp|Sorillus|ZeroTier|JollyFastVNC|AB Tutor|Barracuda Workplace|SolarWinds RMM|Naverisk'
| extend r_2=@'(?i)(NetSupport|TeamViewer|Anydesk|UltraViewer|realvnc|TightVNC|LogMeIn|fastclient|ultraVNC|bomgar.+scc|accessserver|aeroadmin|alitask|alpemix|ammyy|ateraagent|basupsrvc|basupsrvcupdate|basuptshelper|beamyourscreen|beanywhere|cagservice|chrome remote desktop|clientmrinit|connectwise|connectwisecontrol|crossloopservice|ctiserv|dameware|datto|domotz|dwrcs|dwservice|eratool|ericomconnnectconfigurationtool|ezhelpclient|fixmeit|fixmeitclient|fleetdeck|goverrmc|guacd|instanthousecall|intelliadmin|iperiusremote|islalwaysonmonitor|isllightservice|itarian|jumpclient|jumpdesktop|jumpservice|kaseya|landeskagentbootstrap|laplink|laplinkeverywhere|ldsensors|llrcservice|lmiignition|ltsvcmon|mgntsvc|mikogo|mionet|myivomanager|nateon|neturo|netviewer|nhostsvc|ntrntservice|orcus|pcaquickconnect|pcstarter|pcvisit|pocketcontroller|ptdskclient|pulseway|rcengmgru|rcmgrsvc|rdpwrap|remobo|remote utilities|remoteconsole|remotepass|remotepc|remotepcservice|remotesupportplayeru|remoteview|rfusclient|romfusclient|romserver|romviewer|rpaccess|rpcgrab|rpcsetup|rpcsuite|rpwhostscr|rustdesk|rutserv|rutview|rxstartsupport|screenconnect|seetrolclient|seetrolremote|serverproxyservice|showmypc|simplehelpcustomer|simpleservice|sorillus|sragent|supremo|supremohelper|syncro|tacticalrmm|take\s*control|tdp2tcp|tigervnc|trend.+basecamp|turbomeeting|ultraviewer|vncconnect|webex remote|webrdp|weezo|weezohttpd|windows admin centre|wmcsvc|zerotier|zoho assist).*\.exe$'
| extend r_3=@'(?i)\\(baseclient|BASupApp|DWAgent|ITSMAgent|level|Atera|radmin|srserver|rvagent|intouch)\.exe$'
| where (FolderPath matches regex r_1 or FolderPath matches regex r_2 or FolderPath matches regex r_3)
| extend set_DeviceName=iff(count_distinct_DeviceName>5, strcat("Too many (", count_distinct_DeviceName, ")"), set_DeviceName)
| summarize TotalEvents=sum(count_), DeviceCount=count_distinct(set_DeviceName), Devices=make_set(set_DeviceName), Processes=make_set(FolderPath), LastSeen=max(max_Timestamp) by RAT
| sort by DeviceCount desc, TotalEvents desc
| sort by DeviceCount asc
```
