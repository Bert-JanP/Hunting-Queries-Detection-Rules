# New LOLBIN with external connection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218 | System Binary Proxy Execution | https://attack.mitre.org/techniques/T1218/ |

#### Description
This query searches for new lolbins that have executed external connections. This is done by first listing all lolbins that are known to execute external connections, for example msedge.exe will (of course) trigger external connections. With this query you can list rare lolbins which are uncommon to trigger external connections. The list of LOLBINS is based on the lolbas project. 

To further improve this detection you could split up this query for workstations and servers, this will most likely improve the detection / hunt. 
Note: Defender For Endpoint has 30 days to lookup previously used lolbins with external connections, sentinel uses 90 days. 

The *ExcludedLolBins* variable can be used to exclude certain lolbins that often trigger false positives, such as msedge.

#### Risk
An actor has gained access to your network and uses a rare lolbin to communicate to its own infrastructure. 

#### References
- https://lolbas-project.github.io/

## Defender XDR
```KQL
let LOLBins = dynamic(["AppInstaller.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
let ExcludedLolBins = dynamic(["Msedge.exe"]);
// List all lolbins that have made remote connection to public IPs between the last 30 and 2 days.
let KnownRemoteLolbins =
DeviceNetworkEvents
| where Timestamp between (ago(30d) .. ago(2d))
| where InitiatingProcessFileName in~ (LOLBins) and InitiatingProcessFileName !in~ (ExcludedLolBins)
// Only list public IP actions.
| where RemoteIPType == "Public"
| distinct InitiatingProcessFileName;
DeviceNetworkEvents
| where Timestamp > ago(2d)
// Filter KnownRemoteLolbins
| where InitiatingProcessFileName in~ (LOLBins) and InitiatingProcessFileName !in~ (ExcludedLolBins) and not(InitiatingProcessFileName in~ (KnownRemoteLolbins))
| where RemoteIPType == "Public"
// Enrich IP Information
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder Timestamp, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
```

## Sentinel
```KQL
let LOLBins = dynamic(["AppInstaller.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
let ExcludedLolBins = dynamic(["Msedge.exe"]);
// List all lolbins that have made remote connection to public IPs between the last 30 and 2 days.
let KnownRemoteLolbins =
DeviceNetworkEvents
| where TimeGenerated between (ago(90d) .. ago(2d))
| where InitiatingProcessFileName in~ (LOLBins) and InitiatingProcessFileName !in~ (ExcludedLolBins)
// Only list public IP actions.
| where RemoteIPType == "Public"
| distinct InitiatingProcessFileName;
DeviceNetworkEvents
| where TimeGenerated > ago(2d)
// Filter KnownRemoteLolbins
| where InitiatingProcessFileName in~ (LOLBins) and InitiatingProcessFileName !in~ (ExcludedLolBins) and not(InitiatingProcessFileName in~ (KnownRemoteLolbins))
| where RemoteIPType == "Public"
// Enrich IP Information
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder TimeGenerated, DeviceName, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
```


