# IPv4 command detected in lolbin execution

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218 | System Binary Proxy Execution | https://attack.mitre.org/techniques/T1218/ |

#### Description
This query returns all LOLbins that refer to a remote IP in the commandline. These remote IPs can be used to make connections for lateral movement or to remotely upload or download files.

#### References
- https://lolbas-project.github.io/

## Defender XDR
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let LOLBins = dynamic(["AppInstaller.exe", "cmd.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LOLBins)
| extend CommandLineIP = extract(IPRegex, 0, InitiatingProcessCommandLine)
| where isnotempty(CommandLineIP)
// Optional filter to only filter for public ips.
//| where not(ipv4_is_private(RemoteIP))
| project-reorder Timestamp, InitiatingProcessCommandLine, RemoteIP, DeviceName
```
## Sentinel
```KQL
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
let LOLBins = dynamic(["AppInstaller.exe", "cmd.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
DeviceNetworkEvents
| where InitiatingProcessFileName in~ (LOLBins)
| extend CommandLineIP = extract(IPRegex, 0, InitiatingProcessCommandLine)
| where isnotempty(CommandLineIP)
// Optional filter to only filter for public ips.
//| where not(ipv4_is_private(RemoteIP))
| project-reorder TimeGenerated, InitiatingProcessCommandLine, RemoteIP, DeviceName
```

