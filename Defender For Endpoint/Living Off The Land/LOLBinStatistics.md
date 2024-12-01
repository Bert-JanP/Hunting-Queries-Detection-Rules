# Statistics LOLBIN usage

## Query Information

#### Description
List the the statistics of LOLBINS that have been executed. Mostly the rare lolbins are most interesting to why and whom executed them. The list of LOLBINS is based on the lolbas project. 

#### References
- https://lolbas-project.github.io/

## Defender XDR
```KQL
let LOLBins = dynamic(["AppInstaller.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (LOLBins)
| summarize TotalExecutions = count() by InitiatingProcessFileName
| sort by TotalExecutions
```
## Sentinel
```KQL
let LOLBins = dynamic(["AppInstaller.exe", "Aspnet_Compiler.exe", "At.exe", "Atbroker.exe", "Bash.exe", "Bitsadmin.exe", "CertOC.exe", "CertReq.exe", "Certutil.exe", "Cmd.exe", "Cmdkey.exe", "cmdl32.exe", "Cmstp.exe", "ConfigSecurityPolicy.exe", "Conhost.exe", "Control.exe", "Csc.exe", "Cscript.exe", "CustomShellHost.exe", "DataSvcUtil.exe", "Desktopimgdownldr.exe", "DeviceCredentialDeployment.exe", "Dfsvc.exe", "Diantz.exe", "Diskshadow.exe", "Dnscmd.exe", "Esentutl.exe", "Eventvwr.exe", "Expand.exe", "Explorer.exe", "Extexport.exe", "Extrac32.exe", "Findstr.exe", "Finger.exe", "fltMC.exe", "Forfiles.exe", "Ftp.exe", "Gpscript.exe", "Hh.exe", "IMEWDBLD.exe", "Ie4uinit.exe", "Ieexec.exe", "Ilasm.exe", "Infdefaultinstall.exe", "Installutil.exe", "Jsc.exe", "Ldifde.exe", "Makecab.exe", "Mavinject.exe", "Msedge.exe", "Microsoft.Workflow.Compiler.exe", "Mmc.exe", "MpCmdRun.exe", "Msbuild.exe", "Msconfig.exe", "Msdt.exe", "Mshta.exe", "Msiexec.exe", "Netsh.exe", "Odbcconf.exe", "OfflineScannerShell.exe", "OneDriveStandaloneUpdater.exe", "Pcalua.exe", "Pcwrun.exe", "Pktmon.exe", "Pnputil.exe", "Presentationhost.exe", "Print.exe", "PrintBrm.exe", "Psr.exe", "Rasautou.exe", "rdrleakdiag.exe", "Reg.exe", "Regasm.exe", "Regedit.exe", "Regini.exe", "Register-cimprovider.exe", "Regsvcs.exe", "Regsvr32.exe", "Replace.exe", "Rpcping.exe", "Rundll32.exe", "Runexehelper.exe", "Runonce.exe", "Runscripthelper.exe", "Sc.exe", "Schtasks.exe", "Scriptrunner.exe", "Setres.exe", "SettingSyncHost.exe", "Stordiag.exe", "SyncAppvPublishingServer.exe", "Ttdinject.exe", "Tttracer.exe", "Unregmp2.exe", "vbc.exe", "Verclsid.exe", "Wab.exe", "winget.exe", "Wlrmdr.exe", "Wmic.exe", "WorkFolders.exe", "Wscript.exe", "Wsreset.exe", "wuauclt.exe", "Xwizard.exe", "fsutil.exe", "wt.exe", "GfxDownloadWrapper.exe", "Advpack.dll", "Desk.cpl", "Dfshim.dll", "Ieadvpack.dll", "Ieframe.dll", "Mshtml.dll", "Pcwutl.dll", "Setupapi.dll", "Shdocvw.dll", "Shell32.dll", "Syssetup.dll", "Url.dll", "Zipfldr.dll", "Comsvcs.dll", "AccCheckConsole.exe", "adplus.exe", "AgentExecutor.exe", "Appvlp.exe", "Bginfo.exe", "Cdb.exe", "coregen.exe", "Createdump.exe", "csi.exe", "DefaultPack.EXE", "Devinit.exe"]);
DeviceProcessEvents
| where InitiatingProcessFileName in~ (LOLBins)
| summarize TotalExecutions = count() by InitiatingProcessFileName
| sort by TotalExecutions
```

