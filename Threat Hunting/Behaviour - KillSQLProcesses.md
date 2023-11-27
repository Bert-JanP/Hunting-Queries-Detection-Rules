# Ransomware Behaviour Kill SQL Processes

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1489 | Service Stop | https://attack.mitre.org/techniques/T1489/ |

#### Description
Adversaries may stop or disable services on a system to render those services unavailable to legitimate users. Stopping critical services or processes can inhibit or stop response to an incident or aid in the adversary's overall objectives to cause damage to the environment. In this specific case this Threat Hunting query can be used to detect the behaviour that LockBit uses, which is killing SQL related processes via the commandline before deploying ransomware. 

Example commandline:
```PowerShell
cmd.exe /q /c taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe /im sqlwb.exe /im sqltob.exe /im sqlservr.exe /im sqlserver.exe /im sqlscan.exe /im sqlbrowser.exe /im sqlrep.exe /im sqlmangr.exe /im sqlexp3.exe /im sqlexp2.exe /im sqlex.exe
```

The query relies on two different variables as input, the *TotalKilledThreshold* variable determines how many different processes need to be killed, the example above contains 14 different processes that are killed, by altering this variable you can also detect subsets of the executed commandline. The *TotalParametersThreshold* variable determines how many parameters have to be used in the commandline.

#### Risk
An adversary kills all SQL processes before deploying ransomware on the servers

#### References
- https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a

## Defender For Endpoint
```KQL
let TotalKilledThreshold = 10;
let TotalParametersThreshold = 10;
DeviceProcessEvents
| where FileName == "taskkill.exe"
| extend CommandLineParameters = split(ProcessCommandLine, " ")
| extend TotalParameters = array_length(CommandLineParameters)
// Extract allSQL related processes in the CommandLineParameters
| mv-apply KilledProcess = CommandLineParameters on (
    where KilledProcess contains "sql"
    | project KilledProcess
)
| summarize arg_max(Timestamp, *), AllKilledProcess = make_set(KilledProcess) by ReportId
| extend TotalKilledProcesses = array_length(AllKilledProcess)
| project-reorder Timestamp, ProcessCommandLine, TotalParameters, TotalKilledProcesses
| where TotalKilledProcesses >= TotalKilledThreshold and TotalParameters >= TotalParametersThreshold
```
## Sentinel
```KQL
let TotalKilledThreshold = 10;
let TotalParametersThreshold = 10;
DeviceProcessEvents
| where FileName == "taskkill.exe"
| extend CommandLineParameters = split(ProcessCommandLine, " ")
| extend TotalParameters = array_length(CommandLineParameters)
// Extract allSQL related processes in the CommandLineParameters
| mv-apply KilledProcess = CommandLineParameters on (
    where KilledProcess contains "sql"
    | project KilledProcess
)
| summarize arg_max(TimeGenerated, *), AllKilledProcess = make_set(KilledProcess) by ReportId
| extend TotalKilledProcesses = array_length(AllKilledProcess)
| project-reorder TimeGenerated, ProcessCommandLine, TotalParameters, TotalKilledProcesses
| where TotalKilledProcesses >= TotalKilledThreshold and TotalParameters >= TotalParametersThreshold
```