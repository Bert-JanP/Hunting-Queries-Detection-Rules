# Defender AV Exclusion Events

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1562.001 | Impair Defenses: Disable or Modify Tools | https://attack.mitre.org/techniques/T1562/001/ |

#### Description
This query detects attempts to add exclusions to Microsoft Defender via PowerShell commands such as `Add-MpPreference` or `Set-MpPreference`. Attackers frequently add exclusions to Defender to allow their malicious tools to run without being detected. The query covers both direct command-line executions and PowerShell script-based executions captured via `DeviceEvents`.

#### Risk
Adding Defender exclusions is a well-known defense evasion technique. If an attacker gains sufficient privileges, they may add exclusions for paths, extensions, processes, or IP addresses to allow malware to run undetected on the system.

#### References
- https://thedfirreport.com/2022/05/09/seo-poisoning-a-gootloader-story/
- https://redcanary.com/threat-detection-report/techniques/disable-or-modify-tools/

## Defender XDR
```KQL
let ExclusionOptions = dynamic(['ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress']);
let Modules = dynamic(['Add-MpPreference','Set-MpPreference']);
let CommandLineExecutions = DeviceProcessEvents
    | where ProcessCommandLine has_any (Modules) and ProcessCommandLine has_any (ExclusionOptions);
let PowerShellExecutions = DeviceEvents
    | where ActionType == 'PowerShellCommand' 
    | where AdditionalFields  has_any (Modules) and AdditionalFields has_any (ExclusionOptions);
union PowerShellExecutions, CommandLineExecutions
```

## Sentinel
```KQL
let ExclusionOptions = dynamic(['ExclusionPath', 'ExclusionExtension', 'ExclusionProcess', 'ExclusionIpAddress']);
let Modules = dynamic(['Add-MpPreference','Set-MpPreference']);
let CommandLineExecutions = DeviceProcessEvents
    | where ProcessCommandLine has_any (Modules) and ProcessCommandLine has_any (ExclusionOptions);
let PowerShellExecutions = DeviceEvents
    | where ActionType == 'PowerShellCommand' 
    | where AdditionalFields  has_any (Modules) and AdditionalFields has_any (ExclusionOptions);
union PowerShellExecutions, CommandLineExecutions
```