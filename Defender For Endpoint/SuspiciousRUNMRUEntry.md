# Suspicious RUNMRU Entry

## Query Information

#### Description
This query should be implemented as custom detection, it triggers once a Suspicious Windows RUNMRU entry found on a device. These RUNMRU entries are one of the key indicators for ClickFix.

The list of *Parameters* and *Executables* is limited, add additional entries according to your risk apetite.

#### Risk
There is high likelyhood that the command found is deploying malicious content on the device.

#### References
- https://detect.fyi/hunting-clickfix-initial-access-techniques-8c1b38d5ef9b
- https://redcanary.com/blog/threat-intelligence/intelligence-insights-march-2025/

## Defender XDR
```KQL
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", 'iex']);
let Executables = dynamic(["cmd", "powershell", "curl", "mshta"]);
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "RunMRU"
| where RegistryValueData has_any (Parameters) and RegistryValueData has_any (Executables)
| project-reorder Timestamp, DeviceId, DeviceName, RegistryValueData, RegistryKey
```

## Sentinel
```KQL
let Parameters = dynamic(['http', 'https', 'Encoded', 'EncodedCommand', '-e', '-eC', '-enc', "-w", 'iex']);
let Executables = dynamic(["cmd", "powershell", "curl", "mshta"]);
DeviceRegistryEvents
| where ActionType == "RegistryValueSet"
| where RegistryKey has "RunMRU"
| where RegistryValueData has_any (Parameters) and RegistryValueData has_any (Executables)
| project-reorder TimeGenerated, DeviceId, DeviceName, RegistryValueData, RegistryKey
```