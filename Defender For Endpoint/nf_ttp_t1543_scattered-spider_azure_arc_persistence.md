# Azure ARC Related Persistence Detection

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                            | Link                                   |
|--------------|----------------------------------|----------------------------------------|
| T1543        | Create or Modify System Process  | [Create or Modify System Process](https://attack.mitre.org/techniques/T1543/) |

#### Description
This detection rule aims to identify the unexpected installation of Azure ARC agents. Scattered Spider has been known to register their own Azure tenant and install Azure ARC agents on devices to maintain persistence. The rule includes two queries: one for detecting service installations and another for identifying specific file path creations associated with Azure ARC agents.

#### Risk
The risk addressed by this detection rule is the unauthorized installation of Azure ARC agents, which can be used as a persistence mechanism by attackers. This technique allows them to maintain long-term access to compromised systems and potentially exert control over a wider network.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [Azure ARC Agent Overview](https://learn.microsoft.com/en-us/azure/azure-arc/servers/agent-overview)
- [Microsoft Security Blog on Azure ARC](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)

## Defender For Endpoint
```KQL
// Unexpected installation of azure arc agent - service installation
let ServiceNames = datatable(name:string)["himds.exe","gc_arc_service.exe","gc_extension_service.exe"];
DeviceEvents
| where ActionType =~ "ServiceInstalled"
| extend ServiceName = tostring(parse_json(AdditionalFields).ServiceName)
| extend ServiceAccount = tostring(parse_json(AdditionalFields).ServiceAccount)
| extend ServiceStartType = tostring(parse_json(AdditionalFields).ServiceStartType)
| extend ServiceType = tostring(parse_json(AdditionalFields).ServiceType)
| where ServiceName has_any (ServiceNames)
```

```KQL
// Unexpected installation of azure arc agent - filepaths
let AzureArcServicePaths = datatable(name:string)[@"\\AzureConnectedMachineAgent\\GCArcService\\GC"];
DeviceFileEvents
| where ActionType =~ "FileCreated"
| where FolderPath  has_any (AzureArcServicePaths)
```
