# KQL Sentinel & Defender queries [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=KQL%20Detection%20Rules!%20MDE%20and%20Sentinel!&url=https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules)

```
██   ██  ██████  ██                                                                                     
██  ██  ██    ██ ██                                                                                     
█████   ██    ██ ██                                                                                     
██  ██  ██ ▄▄ ██ ██                                                                                     
██   ██  ██████  ███████                                                                                
            ▀▀                                                                                          
                                                                                                        
█  ██████  ██████  ██ ███    ██ ████████   ██  ██     ██ ███████ ██       ██████  ██████  ███    ███ ███████ ██
█  ██   ██ ██   ██ ██ ████   ██    ██          ██     ██ ██      ██      ██      ██    ██ ████  ████ ██      
█  ██████  ██████  ██ ██ ██  ██    ██          ██  █  ██ █████   ██      ██      ██    ██ ██ ████ ██ █████   
█  ██      ██   ██ ██ ██  ██ ██    ██          ██ ███ ██ ██      ██      ██      ██    ██ ██  ██  ██ ██      
█  ██      ██   ██ ██ ██   ████    ██           ███ ███  ███████ ███████  ██████  ██████  ██      ██ ███████ 
```


# KQL for Defender For Endpoint & Microsoft Sentinel
The purpose of this repository is to share KQL queries that can be used by anyone and are understandable. These queries are intended to increase detection coverage through the logs of Microsoft Security products. Not all suspicious activities generate an alert by default, but many of those activities can be made detectable through the logs. These queries include Detection Rules, Hunting Queries and Visualisations. Anyone is free to use the queries. If you have any questions feel free to reach out to me on twitter [@BertJanCyber](https://twitter.com/BertJanCyber). 

**Presenting this material as your own is illegal and forbidden. A reference to Twitter [@BertJanCyber](https://twitter.com/BertJanCyber) or Github [@Bert-JanP](https://github.com/Bert-JanP) is much appriciated when sharing or using the content.**

## KQL Blogs
More detailed KQL information can be found on my blog page: https://kqlquery.com

# KQL Categories

The queries in this repository are split into different categories. The MITRE ATT&CK category contains a list of queries mapped to the tactics of the MITRE Framework. The product section contains queries specific to Microsoft security products. The Processes section contains several queries that can be used in common cyber processes to make things easier for security analysts. In addition, there is a special category for Zero Day detections. Lastly, there is an informational section that explains the use of KQL using examples. 

## MITRE ATT&CK

- [MITRE ATT&CK Mapping](./MITRE%20ATT%26CK/Mapping.md)

## Products
- [Defender For Endpoint detection rules](./Defender%20For%20Endpoint)
- [Defender For Identity detection rules](./Defender%20For%20Identity)
- [Defender For Cloud Apps detection rules](./Defender%20For%20Cloud%20Apps)
- [Defender For Office 365](./Office%20365)
- [Azure Active Directory](./Azure%20Active%20Directory)
- [Microsoft Sentinel](./Sentinel)
- [MISP](./MISP)

## Security Processes
- [Digital Forensics and Incident Response](./DFIR)
- [Threat Hunting](./Threat%20Hunting)
- [Full Threat Hunting Cases](./Threat%20Hunting%20Cases)
- [Vulnerability Management](./Vulnerability%20Management)

## Zero Day Detections
- [Zero Day Detection](./Zero%20Day%20Detection)

## Informational 

- [KQL helful functions](./Functions/)
- [KQL Regex Example List](./KQL%20Regex/RegexExamples.md)
- [Azure Resource Graph](./Azure%20Resource%20Graph/)

### Detection Template
The *[Detection Template](./DetectionTemplate.md)* can be used to standardize the detections in your own repository. This could help other to easily parse the content of the repository to collect the query and the metadata. The following repositories have already been standardized in this manner:
- https://github.com/alexverboon/Hunting-Queries-Detection-Rules - By Alex Verboon
- https://github.com/KustoKing/Hunting-Queries-Detection-Rules - By Gianni Castaldi

If your repository is not yet listed, feel free to create a pull request (PR) or reach out via message to have it added.
# Where to use KQL in Defender For Endpoint & Sentinel?

## Defender For Endpoint
* Open  [security.microsoft.com](https://www.security.microsoft.com)
* Hunting
* Advanced Hunting

## Sentinel
* Open [portal.azure.com](https://www.portal.azure.com)
* Search for Sentinel
* Open Sentinel
* Logs

# KQL Defender For Endpoint vs Sentinel

KQL queries can be used in both Defender For Endpoint and Azure Sentinel. The syntax is almost the same. The main difference is the field that indicates the time. It must be adjusted according to the product used. In Sentinel, the 'TimeGenerated' field is used. In DFE it is 'Timestamp'. The queries below show both in DFE and in Azure Sentinel 10 DeviceEvents of the last 7 days.

Quickstart Defender For Endpoint
```
DeviceEvents
| where Timestamp > ago(7d)
| take 10
```

Quickstart Azure Sentinel
```
DeviceEvents
| where TimeGenerated > ago(7d)
| take 10
```

# KQL Useful Documentation
* [KQL Quick Reference Guide](https://docs.microsoft.com/en-us/azure/data-explorer/kql-quick-reference)
* [KQL Tutorial](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/tutorial?pivots=azuredataexplorer)
* [KQL Cheat Sheet PDF](https://github.com/marcusbakker/KQL/blob/master/kql_cheat_sheet.pdf)

