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
The purpose of this repository is to share KQL queries that can be used by anyone and are understandable. These queries are intended to increase detection coverage through the logs of Microsoft Security products. Not all suspicious activities generate an alert by default, but many of those activities can be made detectable through the logs. These queries include Detection Rules, Hunting Queries and Visualisations. Anyone is free to use the queries. If you have any questions feel free to reach out to me on Twitter [@BertJanCyber](https://twitter.com/BertJanCyber). 

**Presenting this material as your own is illegal and forbidden. A reference to Twitter [@BertJanCyber](https://twitter.com/BertJanCyber) or Github [@Bert-JanP](https://github.com/Bert-JanP) is much appreciated when sharing or using the content.**

## KQL Blogs
More detailed KQL information can be found on my blog page: https://kqlquery.com. Some KQL related blogs:
- [KQL Functions For Security Operations](https://kqlquery.com/posts/kql-for-security-operations/)
- [KQL Functions For Network Operations](https://kqlquery.com/posts/kql-for-network-operations/)
- [Incident Response Part 1: IR on Microsoft Security Incidents (KQL edition)](https://kqlquery.com/posts/kql-incident-response/)
- [Incident Response Part 2: What about the other logs?](https://kqlquery.com/posts/kql-incident-response-everything-else/)
- [From Threat Report to (KQL) Hunting Query](https://kqlquery.com/posts/from-threat-report-to-hunting-query/)
- [Prioritize Vulnerabilities Using The CISA Known Exploited Vulnerabilities Catalog](https://kqlquery.com/posts/prioritize-vulnerabilities-cisa/)
- [KQL Security Sources - 2024 Update](https://kqlquery.com/posts/kql-sources-2024-update/)
- [Detecting Post-Exploitation Behaviour](https://kqlquery.com/posts/detecting-post-exploitation-behaviour/)

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

- [KQL helpful functions](./Functions/)
- [KQL Regex Example List](./KQL%20Regex/RegexExamples.md)
- [Azure Resource Graph](./Azure%20Resource%20Graph/)

# Contributions
Everyone can submit contributions to this repository via a Pull Request. If you want to contribute the [Detection Template](#detection-template) needs to be used. Besides that the query needs to be able to run and be readable. To give credit where credit is due the top contributors are listed in the [Top Contributors section](#top-contributors).

## Top contributors
| Name | Queries added | GitHub | Twitter | Query Links |
|------|---------------|--------|---------| ---------|
|  [Gavin Knapp](https://www.linkedin.com/in/grjk83/)    |    10           |   [@m4nbat](https://github.com/m4nbat)     | [@knappresearchlb](https://twitter.com/knappresearchlb)      | <ul><li>[NetSupport running from unexpected directory (FIN7)](./Defender%20For%20Endpoint/ttp_t1219_netsupportrat_fin7.md)</li>
| | | |  | <ul><li>[Abusing PowerShell to disable Defender components](./Defender%20For%20Endpoint/ttp_t1562-001_disabledefender.md)</li>| 
| | | |  | <ul><li>[Suspicious network connection from MSBuild](./Defender%20For%20Endpoint/ttp_t1127-001_suspNetworkConnMSBuild.md)</li>| 
| | | |  | <ul><li>[PowerShell Encoded Command](./Defender%20For%20Endpoint/ttp_t1027-010_powershellEncodedCommand.md)</li>| 
| | | |  | <ul><li>[PowerShell Launching Scripts From WindowsApps Directory (FIN7)](./Defender%20For%20Endpoint/ttp_t1059-001_powershell_windowsappsdir_fin7.md)</li>| 
| | | |  | <ul><li>[Azure ARC Related Persistence Detection](./Defender%20For%20Endpoint/nf_ttp_t1543_scattered-spider_azure_arc_persistence.md)</li>| 
| | | |  | <ul><li>[Scattered Spider Defense Evasion via Conditional Access Policies Detection](./Azure%20Active%20Directory/nf_ttp_t1562.001_scattered-spider_abuse%20conditional_access_trusted_locations.md)</li>| 
| | | |  | <ul><li>[Check for Phishing Emails Using IPFS in Phishing Campaigns](./Threat%20Hunting/TI%20Feed%20-%20ipfs_phishing.md)</li>| 
| | | |  | <ul><li>[Kerberos attacks](./Defender%20For%20Endpoint/nf_ttp_generic_kerberos_attacks.md)</li>|
| | | |  | <ul><li>[PowerShell Creating LNK Files within a Startup Directory Detection](./Defender%20For%20Endpoint/nf_ttp_t1547-001_yellowcockatoo_powershell_create_link_in_startup)</li>| 
|  [Alex Teixeira](https://www.linkedin.com/in/inode/)    |    2           |   [@inodee](https://github.com/inodee)     | [@ateixei](https://twitter.com/ateixei)      | <ul><li>[Rare_Outgoing_IPv4_Connections](./Defender%20For%20Endpoint/Rare_Outgoing_IPv4_Connections.md)</li>
| | | |  | <ul><li>[Detect Known RAT RMM Process Patterns](./Defender%20For%20Endpoint/Detect_Known_RAT_RMM_Process_Patterns.md)</li>| 
|  [Babak Mahmoodizadeh](https://www.linkedin.com/in/babak-mhz/)    |    1           |   [@babakmhz](https://github.com/babakmhz)     | -      | <ul><li>[WebShell Detection](./Defender%20For%20Endpoint/WebshellDetection.md)</li> |

### Detection Template
The *[Detection Template](./DetectionTemplate.md)* can be used to standardize the detections in your own repository. This could help others to easily parse the content of the repository to collect the query and the metadata. The following repositories have already been standardized in this manner:
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
* [KQL Security Sources](https://kqlquery.com/posts/kql_sources/)

