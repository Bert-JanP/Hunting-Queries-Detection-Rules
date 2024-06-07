# Monitor ransomwarelive for companies of interest on ransowmare data leak sites (DLS)

## Query Information
This query can support monitoring for supply chain risk or companies of interest being present on ransowmare data leak sites (DLS) sites

#### MITRE ATT&CK Technique(s)

| Technique ID | Title                                 | Link                                                         |
|--------------|---------------------------------------|--------------------------------------------------------------|
|    T1486    | Data Encrypted for Impact | https://attack.mitre.org/techniques/T1486/ |
| T1657 | Financial Theft | https://attack.mitre.org/techniques/T1657 |

#### Description
This allows you to monitor the ransomware.live dataset for possible companies of interest being breached and posted by ransomware groups on data leak sites (DLS).

#### Risk
Relevant third parties, suppliers, or clients could be compromised and present an indiretc or direct risk to your organisation.

#### Author 
- **Name:** Gavin Knapp
- **Github:** [https://github.com/m4nbat](https://github.com/m4nbat)
- **Twitter:** [https://twitter.com/knappresearchlb](https://twitter.com/knappresearchlb)
- **LinkedIn:** [https://www.linkedin.com/in/grjk83/](https://www.linkedin.com/in/grjk83/)
- **Website:**

#### References
- [Microsoft Sentinel External Data Operator](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/externaldata-operator?pivots=azuredataexplorer)
- [Ransomware Live](https://ransomware.live/#/)

## Defender For Endpoint
```KQL
let clientkeyword = datatable(name:string)["client1","client2","client3","axip","elutia"]; //add clients
let supplierkeyword = datatable(supplier:string)["supplier1","supplier2","supplier3","merchant.id"]; //add suppliers
let thirdpartykeyword = datatable(supplier:string)["thirdparty1","thunderbirdcc"]; //add third parties
let victims = externaldata(country:string,
        description:string,
        Country:string,
        discovered:string,
        group_name:string,
        post_title:string,
        post_url:string,
        published:string,
        screenshot:string,
        website:string)
[h@"https://api.ransomware.live/recentvictims"]
with(format="multijson",ignoreFirstRecord=false);
victims
| where post_title has_any (clientkeyword) or post_title has_any (supplierkeyword) or post_title has_any (thirdpartykeyword)
```
