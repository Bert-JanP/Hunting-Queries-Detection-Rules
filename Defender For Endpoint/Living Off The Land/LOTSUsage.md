# Living Off Trusted Sites

## Query Information

#### Description
The Living Off Trusted Sites protject is included in the queries below. The project is about: *Attackers are using popular legitimate domains when conducting phishing, C&C, exfiltration and downloading tools to evade detection. The list of websites below allow attackers to use their domain or subdomain.* The query below can be used to hunt for websites which are rare in your organization or are executed by rare *InitiatingFiles*. This query can be used to list all found LOTS domains and how often they are executed, this can serve as input for further investigation or as start for you threat hunting case.

Due to the amount of legitimate traffic this query will likely result in a lot of false positives, therefor is it imporant to look at rare sightings rather then the most common once. Therefor this query only outputs statistics which can be used to build further queries. To limit the false positives, or put websites out of scope, the *WhitelistedDomains* can be used to whitelist domains.

**THIS SHOULD NOT BE USED AS DETECTION RULE**

This qeury levarages a txt file that is located in my repository, however the source of that file is: [lots-project.com](lots-project.com) from [@mrd0x](https://twitter.com/mrd0x).

#### Risk
An actor uses Living Off Trusted Sites to host their malicious infrastructure

#### References
- https://lots-project.com/

## Defender XDR
```KQL
// THIS QUERY IS ONLY FOR HUNTING, NOT FOR DETECTION. IT WILL GENERATE TO MUCH FPs.
// The query levarages the Living Off Trusted Sites from: https://lots-project.com/
let LOTS = externaldata(Data:string )[@"https://raw.githubusercontent.com/Bert-JanP/Hunting-Queries-Detection-Rules/main/Defender%20For%20Endpoint/Living%20Off%20The%20Land/lots-project.txt"] with (format="txt", ignoreFirstRecord=True);
// To finetune your hunt the whitelist below can be used. Use lowercase for the has_any to work.
let WhitelistedDomains = dynamic(['yourdomain.com', 'yoursharepoint.sharepoint.com']);
// Parse Input into Fields
let LotsParsed = LOTS
| where not(Data startswith "#")
| extend Fields = split(Data, ",")
| extend Website = Fields[0], Tags = Fields[1], ServiceProvider = Fields[2];
// Collect all unique domains for better performance.
let LotsDomains = LotsParsed
// Parse Websites to Lower to ensure that has_any can be used.
| extend WebsiteToLower = tolower(tostring(Website))
| distinct WebsiteToLower;
DeviceNetworkEvents
| where RemoteUrl has_any (LotsDomains)
// Filter whitelist.
| where not(RemoteUrl has_any (WhitelistedDomains))
// All upcomming lines below are used to create results which can be valueble. There is some explanation, but limited. If you want more info send me a message.
// The lines below are used to extract the domain -> <domain>.<tld> for good statistics.
// Method 1:
// Parse URL to get the host, if this can be parsed. Otherwise method 2 is used.
| extend ParseURL = parse_url(RemoteUrl)
| extend DomainParseURL = tostring(parse_json(ParseURL).Host)
// Method 2:
// for all domains that could not be parsed via the parseURL
| extend SplitUrl = split(RemoteUrl, ".")
// Combine splitted results and merge results from method one into the domain field.
| extend DomainParsed = iff(isempty(DomainParseURL), tostring(strcat( SplitUrl[array_length(SplitUrl) - 2] , ".", SplitUrl[array_length(SplitUrl) -1])), "na")
| extend SplitDomainParseURL = split(DomainParseURL, ".")
| extend Domain = iff(DomainParsed == "na", tostring(strcat( SplitDomainParseURL[array_length(SplitDomainParseURL) - 2] , ".", SplitDomainParseURL[array_length(SplitDomainParseURL) -1])), DomainParsed)
// Normal query continues, parsing is over.
// Summarize results. Based on the summarize you can investigate further.
| summarize TotalCount = count(), URLs = make_set(RemoteUrl), Devices = make_set(DeviceName), RemotePorts = make_set(RemotePort), InitiatingFiles = make_set(InitiatingProcessFileName) by Domain
// Some additional field for statistics
| extend TotalDevices = array_length(Devices), UniqueURLs = array_length(URLs), TotalInitiatingFiles = array_length(InitiatingFiles)
| sort by TotalCount
// Project all fields
| project Domain, TotalCount, UniqueURLs, TotalDevices, TotalInitiatingFiles, RemotePorts, URLs, Devices, InitiatingFiles
```
## Sentinel
```KQL
// THIS QUERY IS ONLY FOR HUNTING, NOT FOR DETECTION. IT WILL GENERATE TO MUCH FPs.
// The query levarages the Living Off Trusted Sites from: https://lots-project.com/
let LOTS = externaldata(Data:string )[@"https://raw.githubusercontent.com/Bert-JanP/Hunting-Queries-Detection-Rules/main/Defender%20For%20Endpoint/Living%20Off%20The%20Land/lots-project.txt"] with (format="txt", ignoreFirstRecord=True);
// To finetune your hunt the whitelist below can be used. Use lowercase for the has_any to work.
let WhitelistedDomains = dynamic(['yourdomain.com', 'yoursharepoint.sharepoint.com']);
// Parse Input into Fields
let LotsParsed = LOTS
| where not(Data startswith "#")
| extend Fields = split(Data, ",")
| extend Website = Fields[0], Tags = Fields[1], ServiceProvider = Fields[2];
// Collect all unique domains for better performance.
let LotsDomains = LotsParsed
// Parse Websites to Lower to ensure that has_any can be used.
| extend WebsiteToLower = tolower(tostring(Website))
| distinct WebsiteToLower;
DeviceNetworkEvents
| where RemoteUrl has_any (LotsDomains)
// Filter whitelist.
| where not(RemoteUrl has_any (WhitelistedDomains))
// All upcomming lines below are used to create results which can be valueble. There is some explanation, but limited. If you want more info send me a message.
// The lines below are used to extract the domain -> <domain>.<tld> for good statistics.
// Method 1:
// Parse URL to get the host, if this can be parsed. Otherwise method 2 is used.
| extend ParseURL = parse_url(RemoteUrl)
| extend DomainParseURL = tostring(parse_json(ParseURL).Host)
// Method 2:
// for all domains that could not be parsed via the parseURL
| extend SplitUrl = split(RemoteUrl, ".")
// Combine splitted results and merge results from method one into the domain field.
| extend DomainParsed = iff(isempty(DomainParseURL), tostring(strcat( SplitUrl[array_length(SplitUrl) - 2] , ".", SplitUrl[array_length(SplitUrl) -1])), "na")
| extend SplitDomainParseURL = split(DomainParseURL, ".")
| extend Domain = iff(DomainParsed == "na", tostring(strcat( SplitDomainParseURL[array_length(SplitDomainParseURL) - 2] , ".", SplitDomainParseURL[array_length(SplitDomainParseURL) -1])), DomainParsed)
// Normal query continues, parsing is over.
// Summarize results. Based on the summarize you can investigate further.
| summarize TotalCount = count(), URLs = make_set(RemoteUrl), Devices = make_set(DeviceName), RemotePorts = make_set(RemotePort), InitiatingFiles = make_set(InitiatingProcessFileName) by Domain
// Some additional field for statistics
| extend TotalDevices = array_length(Devices), UniqueURLs = array_length(URLs), TotalInitiatingFiles = array_length(InitiatingFiles)
| sort by TotalCount
// Project all fields
| project Domain, TotalCount, UniqueURLs, TotalDevices, TotalInitiatingFiles, RemotePorts, URLs, Devices, InitiatingFiles
```
