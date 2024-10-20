# Twitter IOC feeds

## Description
This query uses tweets from the infosec community ([List](https://twitter.com/i/lists/1423693426437001224)) as input. They have been combined into feeds in https://tweetfeed.live/. Those lists are used to search for IOCS in your environment. This query searches for the following IOC types:
- IP
- Domain
- URL
- MD5
- SHA256 

Some IOC categories that are included:
- CobaltStrike
- Ransomware
- AgentTesla
- Qakbot

The query used two input variables *TimeRange* to select the timerange to search in. The other variable is *IncludeSpamPhishingIPS* which by default filters phishing IPs because they are sensitive to false positives, this can be turned on if wanted.
The rest of the query looks for any IOC that matches if that is the case a row will be shown with that information, which tweet it originated from and which IOC category it has. Before any data is displayed the statistics of the dataset are shown to display what is included.

Source: https://tweetfeed.live/

Feed link: https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv

### Defender XDR
```
// Collect external data from @0xDanielLopez Github. There is a UI for TweetFeed, this can be accessed on https://tweetfeed.live/
// TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community at Twitter. Here you will find malicious URLs, domains, IPs, and SHA256/MD5 hashes.
// Variables that are used:
let TimeRange = 7d; //Customizable h = hours, d = days
// Phishing and Spam IPs are most sensitive to false positves. Only enable this variable if you do want to include them.
let IncludeSpamPhishingIPS = false;
let TweetFeedLastMonth = externaldata(IOCTimestamp:datetime, TwitterUser:string, IOCType:string, IOC:string, IOCCatagory:string, TweetLink:string)[h@"https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv"] with(format="csv");
// Get overall statstics of the dataset.
let IOCStatistics = TweetFeedLastMonth
| summarize Total = count() by IOCType;
// All lines below are used to get lists of IOCs which can be mapped against tables. If you only want to use a some of those entries, remove the others for the best performance.
// Collect IP IOCS and validate IP addresses. Variable for Phishing and Spam is used as defined above.
let IPEntries = TweetFeedLastMonth
| where IOCType == "ip"
| where not(IOCCatagory in ('#phishing', '#phishing #scam', '#scam') and IncludeSpamPhishingIPS == false)
| distinct IOC
| where IOC matches regex '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
// Collect domain entries and make them lowercase.
let DomainEntries = TweetFeedLastMonth
| where IOCType == "domain"
| distinct tolower(IOC);
// Collect domain entries and make them lowercase. remove all HTTP(S):// from the domain
let URLEntries = TweetFeedLastMonth
| where IOCType == "url"
| distinct IOC
| extend StrippedDomain1 = extract(@'//(.*)', 1, IOC);
// Collect MD5 IOCS and validate md5 value
let MD5Entries = TweetFeedLastMonth
| where IOCType == "md5"
| distinct IOC
| where IOC matches regex '[a-f0-9]{32}';
// Collect sha256 IOCS and validate sha256 value
let SHA256Entries = TweetFeedLastMonth
| where IOCType == "sha256"
| distinct IOC
| where IOC matches regex '[a-fA-F0-9]{64}';
// The next lines will be used to search your tenant on the IOCs that are in the TweetFeed. This is done by combining multiple tables into one end result.
// Lookups are used to gain additional information on the IOC
union isfuzzy=true
// List IOC statistics
(IOCStatistics),
// List IP IOC matches if they exsists.
(DeviceNetworkEvents
| where Timestamp > ago(TimeRange)
| where RemoteIP in (IPEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteIP == $right.IOC
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)),
// List domain IOC matches if they exsists.
(DeviceNetworkEvents
| where Timestamp > ago(TimeRange)
| where RemoteUrl has_any (DomainEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteUrl == $right.IOC),
// List url IOC matches if they exsists.
(DeviceNetworkEvents
| where Timestamp > ago(TimeRange)
| where RemoteUrl in (URLEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteUrl == $right.IOC),
(DeviceFileEvents
| where Timestamp > ago(TimeRange)
| where MD5 in (MD5Entries)
| lookup kind=inner (TweetFeedLastMonth) on $left.MD5 == $right.IOC),
(DeviceFileEvents
| where Timestamp > ago(TimeRange)
| where SHA256 in (SHA256Entries)
| lookup kind=inner (TweetFeedLastMonth) on $left.SHA256 == $right.IOC)
// Reorder columns to first get info on IOC
| project-reorder IOCType, Total, IOCTimestamp, IOCCatagory, TweetLink, RemoteIP, RemoteUrl, MD5, SHA256
```

### Sentinel
```
// Collect external data from @0xDanielLopez Github. There is a UI for TweetFeed, this can be accessed on https://tweetfeed.live/
// TweetFeed collects Indicators of Compromise (IOCs) shared by the infosec community at Twitter. Here you will find malicious URLs, domains, IPs, and SHA256/MD5 hashes.
// Variables that are used:
let TimeRange = 7d; //Customizable h = hours, d = days
// Phishing and Spam IPs are most sensitive to false positves. Only enable this variable if you do want to include them.
let IncludeSpamPhishingIPS = false;
let TweetFeedLastMonth = externaldata(IOCTimeGenerated:datetime, TwitterUser:string, IOCType:string, IOC:string, IOCCatagory:string, TweetLink:string)[h@"https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/month.csv"] with(format="csv");
// Get overall statstics of the dataset.
let IOCStatistics = TweetFeedLastMonth
| summarize Total = count() by IOCType;
// All lines below are used to get lists of IOCs which can be mapped against tables. If you only want to use a some of those entries, remove the others for the best performance.
// Collect IP IOCS and validate IP addresses. Variable for Phishing and Spam is used as defined above.
let IPEntries = TweetFeedLastMonth
| where IOCType == "ip"
| where not(IOCCatagory in ('#phishing', '#phishing #scam', '#scam') and IncludeSpamPhishingIPS == false)
| distinct IOC
| where IOC matches regex '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
// Collect domain entries and make them lowercase.
let DomainEntries = TweetFeedLastMonth
| where IOCType == "domain"
| distinct tolower(IOC);
// Collect domain entries and make them lowercase. remove all HTTP(S):// from the domain
let URLEntries = TweetFeedLastMonth
| where IOCType == "url"
| distinct IOC
| extend StrippedDomain1 = extract(@'//(.*)', 1, IOC);
// Collect MD5 IOCS and validate md5 value
let MD5Entries = TweetFeedLastMonth
| where IOCType == "md5"
| distinct IOC
| where IOC matches regex '[a-f0-9]{32}';
// Collect sha256 IOCS and validate sha256 value
let SHA256Entries = TweetFeedLastMonth
| where IOCType == "sha256"
| distinct IOC
| where IOC matches regex '[a-fA-F0-9]{64}';
// The next lines will be used to search your tenant on the IOCs that are in the TweetFeed. This is done by combining multiple tables into one end result.
// Lookups are used to gain additional information on the IOC
union isfuzzy=true
// List IOC statistics
(IOCStatistics),
// List IP IOC matches if they exsists.
(DeviceNetworkEvents
| where TimeGenerated > ago(TimeRange)
| where RemoteIP in (IPEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteIP == $right.IOC
| extend GeoIPInfo = geo_info_from_ip_address(RemoteIP)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)),
// List domain IOC matches if they exsists.
(DeviceNetworkEvents
| where TimeGenerated > ago(TimeRange)
| where RemoteUrl has_any (DomainEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteUrl == $right.IOC),
// List url IOC matches if they exsists.
(DeviceNetworkEvents
| where TimeGenerated > ago(TimeRange)
| where RemoteUrl in (URLEntries)
| lookup kind=inner (TweetFeedLastMonth) on $left.RemoteUrl == $right.IOC),
(DeviceFileEvents
| where TimeGenerated > ago(TimeRange)
| where MD5 in (MD5Entries)
| lookup kind=inner (TweetFeedLastMonth) on $left.MD5 == $right.IOC),
(DeviceFileEvents
| where TimeGenerated > ago(TimeRange)
| where SHA256 in (SHA256Entries)
| lookup kind=inner (TweetFeedLastMonth) on $left.SHA256 == $right.IOC)
// Reorder columns to first get info on IOC
| project-reorder IOCType, Total, IOCTimeGenerated, IOCCatagory, TweetLink, RemoteIP, RemoteUrl, MD5, SHA256
```
