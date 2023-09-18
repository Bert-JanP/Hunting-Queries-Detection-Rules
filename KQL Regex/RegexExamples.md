# KQL Regex List

This page will be used as a quick reference guide for KQL regex queries. Those regular expressions can be used within your detection rules. For additional information see the  [Regex RE2 Library from Microsoft](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/re2-library). 

To be able to easaly test your regeluar expressions the query below can be used:
```
let RegexTest = @'\W*((?i)Admin(?-i))\W*';
let DataSet = materialize (range numbers from 1 to 10 step 1);
DataSet
| extend StringTest = iff(numbers % 2  == 0, 'Admin', 'User') // Change Admin to a string that should match the RegexTest, change User to a string that should not match the RegexTest
| where StringTest matches regex RegexTest
```

## IP
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
```
Example query: [AbuseCH IP Blacklist](../Threat%20Hunting/TI%20Feed%20-%20AbuseCHIPBlacklistFeed.md)

## Subnet
```
let IPv4SubnetRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]{1,3}';
```

Example query:
```
let MISPFeed = externaldata(Subnet: string)[@"https://raw.githubusercontent.com/ktsaou/blocklist-ipsets/master/firehol_level1.netset"] with (format="txt", ignoreFirstRecord=True);
let IPv4SubnetRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}/[0-9]{1,3}';
let x = MISPFeed 
| where Subnet matches regex IPv4SubnetRegex
| distinct Subnet;
x
```

## Domain
```
let DomainRegex = @"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+";
```
Example query: [Most Unusal Connections Made By office](../Defender%20For%20Endpoint/RareConnectionsMadeByOffice.md)

## File Extension
```
let FileExtensionRegex = "\\.([a-z])*";
```
Example query: [Most Unusal Connections Made By office](../Defender%20For%20Endpoint/RareConnectionsMadeByOffice.md)

## Regex search for string
```
let DomainAdminRegex = @'\W*((?i)Domain Admins(?-i))\W*';
```
Example query:
```
let DomainAdminRegex = @'\W*((?i)Domain Admins(?-i))\W*'; // Replace Domain Admins with the string you would like to match on
DeviceProcessEvents
| where ProcessCommandLine matches regex DomainAdminRegex
```

## Regex Parse Functionality 
```
let BetweenTwoStrings = @'"Path":"([^"]*)"'; //Extract from "Path:""C:\Users\XX\File.txt" to collect C:\Users\XX\File.txt
```
Example query: [Visualisation of the users with the most HardDelete actions performed (Line 8)](../Defender%20For%20Cloud%20Apps/HardUserDelete.md)

## Regex Between Two Strings
```
let BetweenTwoStrings = @'findstr(.*)password';
```
Example query:
```
let BetweenTwoStrings = @'findstr(.*)password'; // Replace findstr and password with the strings you would like to match on
DeviceProcessEvents
| where ProcessCommandLine matches regex BetweenTwoStrings
```

## Regex Between Last Char and String
```
let BetweenTwoStrings = @'.*/(.*)HTTP'; Between the last '/' and 'HTTP'. 
```
Example query: [Executable File Extentions downloaded via HTTP GET (Line 11)](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/HTTPExecutableFilesDownloaded.md)

## Regex Capture Everything After Char/String
```
let AfterChar = @'.*\.(.*)$'; // Capture all after last '.'. To collect file extentions.
let AfterString = @'.*test(.*)$';
```
Example query: [Executable File Extentions downloaded via HTTP GET (Line 12)](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Defender%20For%20Endpoint/HTTPExecutableFilesDownloaded.md)

## Regex Between word and special char
```
let Regex = @'Role.DisplayName(.*?)"}'; Between Role.DisplayName until "}. 
```
Example query: [List Role Additions (Line 5)](../Azure%20Active%20Directory/ADRoleAdditions.md)

## Regex Between two forward slashes 
```
let Regex = @'\\(.*?)\\'; Between \ extra \ to escape and until \ and again an extra \ to excape. 
```
Example query: [List Role Additions (Line 6)](../Azure%20Active%20Directory/ADRoleAdditions.md)

## File Hash

### MD5
```
let MD5Regex = '[a-f0-9]{32}';
```
Example query: [AbuseCH MD5 Malware Hash](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/AbuseCHMD5Malware.md)