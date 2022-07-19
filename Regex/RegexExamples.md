# KQL Regex List

## IP
```
let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
```
Example query: [AbuseCH IP Blacklist](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/AbuseCHIPBlacklistFeed.md)

## Domain
```
let DomainRegex = @"([a-z0-9|-]+\.)*[a-z0-9|-]+\.[a-z]+";
```
Example query: [Most Unusal Connections Made By office](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/RareConnectionsMadeByOffice.md)

## File Extension
```
let FileExtensionRegex = "\\.([a-z])*";
```
Example query: [Most Unusal Connections Made By office](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/RareConnectionsMadeByOffice.md)

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

## File Hash

### MD5
```
let MD5Regex = '[a-f0-9]{32}';
```
Example query: [AbuseCH MD5 Malware Hash](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/blob/main/Threat%20Hunting/AbuseCHMD5Malware.md)