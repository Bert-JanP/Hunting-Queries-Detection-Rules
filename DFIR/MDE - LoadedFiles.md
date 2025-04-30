# Files Loaded by Suspicious Executable

## Query Information

#### Description
This query is designed to list the files that have been loaded by a suspicious executable. Often malware loads dlls to properly function, these dlls can be identified by giving the SHA1 hash of the malicious executable as *InputSHA1*.

#### Risk
A malicious image is loaded into an executable and performs activities.

## Defender XDR
```KQL
let InputSHA1 = "035833d4d9673fd767b3a73e5943abe0cb88b122";
let LoadedFiles = DeviceImageLoadEvents
| where InitiatingProcessSHA1 =~ InputSHA1
| summarize LoadedFiles = make_set(SHA1);
union DeviceNetworkEvents, DeviceProcessEvents, DeviceEvents
| where InitiatingProcessSHA1 in~ (InputSHA1)
```

## Sentinel
```KQL
let InputSHA1 = "035833d4d9673fd767b3a73e5943abe0cb88b122";
let LoadedFiles = DeviceImageLoadEvents
| where InitiatingProcessSHA1 =~ InputSHA1
| summarize LoadedFiles = make_set(SHA1);
union DeviceNetworkEvents, DeviceProcessEvents, DeviceEvents
| where InitiatingProcessSHA1 in~ (InputSHA1)
```