Follina Detection
----------
    // Sources: https://www.reddit.com/r/blueteamsec/comments/v0wgqh/sentinel_kql_detections_for_microsoft_word_zero/ & https://github.com/reprise99/Sentinel-Queries/blob/main/Defender%20for%20Endpoint/Device-msdtPotentialExploit.kql
    (union isfuzzy=true
    (DeviceProcessEvents
    | where ProcessCommandLine contains "msdt.exe"
    | where InitiatingProcessFileName has_any (@"outlook.exe", @"winword.exe", @"excel.exe")),
    (DeviceProcessEvents
    | where InitiatingProcessCommandLine contains "msdt.exe" and ProcessCommandLine !contains "msdt.exe"),
    (DeviceNetworkEvents
    | where InitiatingProcessFileName has_any ("sdiagnhost.exe", "msdt.exe")
    | where RemoteIPType == "Public"
    | where ActionType == "ConnectionSuccess"
    and RemoteUrl !endswith ".visualstudio.com"
    and RemoteUrl !endswith ".microsoft.com")
    )
