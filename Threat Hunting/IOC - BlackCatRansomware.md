# All BlackCat/ALPHV Ransomware IOCs with one KQL query
----
### Defender For Endpoint

```
// BlackCat/ALPHV Ransomware IOCs from: https://www.ic3.gov/Media/News/2022/220420.pdf
let MD5_IOCs = dynamic(['861738dd15eb7fb50568f0e39a69e107', '9f60dd752e7692a2f5c758de4eab3e6f', '09bc47d7bc5e40d40d9729cec5e39d73', 
'f5ef5142f044b94ac5010fd883c09aa7', '84e3b5fe3863d25bb72e25b10760e861', '9f2309285e8a8471fce7330fcade8619', '6c6c46bdac6713c94debbd454d34efd9', 
'e7ee8ea6fb7530d1d904cdb2d9745899', '815bb1b0c5f0f35f064c55a1b640fca5', '6c2874169fdfb30846fe7ffe34635bdb', '20855475d20d252dda21287264a6d860', 
'82db4c04f5dcda3bfcd75357adf98228', 'fcf3a6eeb9f836315954dae03459716d', '91625f7f5d590534949ebe08cc728380']);
let SHA1_IOCs = dynamic (['d241df7b9d2ec0b8194751cd5ce153e27cc40fa4', '4831c1b113df21360ef68c450b5fca278d08fae2', 
'fce13da5592e9e120777d82d27e06ed2b44918cf', '3f85f03d33b9fe25bcfac611182da4ab7f06a442', '37178dfaccbc371a04133d26a55127cf4d4382f8', 
'1b2a30776df64fbd7299bd588e21573891dcecbe']);
let SHA256_IOCs = dynamic(['731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161', 
'f837f1cd60e9941aa60f7be50a8f2aaaac380f560db8ee001408f35c1b7a97cb', 
'731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161', 
'80dd44226f60ba5403745ba9d18490eb8ca12dbc9be0a317dd2b692ec041da28']);
let IP_IOCs = dynamic (['89.44.9.243', '142.234.157.246', '45.134.20.66', '185.220.102.253',
     '37.120.238.58', '152.89.247.207', '198.144.121.93', '89.163.252.230',
     '45.153.160.140', '23.106.223.97', '139.60.161.161', '146.0.77.15',
     '94.232.41.155']);
(union isfuzzy=true
     (DeviceNetworkEvents
     | where RemoteIP has_any (IP_IOCs)),
     (DeviceFileEvents
     | where MD5 has_any (MD5_IOCs)),
     (DeviceFileEvents
     | where SHA1 has_any (SHA1_IOCs)),
     (DeviceFileEvents
     | where SHA256 has_any (SHA256_IOCs))
)
```
### Sentinel
```
// BlackCat/ALPHV Ransomware IOCs from: https://www.ic3.gov/Media/News/2022/220420.pdf
let MD5_IOCs = dynamic(['861738dd15eb7fb50568f0e39a69e107', '9f60dd752e7692a2f5c758de4eab3e6f', '09bc47d7bc5e40d40d9729cec5e39d73', 
'f5ef5142f044b94ac5010fd883c09aa7', '84e3b5fe3863d25bb72e25b10760e861', '9f2309285e8a8471fce7330fcade8619', '6c6c46bdac6713c94debbd454d34efd9', 
'e7ee8ea6fb7530d1d904cdb2d9745899', '815bb1b0c5f0f35f064c55a1b640fca5', '6c2874169fdfb30846fe7ffe34635bdb', '20855475d20d252dda21287264a6d860', 
'82db4c04f5dcda3bfcd75357adf98228', 'fcf3a6eeb9f836315954dae03459716d', '91625f7f5d590534949ebe08cc728380']);
let SHA1_IOCs = dynamic (['d241df7b9d2ec0b8194751cd5ce153e27cc40fa4', '4831c1b113df21360ef68c450b5fca278d08fae2', 
'fce13da5592e9e120777d82d27e06ed2b44918cf', '3f85f03d33b9fe25bcfac611182da4ab7f06a442', '37178dfaccbc371a04133d26a55127cf4d4382f8', 
'1b2a30776df64fbd7299bd588e21573891dcecbe']);
let SHA256_IOCs = dynamic(['731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161', 
'f837f1cd60e9941aa60f7be50a8f2aaaac380f560db8ee001408f35c1b7a97cb', 
'731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161', 
'80dd44226f60ba5403745ba9d18490eb8ca12dbc9be0a317dd2b692ec041da28']);
let IP_IOCs = dynamic (['89.44.9.243', '142.234.157.246', '45.134.20.66', '185.220.102.253',
     '37.120.238.58', '152.89.247.207', '198.144.121.93', '89.163.252.230',
     '45.153.160.140', '23.106.223.97', '139.60.161.161', '146.0.77.15',
     '94.232.41.155']);
(union isfuzzy=true
     (DeviceNetworkEvents
     | where RemoteIP has_any (IP_IOCs)),
     (DeviceFileEvents
     | where MD5 has_any (MD5_IOCs)),
     (DeviceFileEvents
     | where SHA1 has_any (SHA1_IOCs)),
     (DeviceFileEvents
     | where SHA256 has_any (SHA256_IOCs))
)

```



