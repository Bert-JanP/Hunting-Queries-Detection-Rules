# MicrosoftGraphActivityLogs IP Enrichment

## Query Information

#### Description
The IP information can be enriched using the [geo_info_from_ip_address()](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/geo-info-from-ip-address-function) function, which returns the country, state, city, latitude and longitude of each IPv4 and IPv6 address.

#### References
- https://learn.microsoft.com/en-us/graph/microsoft-graph-activity-logs-overview#what-data-is-available-in-the-microsoft-graph-activity-logs

## Sentinel
```KQL
MicrosoftGraphActivityLogs
| extend GeoIPInfo = geo_info_from_ip_address(IPAddress)
| extend country = tostring(parse_json(GeoIPInfo).country), state = tostring(parse_json(GeoIPInfo).state), city = tostring(parse_json(GeoIPInfo).city), latitude = tostring(parse_json(GeoIPInfo).latitude), longitude = tostring(parse_json(GeoIPInfo).longitude)
| project-reorder IPAddress, country, state, RequestUri
```
