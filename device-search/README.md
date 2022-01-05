# McAfee MVISION EDR Device Search

This is a script to query the device search in MVISION EDR. The script requires a tenant region, username, hostname, days and a limit to query the device data store. The days are referring to the timeframe. E.g search data from 3 days (starting point today (utc)).


Usage:

```sh
usage: python mvision_edr_device_search.py -R <REGION> -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> -T <TYPE> -S <SEARCH> -D <DAYS> -L <MAX RESULTS>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US,SY}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --hostname HOSTNAME, -H HOSTNAME
                        Hostname to Query
  --type {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}, -T {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}
                        Search Type
  --search SEARCH, -S SEARCH
                        Search Term
  --days DAYS, -D DAYS  How many days back to query
  --limit LIMIT, -L LIMIT
                        Limit
```
