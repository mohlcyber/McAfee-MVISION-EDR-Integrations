# McAfee MVISION EDR Device Search

This is a script to query the device search in MVISION EDR. The script requires a tenant region, username, hostname, days and a limit to query the device data store. The days are referring to the timeframe. E.g search data from 3 days (starting point today (utc)).


Usage:

```sh
usage: python mvision_edr_device_search.py -R <REGION> -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> -T <TYPE> -S <SEARCH> -D <DAYS> -L <MAX RESULTS>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --hostname HOSTNAME, -H HOSTNAME
                        Hostname to Query
  --type {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}, -T {APICall,ProcessCreated,PECreated,NonPECreated,ArchiveCreated,ScriptCreated,ScriptExecuted,AdminHackingToolExecuted,ASEPCreatedOrModified,ServiceChanged,NetworkConnection,DNSQuery,ScheduledTaskRegistered,LoginLogout,LoadedDLLs,UserAccounts,WMIActivity,EPP_Response,DetectionsAlerts,Alerts}
                        Search Type
  --search SEARCH, -ST SEARCH
                        Search Term
  --days DAYS, -D DAYS  How many days back to query
  --limit LIMIT, -L LIMIT
                        Limit
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Set Log Level

```
