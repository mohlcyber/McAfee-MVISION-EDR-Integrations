# MVISION EDR Real-Time-Search and Reactions

This is a collection of scripts to run Real-Time-Search and optional to execute reactions. 

The script requires tenant_region, client_id and client_secret to execute real-time searches. 
Client_ID and Client_Secrets can get generated with the [mvision_edr_creds_generator.py](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations/blob/master/mvision_edr_creds_generator.py) script posted in the main [repository](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations).

Search Hash Usage:
```
usage: Usage: python mvision_edr_search_hash.py -C <CLIENT_ID> -S <CLIENT_SECRET> -H <HASH>

MVISION EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --hash HASH, -H HASH
  --reaction {True,False}, -RE {True,False}
                        Delete Files that got identified.
  --loglevel {INFO,DEBUG}, -L {INFO,DEBUG}
                        Specify log level.

```

Search Process Usage:

```
usage: Usage: python mvision_edr_search_process.py -C <CLIENT_ID> -S <CLIENT_SECRET> -PN <process name>

MVISION EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --process PROCESS, -PN PROCESS
  --reaction {True,False}, -RE {True,False}
                        Kill Process
  --loglevel {INFO,DEBUG}, -L {INFO,DEBUG}
                        Specify log level

```

Search Filename Usage:

```
usage: Usage: python mvision_edr_search_filename.py -C <CLIENT_ID> -S <CLIENT_SECRET> -H <HASH>

MVISION EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --file FILE, -F FILE
  --reaction {True,False}, -RE {True,False}
                        Delete Files that got identified.
  --loglevel {INFO,DEBUG}, -L {INFO,DEBUG}
                        Specify log level.

```
