# MVISION EDR Real-Time-Search and Reactions

This is a collection of scripts to run Real-Time-Search and optional to execute reactions.

Search File Usage:
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
usage: mvision_edr_search_process.py -U <username> -P <password> -PN <process name> 

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US,SY}, -R {EU,US,SY}
                        MVISION EDR Tenant Region
  --user USER, -U USER  MVISION EDR User Account
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --process PROCESS, -PN PROCESS
  --reaction {True,False}, -RE {True,False}
                        Kill Process.
  --loglevel {INFO,DEBUG}, -L {INFO,DEBUG}
                        Specify log level.
```
