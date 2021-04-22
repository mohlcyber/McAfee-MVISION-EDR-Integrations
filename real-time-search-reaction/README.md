# McAfee MVISION EDR Real-Time-Search and Reactions

This is a collection of scripts to run Real-Time-Search and optional to execute reactions.

Search File Usage:
```
usage: mvision_edr_search_file.py -U <username> -P <password> -H <hash>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US,SY}, -R {EU,US,SY}
                        MVISION EDR Tenant Region
  --user USER, -U USER  MVISION EDR User Account
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
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