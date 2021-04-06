# McAfee MVISION EDR Threats (Monitoring)

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard). The script requires a username, password, details (True/False), hours and a limit to query the threats.

Further the script allows to retrieve additional details about the threat itself (-D / --details flag). This includes traces of the affected systems. 

Usage:

```sh
usage: python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -D <DETAILS> -M <MINUTES> -L <MAX RESULTS> -S <SYSLOG IP> -SP <SYSLOG PORT>

McAfee EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US,SY}, -R {EU,US,SY}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --details {True,False}, -D {True,False}
                        Enrich threat information with trace data
  --minutes MINUTES, -M MINUTES
                        Timeframe to pull data in minutes
  --limit LIMIT, -L LIMIT
                        Maximum number of returned items
  --syslog-ip SYSLOG_IP, -S SYSLOG_IP
                        Syslog IP Address
  --syslog-port SYSLOG_PORT, -SP SYSLOG_PORT
                        Syslog Port
```
