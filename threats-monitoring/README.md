# McAfee MVISION EDR Threats (Monitoring)

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard). The script requires a username, password and a limit to query the threats. The script will write a file called cache.log to safe the last threat detection date. In case of internet connection issue or script execution issue it makes sure to pull all newest threat detections.

Further the script allows to retrieve additional details about the threat itself (-D / --details flag). This includes traces of the affected systems. This feature is experimental.

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
                        EXPERIMENTAL: Enrich threat information with trace data
  --limit LIMIT, -L LIMIT
                        Maximum number of returned items
  --syslog-ip SYSLOG_IP, -S SYSLOG_IP
                        Syslog IP Address
  --syslog-port SYSLOG_PORT, -SP SYSLOG_PORT
                        Syslog Port
```
