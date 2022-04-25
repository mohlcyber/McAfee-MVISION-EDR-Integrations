# MVISION EDR Threats (Monitoring)

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard). The script requires tenant_region, client_id and client_secret to pull the latest threats. The script will write a file called cache.log to safe the last threat detection date. 

Client_ID and Client_Secrets can get generated with the [mvision_edr_creds_generator.py](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations/blob/master/mvision_edr_creds_generator.py) script posted in the main [repository](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations).

Further the script allows to retrieve additional details about the threat itself (-T / --trace flag). This includes traces of the affected systems. This feature is experimental.

Usage:

```sh
usage: python mvision_edr_threats.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -LL <LOG_LEVEL> -F <FILE WRITE> -SI <SYSLOG IP> -SP <SYSLOG PORT>

MVISION EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --trace {True,False}, -T {True,False}
                        EXPERIMENTAL: Enrich threat information with trace data
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Set Log Level
  --file {True,False}, -F {True,False}
                        Option to write Threat Events to files
  --syslog-ip SYSLOG_IP, -SI SYSLOG_IP
                        Syslog IP Address
  --syslog-port SYSLOG_PORT, -SP SYSLOG_PORT
                        Syslog Port
```
