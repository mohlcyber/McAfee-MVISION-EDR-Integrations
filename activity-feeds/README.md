# McAfee MVISION EDR Activity Feed

This is a script to consume activity feeds from MVISION EDR. 
The script contains various modules to ingest trace data into e.g. ServiceNow, TheHive, Syslog or Email.
Further it provides an optional function to enrich the maGuid with EPO data like Hostname, Name, IP Address and assigned Tags.

## Prerequisites

The script requires the dxlstreaming client libraries. To install these libraries execute:
```sh
pip install dxlstreamingclient
```

## Execute the script

```sh
usage: python mvision_edr_activity_feeds.py -h

McAfee EDR Activity Feeds

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US}, -R {EU,US}
                        MVISION EDR Tenant Location
  --user USER, -U USER  MVISION EDR Username
  --password PASSWORD, -P PASSWORD
                        MVISION EDR Password
  --module {Syslog,TheHive,Email,ServiceNow}, -M {Syslog,TheHive,Email,ServiceNow}
                        Modules
  --command COMMAND, -C COMMAND
                        Commands for Modules: 
                         
                        For Syslog please use the following commands: 
                        -C syslog=<Syslog Server IP> -C port=<PORT>
                         
                        For TheHive please use the following commands: 
                        -C url=<URL to TheHive http://> -C port=<PORT> -C token=<TOKEN> 
                         
                        For Email please use the following commands: 
                        -C smtp=<IP to SMTP server> -C port=<PORT> -C user=<SMTP User> -C pw=<SMTP PW> -C recipient=<Recipient>
                         
                        For ServiceNow please use the following commands: 
                        -C url=<URL to SNOW Instance> -C user=<SNOW User> -C pw=<SNOW PW>
                         
  --loglevel {critical,error,warning,info,debug,notset}, -L {critical,error,warning,info,debug,notset}
  --enrich {True,False}
                        Enrich MAGUID with EPO
  --epo-ip EPO_IP       ePO Server IP or hostname
  --epo-port EPO_PORT   ePO Server Port
  --epo-user EPO_USER   ePO Server User
  --epo-pwd EPO_PWD     ePO Server Password
```

## Parsing

I uploaded McAfee ESM parser for Case Events, Business Events and Threat Events. Parsers for Finding Events will follow soon.
