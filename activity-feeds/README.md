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

## Example 

Example of a threat event with enriched data.

```
{
  "entity": "threat",
  "id": "2AC2F54C9C2AD354E506A9E1B0B66D1F13707CA0F476D34D2C39DFA96C93E2BD",
  "nature": "system",
  "origin": "FT",
  "tenant-id": "E08A6558-C4CF-4F42-B7C6-7D25B04BF21C",
  "threat": {
    "contentVersion": null,
    "detectionDate": "2020-10-06T19:44:21.503Z",
    "detectionTags": [
      "@ATA.DefenseEvasion",
      "@ATA.Execution",
      "@ATE.T1059",
      "@ATE.T1107",
      "@MSI._file_deletecommon",
      "@ATE.T1064",
      "@ATE.T1086",
      "@ATE.T1204",
      "@ATE.T1173",
      "@MSI._process_powershell_via_office_macro",
      "@MSI._process_sans_powershell_15",
      "@MSI._process_lolbas_public_ip",
      "@ATA.CommandAndControl",
      "@ATE.T1102",
      "@MSI._process_powershell_download_public_IP",
      "@ATE.T1105",
      "@MSI._process_psdownload",
      "@MSI._process_psexecexpression",
      "@MSI._process_psparams"
    ],
    "eventType": "Threat Detection Summary",
    "id": "b9f4dafb-0484-43b6-9690-3a3b572a21b9",
    "interpreterFileAttrs": {
      "md5": null,
      "name": null,
      "path": null,
      "sha1": null,
      "sha256": null
    },
    "maGuid": "EA9F52CE-36A0-11EA-10AD-BC305BC1C08F",
    "maHostname": "warroom1.mcafeeebc.net",
    "maIP": "172.26.160.18",
    "maName": "WARROOM1",
    "maTags": "Block Powershell, Escalated, Workstation",
    "rank": "270",
    "score": "70",
    "severity": "s4",
    "threatAttrs": {
      "md5": "44D7816CCE82E5450FCA03C18A156B4B",
      "name": "WINWORD.EXE",
      "path": "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "sha1": "9DE7C2A2C413C00CB33FAFBDEED1B6B70B327F3A",
      "sha256": "2AC2F54C9C2AD354E506A9E1B0B66D1F13707CA0F476D34D2C39DFA96C93E2BD"
    },
    "threatType": "pe"
  },
  "timestamp": "2020-10-06T19:44:21.503Z",
  "transaction-id": "b1241c1b-a887-453f-a104-16cb241c9d6d",
  "type": "threat-detection",
  "user": "system"
}
```
