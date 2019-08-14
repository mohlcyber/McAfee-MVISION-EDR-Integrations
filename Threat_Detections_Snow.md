# McAfee MVISION EDR Threat Detections in ServiceNow

This is a script to consume threat detections from MVISION EDR and create new cases in ServiceNow as well as ingest the data into a Syslog Server. 

## Prerequisites

The script requires the dxlstreaming client libraries. To install these libraries execute:
```sh
$ pip install dxlstreamingclient
```

[Download the scripts here](threat_detections_snow)

## Configuration

Change the MVISION EDR and Syslog details between line 9 and 20 in mvision_edr_threats_snow.py.

<img width="523" alt="Screenshot 2019-07-31 at 16 41 43" src="https://user-images.githubusercontent.com/25227268/62221556-1d61a580-b3b2-11e9-979b-bd153a74d858.png">

Change the ServiceNow details between line 10 and 15 in snow.py

<img width="608" alt="Screenshot 2019-08-14 at 15 15 24" src="https://user-images.githubusercontent.com/25227268/63023942-71868280-bea6-11e9-80d4-c9c0e776bb6d.png">


## Execute the script

```sh
$ python mvision_edr_threats_snow.py
```

## Parsing

I uploaded McAfee ESM parser for MVISION EDR Threat Events here: [MEDR_Threat_Event.xml](activity-feeds/parser).
