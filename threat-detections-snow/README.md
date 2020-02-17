# McAfee MVISION EDR Threat Detections in ServiceNow

This is a script to consume threat detections from MVISION EDR and create new cases in ServiceNow as well as ingest the data into a Syslog Server. 

## Prerequisites

The script requires the dxlstreaming client libraries. To install these libraries execute:
```sh
$ pip install dxlstreamingclient
```

## Configuration

Change the MVISION EDR, ServiceNow and Syslog details between line 12 and 25 in mvision_edr_threats_snow.py.

<img width="470" alt="Screenshot 2019-08-15 at 09 59 08" src="https://user-images.githubusercontent.com/25227268/63081209-5b7acf80-bf43-11e9-8a00-36778e75fd9e.png">

## Execute the script

```sh
$ python mvision_edr_threats_snow.py
```

The script will map the severity to the ServieNow mapping. This is just an example and can be changed.
<img width="1439" alt="Screenshot 2019-08-15 at 09 47 47" src="https://user-images.githubusercontent.com/25227268/63080935-9defdc80-bf42-11e9-8473-95ddbba011e1.png">

## Parsing

I uploaded McAfee ESM parser for MVISION EDR Threat Events here: [MEDR_Threat_Event.xml](activity-feeds/parser).
