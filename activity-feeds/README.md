# McAfee MVISION EDR Activity Feed

This is a script to consume activity feeds from MVISION EDR. Further the script will ingest the Activity Feed into a Syslog Server.

## Prerequisites

The script requires the dxlstreaming client libraries. To install these libraries execute:
```sh
pip install dxlstreamingclient
```

## Execute the script

```sh
python mvision_edr_activity_feeds.py -U <USERNAME> -P <PASSWORD> -S <SYSLOG IP> -SP <SYSLOG PORT>

```

## Parsing

I uploaded McAfee ESM parser for Case Events, Business Events and Threat Events. Parsers for Finding Events will follow soon.
