# McAfee MVISION EDR Activity Feed

This is a script to consume activity feeds from MVISION EDR. Further the script will ingest the Activity Feed into a Syslog Server.

## Prerequisites

The script requires the dxlstreaming client libraries. To install these libraries execute:
```sh
$ pip install dxlstreamingclient
```

Download the script:
[mvision_edr_activity_feeds.py](activity-feeds)

## Configuration

Change the MVISION EDR and Syslog details between line 9 and 20.

<img width="523" alt="Screenshot 2019-07-31 at 16 41 43" src="https://user-images.githubusercontent.com/25227268/62221556-1d61a580-b3b2-11e9-979b-bd153a74d858.png">

## Execute the script

```sh
$ python mvision_edr_activity_feeds.py
```

## Parsing

I uploaded McAfee ESM parser for Case Events, Business Events and Threat Events. Parsers for Finding Events will follow soon.
