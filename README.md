# Introduction

This is a collection of different McAfee MVISION EDR integration scripts. This includes:

[McAfee MVISION EDR Activity Feeds Script](activity-feeds): 
This is a script to consume activity feeds from MVISION EDR. Further the script will ingest the Activity Feed into a Syslog Server.

[McAfee MVISION EDR RemoveFiles Script](remove-file): 
This is a script that will search for systems based on a specific hash and will automatically remove these files.

[McAfee MVISION EDR Threat Detections to ServiceNow](threat_detections_snow):
This is a script to consume threat detections from MVISION EDR and create new cases in ServiceNow as well as ingest the data into a Syslog Server.

[McAfee MVISION EDR Historical Search](history_search):
This is a script to query the historical data store in MVISION EDR.The script requires a hostname, search type, days and a limit to query the historical data store.
