# McAfee MVISION EDR Threats (Monitoring)

This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard). The script requires a username, password, details (True/False), days and a limit to query the threats.

Further the script allows to retrieve additional details about the threat itself (-DT / --details flag). This includes the detections and affected systems. 

Usage:

```sh
python mvision_edr_threats.py -R <REGION> -U <USERNAME> -P <PASSWORD> -DT <DETAILS> -D <DAYS> -L <MAX RESULTS>
```

Example:

```sh
python mvision_edr_threats.py -R EU -U username@test.com -D 3 -L 100
```
