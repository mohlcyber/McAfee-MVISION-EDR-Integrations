# MVISION EDR Action History

This is a script to retrieve the action history from MVISION EDR. 

The script requires tenant_region, client_id and client_secret to pull the action history. 
Client_ID and Client_Secrets can get generated with the [mvision_edr_creds_generator.py](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations/blob/master/mvision_edr_creds_generator.py) script posted in the main [repository](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations).

Usage: 

```sh
usage: python mvision_edr_action_history.py -R <REGION> -C <CLIENT_ID> -S <CLIENT_SECRET> -P <PROXY> -L <LIMIT> -L <LOG_LEVEL>

MVISION EDR Python API

optional arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --proxy {True,False}, -P {True,False}
                        Provide Proxy JSON in line 35
  --limit LIMIT, -L LIMIT
                        Set the maximum number of events returned
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Set Log Level

```

Output:

```
{
    "currentItemCount": 2,
    "items":
    [
        {
            "action": "removeFile",
            "caseId": null,
            "creationDate": "2022-04-25T14:36:55.812+0000",
            "errorCode": null,
            "errorDescription": "",
            "hostsAffected": 1,
            "id": 56850,
            "investigationName": null,
            "status": "COMPLETED",
            "threatId": null,
            "threatName": null,
            "userId": "nice@try.com"
        },
        {
            "action": "killProcess",
            "caseId": null,
            "creationDate": "2022-04-25T14:22:58.598+0000",
            "errorCode": null,
            "errorDescription": "",
            "hostsAffected": 1,
            "id": 56847,
            "investigationName": null,
            "status": "COMPLETED",
            "threatId": null,
            "threatName": null,
            "userId": "nice@try.co"
        }
    ],
    "itemsPerPage": 2,
    "startIndex": 0,
    "totalItems": 60
}
```
