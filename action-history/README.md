# McAfee MVISION EDR Action History

This is a script to retrieve the action history from MVISION EDR. The script requires a username, password and a limit to query the action history.

Usage:

```sh
python3 mvision_edr_action_history.py -R <REGION>-U <USERNAME> -P <PASSWORD> -L <MAX RESULTS>

```

Example:

```sh
python3 mvision_edr_action_history.py -R EU -U username@test.com -P password -L 20
```

Output:

```
{
    "startIndex": 0,
    "itemsPerPage": 2,
    "currentItemCount": 2,
    "totalItems": 25,
    "items":
    [
        {
            "errorDescription": "",
            "errorCode": null,
            "status": "COMPLETED",
            "action": "DismissThreat",
            "creationDate": "2021-06-24T07:44:39.957+0000",
            "caseId": "061c4f20-d4c0-11eb-a9f8-000000000000",
            "threatId": "6188970",
            "hostsAffected": null,
            "userId": "email@email.com",
            "threatName": "WINWORD.EXE",
            "investigationName": "",
            "id": 9345
        },
        {
            "errorDescription": "",
            "errorCode": null,
            "status": "COMPLETED",
            "action": "DismissThreat",
            "creationDate": "2021-06-24T07:38:41.965+0000",
            "caseId": "27bf69b0-d4bf-11eb-a161-000000000000",
            "threatId": "6188919",
            "hostsAffected": null,
            "userId": "email@email.com",
            "threatName": "Z7HX7Hq7.exe",
            "investigationName": "",
            "id": 9344
        }
    ]
}
```
