# McAfee MVISION EDR Action History

This is a script to retrieve the action history from MVISION EDR. The script requires a username, password and a limit to query the action history.

Usage:

```sh
python mvision_edr_action_history.py -U <USERNAME> -P <PASSWORD> -L <MAX RESULTS>

```

Example:

```sh
python mvision_edr_action_history.py -U username@test.com -P password -L 20
```
