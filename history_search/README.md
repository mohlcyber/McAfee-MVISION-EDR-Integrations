# McAfee MVISION EDR Historical Search

This is a script to query the historical data store in MVISION EDR. The script requires a hostname, days and a limit to query the historical data store. The days are referring to the timeframe. E.g search data from 3 days (starting point today).

Usage:

```sh
python mvision_edr_hist_search.py -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> -D <DAYS> -L <MAX RESULTS>

```

Example:

```sh
python mvision_edr_hist_search.py -U username@test.com -P password -H hostname -D 1 -L 20
```
