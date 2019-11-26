# McAfee MVISION EDR Historical Search

This is a script to query the historical data store in MVISION EDR. The script requires a hostname, search type, days and a limit to query the historical data store. The days are referring to the timeframe. E.g search data from 3 days (starting point today).

The search type should include one of the following:

['ProcessCreated', 'PECreated', 'ScriptCreated', 'AdminHackingToolExecuted', 'ServiceChanged', 'NetworkConnection', 'ASEPCreatedOrModified', 'DNSQuery', 'LoadedDLLs', 'UserAccounts']

Usage:

```sh
python mvision_edr_hist_search.py -U <USERNAME> -P <PASSWORD> -H <HOSTNAME> -T <SEARCHTYPE> -D <DAYS> -L <MAX RESULTS>

```

Example:

```sh
python mvision_edr_hist_search.py -U username@test.com -P password -H hostname -T DNSQuery -D 1 -L 20
```
