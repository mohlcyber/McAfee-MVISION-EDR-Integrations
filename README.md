# MVISION EDR Integrations

This is a collection of different MVISION EDR integration scripts. 

## Client Credential Generator

To authenticate against the MVISION EDR API, client credentials need to be generated with the [MVISION EDR Credential Generator](mvision_edr_creds_generator.py) first.

1. Log on to MVISION EPO Console using your credentials
2. Go to "Appliance and Server Registration" page from the menu

   ![1](https://user-images.githubusercontent.com/25227268/165046594-7af12d3c-a6fd-43fc-b88f-0381b08b1b9c.png)
3. Click on "Add" button
4. Choose client type "MVISION Endpoint Detection and Response"
5. Enter number of clients (1)

   ![2](https://user-images.githubusercontent.com/25227268/165046797-2a913460-9f84-480e-a3a5-a9c358467e32.png)
6. Click on the "Save" button
7. Copy the "Token" value from the table under the section "MVISION Endpoint Detection and Response"

   ![3](https://user-images.githubusercontent.com/25227268/165047049-6a40a72e-84fc-42a1-80ae-7bbfff9b56e5.png)
8. Pass the token value as the input parameter to the [mvision_edr_creds_generator.py](mvision_edr_creds_generator.py) script
9. The script will generate the client_id, client_secret and print on the output console / writes the output to a file (optional)
10. Use the client_id, client_secret for authentication against the MVISION EDR API

## Sample Scripts 

[MVISION EDR Action History](action-history):
This is a script to retrieve the action history from MVISION EDR.

[MVISION EDR Activity Feeds Script](activity-feeds): 
This is a script to consume activity feeds from MVISION EDR.
The script contains various modules to ingest trace data into e.g. ServiceNow, TheHive, Syslog or Email.

[MVISION EDR Device Search](device-search):
This is a script to query the device search in MVISION EDR.

[MVISION EDR Real-Time-Search and Reaction Script](real-time-search-reaction): 
This is a collections of scripts that will start RTS for hashes or process and provides the ability to execute reactions.

[MVISION EDR Threats](threats-monitoring):
This is a script to retrieve the threat detections from MVISION EDR (Monitoring Dashboard).
