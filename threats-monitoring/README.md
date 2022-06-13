# MVISION EDR Threats (Monitoring)

This is a script to retrieve threats and detections from MVISION EDR (Monitoring Dashboard).

The following steps describe an example to run the provided script as a service under a Linux Operating system (CentOS).
The script requires various parameters to execute incl. MVISION EDR Tenant Region, ClientId and ClientSecret.

There are multiple ways in securely provide credentials to the script. 
- Password Vaults like Vault from Hashicorp (https://www.vaultproject.io/) or python vaults to store credentials securely. 
- Using a hidden .env file to store credentials and provide credentials in form of environment variables to the script.

The latter example will be described below.

**Important** 

Client_ID and Client_Secrets can get generated with the [mvision_edr_creds_generator.py](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations/blob/master/mvision_edr_creds_generator.py) script posted in the main [repository](https://github.com/mohlcyber/McAfee-MVISION-EDR-Integrations).

## Configuration

1. Place the script in an accessible directory e.g.

   ```
   /opt/script/mvision_edr_threats.py
   ```


2. Make sure the following dependencies are installed

   ```
   python3 -m pip install requests python-dotenv python-dateutil pytz
   ```


3. Create a new file called .env in the same directory as the provided script (e.g. /opt/script/.env) and provide all required parameters. Leave empty if parameter does not apply.

   ```
   vim /opt/script/.env
   ```

   Content:
   ```
   # EDR settings (required)
   EDR_REGION = US-E
   EDR_CLIENT_ID = 
   EDR_CLIENT_SECRET =

   # Pulling Interval in seconds (required)
   INTERVAL  = 300

   # Initial Pull in days
   INITIAL_PULL = 3

   # SYSLOG settings (optional)
   SYSLOG_IP =
   SYSLOG_PORT =
   
   # Cache File location (required)
   CACHE_DIR = /opt/script

   # Proxy settings (optional)
   PROXY =
   VALID =

   # Logging (required)
   LOG_LEVEL = DEBUG
   LOG_DIR = /opt/script/logs

   # Write Threat Detections into File (optional)
   THREAT_LOG = True
   THREAT_DIR = /opt/script/threats
   ```

4. Create a new file in the service directory

   ```
   vim /etc/systemd/system/mvision_edr_threats.service
   ```

   Content:
   ```
   [Unit]
   Description=MVISION EDR Threat Pull
   After=network-online.target
   Wants=network-online.target

   [Service]
   Type=simple
   WorkingDirectory=/opt/script
   ExecStart=/usr/bin/python3 /opt/script/mvision_edr_threats.py
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

5. Restart the systemctl daemon loader
   
   ```
   systemctl daemon-reload
   ```
   
6. Start the service

   ```
   systemctl start mvision_edr_threats.service
   ```
   To start the service on system startup execute the following command

   ```
   systemctl enable mvision_edr_threats.service
   ```
   
7. Check the status of the service
   
   ```
   systemctl status mvision_edr_threats.service
   ```
   ![1](https://user-images.githubusercontent.com/25227268/173325218-0f6413fa-c44d-4509-8d3d-44eca0b9c726.png)

8. You can also check the logs of the service

   ```
   tail -f /opt/script/logs/mvedr_logger.log
   ```
   ![2](https://user-images.githubusercontent.com/25227268/173325628-7a044943-4df3-422e-a05e-764e3826c97e.png)
