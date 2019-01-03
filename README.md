# alarm-server
## Installing
alarm-server requires some python dependencies to run. 

```bash
pip install paho-mqtt
pip install python-daemon
```

## Configuring the Server
### MQTT Server Configuration
- If your MQTT server is running locally or on the same box as the server listener, you can likely leave the settings as default.
- If you need to adjust anything, you can do so in `alarmserver.conf`

### Configuring allowed panel addresses
- Allowed panel addresses should be entered in tab separated format innto `/etc/alarmserver/accounts.conf` (or wherever you configure this file to be - see `alarmserver.conf`)
- Example: `1234 192.168.1.2` where `1234` is the account number you configure in Wintex/On Panel.
## Configuring the Alarm Panel
The simplest method to configure the server and panel communication is to use Wintex to configure the ARC settings.
### Using Wintex
> Disclaimer! It's easy to overwrite configurations, misconfigure or break your panel's current working configuration using Wintex. Please be sure you're confident in using wintex before proceeding - and always remember to take a backup, or at the very least receive all data first!
- Connect to your Panel
- Navigate to the Comms page
- Select the `ARCs` tab
- Find an empty ARC slot
- Enter the IP address and port of your server in the `Pri Tel No` field in the format `ip/port` (For example `192.168.1.92/10500`)
- Ensure `Connect via IP` is checked
- Save / send current page.

## Running the Server
```bash
python alarmrx.py
```

## Subscribing to Messages
Topics:
- /alarms/{account-num}/event
- /alarms/{account-num}/message
- /alarms/{account-num}/status
