# FortiGate REST API Automation

A small reusable client (`fortigate_api.py`) for the FortiOS v2 REST API
(token auth, firewall address objects, address groups). Drop in your
FortiGate's host/token and write any script on top of it - e.g. block an
attacker IP, bulk-create address objects, or query system status, the kind
of action a SOAR playbook or Wazuh active-response hook would trigger
automatically.

## 1. Create a REST API admin on FortiGate

On the FortiGate CLI (`ssh admin@192.168.120.200`):

```
config system accprofile
    edit "api-automation"
        set fwgrp-permission read-write
        set sysgrp-permission read-write
    next
end

config system api-user
    edit "automation"
        set accprofile "api-automation"
        set vdom "root"
        config trusthost
            edit 1
                set ipv4-trusthost 192.168.120.0 255.255.255.0
            next
        end
    next
end

execute api-user generate-key automation
```

Copy the generated token - it is shown only once.

## 2. Configure

```bash
pip install requests
cp config.example.json config.json   # fill in host + token, not committed
```

## 3. Use it

```python
from fortigate_api import FortiGateAPI
import json

config = json.load(open("config.json"))
fg = FortiGateAPI(host=config["host"], token=config["token"])

print(fg.system_status())
fg.create_address("blocked-192.168.120.130", "192.168.120.130", comment="SSH brute-force source")
fg.add_to_addrgrp("Blocked-IPs", "blocked-192.168.120.130")
```

## Backup before experimenting

Before trying out new policy/VLAN/routing automation against the lab, take a
config snapshot so you can restore it if something breaks:

```bash
python backup_config.py
```

Saves the full running config to `backups/fortigate-<timestamp>.conf`
(gitignored - contains ENC-encrypted secrets).

## Restoring a backup

```bash
python restore_config.py backups/fortigate-2026-06-12_153000.conf
```

Prompts for confirmation before uploading - **this overwrites the running
config and the FortiGate may reboot / drop the API session**. Alternatively
restore manually via System > Firmware & Configuration > Restore in the GUI,
or `execute restore config` on the CLI.

## Files

- `fortigate_api.py` - generic REST client (auth, system status, config backup/restore, firewall address objects, address groups)
- `backup_config.py` - downloads the running config with a timestamp into `backups/`
- `restore_config.py` - restores a config file back onto the FortiGate (with confirmation prompt)
- `config.example.json` - config template (`config.json` is gitignored)
