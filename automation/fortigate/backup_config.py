"""
Download the full FortiGate configuration and save it locally with a
timestamp - run this before experimenting with policies/VLANs/routing via
the API, so you can restore from the file (System > Firmware & Configuration
> Restore, or `execute restore config`) if something breaks.

Usage:
  python backup_config.py
"""

import json
from datetime import datetime
from pathlib import Path

from fortigate_api import FortiGateAPI

CONFIG_PATH = Path(__file__).parent / "config.json"
BACKUP_DIR = Path(__file__).parent / "backups"


def main():
    if not CONFIG_PATH.exists():
        raise SystemExit(
            f"Missing {CONFIG_PATH}. Copy config.example.json to config.json "
            "and fill in host/token."
        )
    config = json.loads(CONFIG_PATH.read_text())

    fg = FortiGateAPI(host=config["host"], token=config["token"])
    backup_text = fg.backup_config()

    BACKUP_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    out_path = BACKUP_DIR / f"fortigate-{timestamp}.conf"
    out_path.write_text(backup_text)

    print(f"[+] Saved config backup to {out_path} ({len(backup_text)} bytes)")


if __name__ == "__main__":
    main()
