"""
Restore a FortiGate configuration from a file previously saved by
backup_config.py.

WARNING: this overwrites the running configuration and the FortiGate may
reboot / drop the API session as a result. Double-check the file path
before confirming.

Usage:
  python restore_config.py backups/fortigate-2026-06-12_153000.conf
"""

import json
import sys
from pathlib import Path

from fortigate_api import FortiGateAPI

CONFIG_PATH = Path(__file__).parent / "config.json"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python restore_config.py <backup-file>")

    backup_file = Path(sys.argv[1])
    if not backup_file.exists():
        raise SystemExit(f"Backup file not found: {backup_file}")

    if not CONFIG_PATH.exists():
        raise SystemExit(
            f"Missing {CONFIG_PATH}. Copy config.example.json to config.json "
            "and fill in host/token."
        )
    config = json.loads(CONFIG_PATH.read_text())

    print(f"About to restore {backup_file} onto {config['host']}.")
    print("This OVERWRITES the running configuration and may reboot the FortiGate.")
    answer = input("Type 'yes' to continue: ")
    if answer.strip().lower() != "yes":
        print("Aborted.")
        return

    fg = FortiGateAPI(host=config["host"], token=config["token"])
    result = fg.restore_config(backup_file.read_text())
    print(f"[+] Restore response: {result}")


if __name__ == "__main__":
    main()
