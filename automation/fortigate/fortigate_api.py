"""
Reusable FortiGate REST API client.

Wraps the FortiOS v2 REST API (https://<host>/api/v2/...) using a Bearer
API token. Provides generic request helpers plus a few firewall object
operations that any automation script can build on.

Auth: create a REST API admin on the FortiGate and generate a token first,
see automation/fortigate/README.md.
"""

import requests

requests.packages.urllib3.disable_warnings()


class FortiGateAPI:
    def __init__(self, host, token, verify=False, timeout=10):
        self.base_url = f"https://{host}/api/v2"
        self.token = token
        self.verify = verify
        self.timeout = timeout

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def _request(self, method, path, **kwargs):
        url = f"{self.base_url}{path}"
        resp = requests.request(
            method,
            url,
            headers=self._headers(),
            verify=self.verify,
            timeout=self.timeout,
            **kwargs,
        )
        resp.raise_for_status()
        return resp.json()

    def get(self, path, params=None):
        return self._request("GET", path, params=params)

    def post(self, path, data):
        return self._request("POST", path, json=data)

    def put(self, path, data):
        return self._request("PUT", path, json=data)

    def delete(self, path):
        return self._request("DELETE", path)

    # --- system ---

    def system_status(self):
        return self.get("/monitor/system/status")

    def backup_config(self, scope="global"):
        """Download the full running configuration as plain text (CLI format).

        Unlike other endpoints this returns raw text, not JSON, so it
        bypasses _request()/resp.json().
        """
        url = f"{self.base_url}/monitor/system/config/backup"
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {self.token}"},
            params={"scope": scope},
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.text

    def restore_config(self, config_text, scope="global"):
        """Upload a configuration file to restore the FortiGate config.

        WARNING: this overwrites the running configuration and the
        FortiGate may reboot/drop the session as a result. Multipart
        upload, so it bypasses _request()'s JSON Content-Type header.
        """
        url = f"{self.base_url}/monitor/system/config/restore"
        files = {"file": ("restore.conf", config_text, "text/plain")}
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {self.token}"},
            params={"scope": scope},
            files=files,
            verify=self.verify,
            timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.json()

    # --- firewall address objects ---

    def get_address(self, name):
        return self.get(f"/cmdb/firewall/address/{name}")

    def address_exists(self, name):
        try:
            self.get_address(name)
            return True
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return False
            raise

    def create_address(self, name, ip, mask="255.255.255.255", comment=""):
        data = {
            "name": name,
            "subnet": f"{ip} {mask}",
            "type": "ipmask",
            "comment": comment,
        }
        return self.post("/cmdb/firewall/address", data)

    def delete_address(self, name):
        return self.delete(f"/cmdb/firewall/address/{name}")

    # --- firewall address groups ---

    def get_addrgrp(self, name):
        return self.get(f"/cmdb/firewall/addrgrp/{name}")

    def addrgrp_members(self, name):
        result = self.get_addrgrp(name)
        members = result["results"][0].get("member", [])
        return [m["name"] for m in members]

    def add_to_addrgrp(self, group, member_name):
        members = self.addrgrp_members(group)
        if member_name in members:
            return None  # already present, nothing to do
        members.append(member_name)
        data = {"member": [{"name": m} for m in members]}
        return self.put(f"/cmdb/firewall/addrgrp/{group}", data)

    def remove_from_addrgrp(self, group, member_name):
        members = self.addrgrp_members(group)
        if member_name not in members:
            return None
        members.remove(member_name)
        data = {"member": [{"name": m} for m in members]}
        return self.put(f"/cmdb/firewall/addrgrp/{group}", data)
