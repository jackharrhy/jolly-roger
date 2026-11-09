from copy import deepcopy


def mapping(uid=1200, **fields):
    return {
        "uid": uid,
        "Description": "web",
        "Enable": True,
        "Status": "ENABLED" if fields.get("Enable", True) else "DISABLED",
        "Protocol": "TCP",
        "InternalClient": "192.168.2.30",
        "InternalPort": 8443,
        "ExternalPort": 443,
        "ExternalPortEndRange": 0,
        "LeaseStart": "0-12-31T20:30:00-0330",
        "Alias": "",
        "Service": "",
        **fields,
    }


class Gateway:
    def __init__(self, new_enabled=False):
        self.new_enabled = new_enabled
        self.rows = [mapping(), mapping(1, Alias="BELL_API_DMZ", Service="DMZ", ExternalPort=0)]
        self.calls = []
        self.corrupt = False

    def request(self, method, path, value=None):
        self.calls.append((method, path, value))
        if method == "getValue":
            return {"PortMappings": {"PortMapping": deepcopy(self.rows)}}
        if method == "addChild":
            self.rows.append(mapping(1201, Description="", Enable=self.new_enabled, ExternalPort=0))
            return {"uid": 1201}
        uid = int(path.split("[@uid='")[1].split("']")[0])
        row = next(r for r in self.rows if r["uid"] == uid)
        if method == "deleteChild":
            self.rows.remove(row)
        elif method == "setValue":
            field = path.rsplit("/", 1)[1]
            row[field] = value
            row["LeaseStart"] = "2026-01-02T00:00:00Z"
            if field == "Enable":
                row["Status"] = "ENABLED" if value else "DISABLED"
        if self.corrupt:
            self.rows[0]["InternalPort"] = 22
        return {}
