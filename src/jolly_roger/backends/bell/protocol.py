"""Bell XMO forwarding scope and identifiers; not a generic router protocol."""

import re

from ...models import RouterError, positive

PATH = "Device/NAT/PortMappings"


def parse_id(value):
    return positive(value, 4294967295)


FIELDS = "Description|Enable|Protocol|InternalClient|InternalPort|ExternalPort|ExternalPortEndRange"


def allowed(method, path):
    if method in ("getValue", "addChild") and path == PATH:
        return
    prefix = re.escape(PATH) + r"/PortMapping\[@uid='[1-9][0-9]{0,9}'\]"
    if method == "deleteChild" and re.fullmatch(prefix, path):
        return
    if method == "setValue" and re.fullmatch(prefix + "/(" + FIELDS + ")", path):
        return
    raise RouterError("Bell request outside forwarding scope; no request sent")


def row_id(row):
    value = row.get("uid", row.get("@uid"))
    if "uid" in row and "@uid" in row and row["uid"] != row["@uid"]:
        raise RouterError("Conflicting Bell mapping identifiers")
    return parse_id(value)


def node(id):
    return f"{PATH}/PortMapping[@uid='{parse_id(id)}']"
