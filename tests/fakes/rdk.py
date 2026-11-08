GLOBAL = '<script>$("#pf_switch").radioswitch({state: true ? "on" : "off"});</script>'


ROW = """<tr><td headers="service-name">synthetic</td><td headers="service-type">TCP</td>
<td headers="start-port">54321</td><td headers="end-port">54322</td>
<td headers="server-ip">10.0.0.42</td><td headers="server-ipv6"></td>
<td headers="active"><input type="checkbox" name="PortActive" id="PortActive_7" checked></td>
<td><a href="port_forwarding_edit.jst?id=7">Edit</a></td></tr>"""


def listing(row=ROW):
    return (
        GLOBAL
        + '<table summary="This table list available port forwarding entries">'
        + row
        + "</table>"
    )


class SyntheticTransport:
    def __init__(self, pages, response='"Success!"'):
        self.pages = iter(pages)
        self.response = response
        self.writes = []
        self.reads = []

    def get(self, path):
        self.reads.append(path)
        return next(self.pages)

    def post(self, fields):
        self.writes.append(fields)
        return self.response
