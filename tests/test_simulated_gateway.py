"""End-to-end SIMULATION: real CLI + CDP Chromium + synthetic localhost gateway.

No real router, authentication service, or public network is contacted.
"""

import html
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from playwright.sync_api import sync_playwright
from test_cli import run


def test_simulated_gateway_full_cli_lifecycle():
    rules = {
        7: dict(
            name="existing-synthetic",
            protocol="UDP",
            ip="10.0.0.41",
            start=54320,
            end=54320,
            enabled=True,
        )
    }
    original = dict(rules[7])
    state = {"enabled": False, "gated": False}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, body, status=200, login=False):
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            if login:
                self.send_header(
                    "Set-Cookie", "synthetic_session=authenticated; HttpOnly; SameSite=Strict"
                )
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            requests.append(("GET", self.path))
            if self.path == "/":
                return self.send("<h1>Synthetic login</h1>", login=True)
            if self.headers.get("Cookie") != "synthetic_session=authenticated":
                return self.send("unauthenticated", 401)
            if self.path == "/port_forwarding.jst":
                body = '<script>var token = "synthetic-csrf";'
                body += '$("#pf_switch").radioswitch({state: ' + str(state["enabled"]).lower()
                body += ' ? "on" : "off"});</script>'
                if not state["gated"]:
                    body += '<table summary="This table list available port forwarding entries">'
                    for id, r in rules.items():
                        cells = {
                            "service-name": r["name"],
                            "service-type": r["protocol"],
                            "start-port": r["start"],
                            "end-port": r["end"],
                            "server-ip": r["ip"],
                            "server-ipv6": "",
                        }
                        body += "<tr>" + "".join(
                            f'<td headers="{k}">{html.escape(str(v))}</td>'
                            for k, v in cells.items()
                        )
                        checked = " checked" if r["enabled"] else ""
                        body += f'<td><input type="checkbox" name="PortActive" id="PortActive_{id}"{checked}></td></tr>'
                    body += "</table>"
                return self.send(body)
            if self.path.startswith("/port_forwarding_edit.jst?id="):
                id = int(self.path.split("=")[1])
                if id not in rules:
                    return self.send('<script>location.href="port_forwarding.jst";</script>')
                r = rules[id]
                return self.send(f'''<script>var ID = "{id}"; var jsV6ServerIP = "x";
                    var service_name='{r["name"]}'; var startport='{r["start"]}';
                    var endport='{r["end"]}';</script>''')
            return self.send("unexpected path", 404)

        def do_POST(self):
            fields = {
                k: v[0]
                for k, v in parse_qs(
                    self.rfile.read(int(self.headers["Content-Length"])).decode()
                ).items()
            }
            requests.append(("POST", self.path))
            if (
                self.path != "/actionHandler/ajax_port_forwarding.jst"
                or self.headers.get("Cookie") != "synthetic_session=authenticated"
                or fields.pop("csrfp_token", None) != "synthetic-csrf"
            ):
                return self.send("unauthenticated", 403)
            if "set" in fields:
                state["enabled"] = fields["UFWDStatus"] == "Enabled"
            elif "add" in fields:
                rules[12] = dict(
                    name=fields["name"],
                    protocol=fields["type"],
                    ip=fields["ip"],
                    start=int(fields["startport"]),
                    end=int(fields["endport"]),
                    enabled=True,
                )
            elif "active" in fields:
                rules[int(fields["id"])]["enabled"] = fields["isChecked"] == "true"
            elif "del" in fields:
                del rules[int(fields["del"])]
            else:
                return self.send("unexpected operation", 400)
            return self.send('"Success!"')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    with socket.socket() as socket_:
        socket_.bind(("127.0.0.1", 0))
        cdp_port = socket_.getsockname()[1]
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=[f"--remote-debugging-port={cdp_port}"])
            page = browser.new_page()
            page.goto(origin)

            def command(*args, success=True):
                result = run(
                    "--gateway", origin, "--cdp-url", f"http://127.0.0.1:{cdp_port}", *args
                )
                assert result.returncode == (0 if success else 2), result.stderr
                assert "synthetic-csrf" not in result.stdout + result.stderr
                assert "synthetic_session" not in result.stdout + result.stderr
                return json.loads(result.stdout) if success else result.stderr

            assert command("status")["enabled"] is False
            assert len(command("list")["rules"]) == 1
            assert "global-enable" in command("remove", "7", "--yes", success=False)
            assert command("global-enable", "--yes")["enabled"] is True
            created = command(
                "add",
                "--name",
                "temporary-synthetic",
                "--protocol",
                "TCP",
                "--ip",
                "10.0.0.42",
                "--start",
                "54321",
                "--end",
                "54322",
                "--yes",
            )
            assert created["id"] == 12
            assert command("disable", "12", "--yes")["enabled"] is False
            assert command("enable", "12", "--yes")["enabled"] is True
            assert command("remove", "12", "--yes")["verified"] is True
            state["gated"] = True
            gated = command("list")
            assert gated["complete"] is False
            scanned = command("scan", "--max-id", "8")
            assert scanned["complete"] is False
            assert [r["id"] for r in scanned["rules"]] == [7]
            before = list(requests)
            error = command(
                "add",
                "--name",
                "temporary-synthetic",
                "--protocol",
                "TCP",
                "--ip",
                "10.0.0.42",
                "--start",
                "54321",
                "--scan-max-id",
                "8",
                "--yes",
                success=False,
            )
            assert "state" in error
            assert not any(r[0] == "POST" for r in requests[len(before) :])
            assert command("global-disable", "--yes")["enabled"] is False
            assert browser.is_connected()
            assert page.url.rstrip("/") == origin
            browser.close()
        assert rules == {7: original}
        assert not any(method == "GET" and "actionHandler" in path for method, path in requests)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
