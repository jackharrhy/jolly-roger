"""Synthetic local HTTP gateway; never contacts a router."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest


def test_browser_same_origin_fetch_and_private_token():
    from playwright.sync_api import sync_playwright

    from jolly_roger.browser import BrowserTransport
    from jolly_roger.router import RouterError

    calls = []
    mode = {"token": True, "redirect": False, "response": '"Success!"'}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            calls.append(("GET", self.path))
            if mode["redirect"]:
                self.send_response(302)
                self.send_header("Location", "/actionHandler/ajax_port_forwarding.jst")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            token = (
                '<script>var token = "synthetic-private-token";</script>' if mode["token"] else ""
            )
            self.wfile.write((token + "<h1>Synthetic gateway</h1>").encode())

        def do_POST(self):
            fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            calls.append(("POST", self.path, fields))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(mode["response"].encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(origin)
            transport = BrowserTransport(page, origin)
            html = transport.get("port_forwarding.jst")
            assert "synthetic-private-token" not in html
            assert "Synthetic gateway" in html
            assert (
                transport.post({"active": "true", "isChecked": "false", "id": "7"}) == '"Success!"'
            )
            post = next(c for c in calls if c[0] == "POST")
            assert post[1] == "/actionHandler/ajax_port_forwarding.jst"
            assert post[2]["csrfp_token"] == ["synthetic-private-token"]
            for path in [
                "actionHandler/ajax_port_forwarding.jst",
                "../index.jst",
                "http://example.com/",
                "port_forwarding_edit.jst?id=07",
            ]:
                with pytest.raises(RouterError):
                    transport.get(path)
            assert not any(c[0] == "GET" and "actionHandler" in c[1] for c in calls)
            with pytest.raises(RouterError):
                BrowserTransport(page, "http://10.0.0.1").get("port_forwarding.jst")
            mode["token"] = False
            count = len([c for c in calls if c[0] == "POST"])
            with pytest.raises(RouterError, match="token"):
                transport.post({"del": "7"})
            assert len([c for c in calls if c[0] == "POST"]) == count
            mode["token"] = True
            mode["response"] = "<html>Login synthetic-private-token</html>"
            with pytest.raises(RouterError) as exc:
                transport.post({"del": "7"})
            assert "synthetic-private-token" not in str(exc.value)
            mode["redirect"] = True
            with pytest.raises(RouterError):
                transport.get("port_forwarding.jst")
            assert not any(c[0] == "GET" and "actionHandler" in c[1] for c in calls)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
