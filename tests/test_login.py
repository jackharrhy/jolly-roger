import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs


def test_dotenv_login_and_verified_write(tmp_path):
    state = {"enabled": False, "logins": 0}

    class Gateway(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, text, cookie=False):
            self.send_response(200)
            if cookie:
                self.send_header("Set-Cookie", "session=synthetic; HttpOnly")
            self.end_headers()
            self.wfile.write(text.encode())

        def do_GET(self):
            if self.path == "/index.jst":
                return self.reply('<form action="check.jst" method="post"></form>')
            if self.headers.get("Cookie") != "session=synthetic":
                return self.reply("Please Login First!")
            assert self.path == "/port_forwarding.jst"
            self.reply(
                '<script>var token = "synthetic-token"; state: '
                + str(state["enabled"]).lower()
                + ' ? "on" : "off";</script>'
            )

        def do_POST(self):
            fields = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode())
            if self.path == "/check.jst":
                state["logins"] += 1
                valid = fields == {"username": ["admin"], "password": ["synthetic-password"]}
                return self.reply("login result", cookie=valid)
            assert self.path == "/actionHandler/ajax_port_forwarding.jst"
            assert self.headers.get("Cookie") == "session=synthetic"
            assert fields["csrfp_token"] == ["synthetic-token"]
            state["enabled"] = fields["UFWDStatus"] == ["Enabled"]
            self.reply('""')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"JOLLY_ROGER_GATEWAY=http://127.0.0.1:{server.server_port}\n"
        "JOLLY_ROGER_USERNAME=admin\nJOLLY_ROGER_PASSWORD=synthetic-password\n"
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("JOLLY_ROGER_")}
    try:

        def run(*args, extra=None):
            return subprocess.run(
                [sys.executable, "-m", "jolly_roger", *args],
                cwd=tmp_path,
                env=env | (extra or {}),
                capture_output=True,
                text=True,
                timeout=15,
            )

        result = run("global-enable", "--yes")
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["enabled"] is True
        assert state["enabled"] is True
        failed = run("status", extra={"JOLLY_ROGER_PASSWORD": "wrong-synthetic-password"})
        assert failed.returncode == 2
        assert "login" in failed.stderr.lower()
        assert "wrong-synthetic-password" not in failed.stderr
        assert state["logins"] == 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
