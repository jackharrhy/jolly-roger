"""CLI-owned Bell XMO authentication and HTTP session."""

import hashlib
import json
import re
import secrets

import httpx

from ...gateway import gateway_origin
from ...models import RouterError
from .protocol import allowed


class BellHttpTransport:
    def __init__(self, gateway, *, transport=None):
        self.client = httpx.Client(
            base_url=gateway_origin(gateway),
            timeout=30,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )
        self.session = 0
        self.index = 0
        self.nonce = ""
        self.username = ""
        self.password_hash = ""
        self.algorithm = ""

    def close(self):
        try:
            if self.session:
                self._send("logOut")
        finally:
            try:
                self.client.close()
            finally:
                self.session = 0
                self.password_hash = ""
                self.nonce = ""

    def _hash(self, value):
        return hashlib.new(self.algorithm, value.encode()).hexdigest()

    def login(self, username, password):
        try:
            r = self.client.get("/gui/js/gui-core.js")
            r.raise_for_status()
            flag = re.findall(r"GUI_ACTIVATE_SHA512ENCODE_OPT\s*:\s*([01])\b", r.text)
            salt = re.findall(r'GUI_PASSWORD_SALT\s*:\s*"([^"\\]*)"', r.text)
            if len(flag) != 1 or len(salt) != 1:
                raise RouterError("Unknown Bell authentication settings; no login sent")
            self.algorithm = "sha512" if flag[0] == "1" else "md5"
            self.username = username
            self.password_hash = self._hash(password + (":" + salt[0] if salt[0] else ""))
            parameters = self._send(
                "logIn",
                parameters={
                    "user": username,
                    "persistent": "true",
                    "session-options": {
                        "nss": [{"name": "gtw", "uri": "http://sagemcom.com/gateway-data"}],
                        "context-flags": {
                            "get-content-name": True,
                            "local-time": True,
                            "no-default": False,
                        },
                        "capability-depth": 2,
                        "depth": 2,
                        "compatibility-flags": {"flags": True, "default-value": True, "type": True},
                        "write-only-string": "_XMO_WRITE_ONLY_",
                        "undefined-write-only-string": "_XMO_UNDEFINED_WRITE_ONLY_",
                        "capability-flags": {
                            "name": True,
                            "default-value": False,
                            "restriction": True,
                            "description": False,
                        },
                        "time-format": "ISO_8601",
                    },
                },
            )
            if type(parameters.get("id")) not in (int, str) or not parameters.get("nonce"):
                raise RouterError("Bell session could not be verified")
            self.session = parameters["id"]
            self.nonce = parameters["nonce"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            raise RouterError("Bell login failed; inspect credentials/firmware, no retry") from None

    def _send(self, method, path=None, parameters=None):
        action = {"id": 0, "method": method}
        if path is not None:
            action["xpath"] = path
        if parameters is not None:
            action["parameters"] = parameters
        cnonce = secrets.randbelow(4294967295)
        index = self.index
        self.index += 1
        ha1 = self._hash(f"{self.username}:{self.nonce}:{self.password_hash}")
        request = {
            "id": index,
            "session-id": "0" if method == "logIn" else self.session,
            "priority": method == "logIn",
            "cnonce": cnonce,
            "auth-key": self._hash(f"{ha1}:{index}:{cnonce}:JSON:/cgi/json-req"),
            "actions": [action],
        }
        try:
            response = self.client.post(
                "/cgi/json-req", data={"req": json.dumps({"request": request})}
            )
            response.raise_for_status()
            reply = response.json()["reply"]
            if reply["error"]["code"] != 16777216:
                raise RouterError("Bell request rejected; inspect state before retrying")
            actions = reply["actions"]
            if (
                len(actions) != 1
                or actions[0]["id"] != 0
                or actions[0]["error"]["code"] != 16777238
            ):
                raise RouterError("Bell action failed; inspect state before retrying")
            callbacks = actions[0]["callbacks"]
            if len(callbacks) != 1 or callbacks[0]["result"]["code"] != 16777238:
                raise RouterError("Bell callback failed; inspect state before retrying")
            return callbacks[0].get("parameters", {})
        except (httpx.HTTPError, ValueError, KeyError, TypeError, IndexError):
            raise RouterError(
                "Bell request failed; outcome unknown, inspect before retrying"
            ) from None

    def request(self, method, path, value=None):
        allowed(method, path)
        if not self.session:
            raise RouterError("Bell authenticated session required")
        params = {"value": value} if method in ("setValue", "addChild") else None
        result = self._send(method, path, params)
        if method == "getValue":
            if "value" not in result:
                raise RouterError("Bell collection response missing")
            return result["value"]
        return result
