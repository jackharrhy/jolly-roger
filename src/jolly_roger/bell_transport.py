"""Bell XMO transports; never export browser cookies or log authentication data."""

import hashlib
import json
import re
import secrets

import httpx

from .bell import PATH
from .browser import gateway_origin
from .router import RouterError

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
        except RouterError:
            # Session cleanup must not mask the original operation's outcome.
            pass
        finally:
            self.client.close()
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


BROWSER_REQUEST = r"""({origin, method, path, value}) => new Promise(resolve => {
    if (location.origin !== origin) return resolve({error: true});
    const gui = window.jQuery && jQuery.gui;
    const client = gui && gui.client;
    if (!client || !client.isConnected() || !client.user || client.user === 'guest')
        return resolve({error: true});
    const timer = setTimeout(() => resolve({error: true}), 30000);
    const finish = result => { clearTimeout(timer); resolve(result); };
    const fail = () => finish({error: true});
    try {
        const request = client.newRequest({ajaxRetry: false, ajaxTimeout: 30000,
            requestErrorFunc: fail, ajaxErrorFunc: fail});
        const success = result => finish({value: result === undefined ? {} : result});
        if (method === 'getValue') request.getValue(path, success, fail);
        else if (method === 'setValue') request.setValue(path, value, success, fail);
        else if (method === 'addChild') request.addChild(path, value,
            (_reply, callback) => success({uid: callback.parameters.uid}), fail);
        else if (method === 'deleteChild') request.deleteElement(path, success, fail);
        else return fail();
        request.send(undefined, fail);
    } catch (_) { fail(); }
})"""


class BellBrowserTransport:
    def __init__(self, page, gateway):
        self.page = page
        self.origin = gateway_origin(gateway)

    def request(self, method, path, value=None):
        allowed(method, path)
        try:
            result = self.page.evaluate(
                BROWSER_REQUEST,
                {
                    "origin": self.origin,
                    "method": method,
                    "path": path,
                    "value": value,
                },
            )
            if not isinstance(result, dict) or result.get("error") or "value" not in result:
                raise RouterError(
                    "Bell browser session/request unavailable; inspect state before retrying"
                )
            return result["value"]
        except RouterError:
            raise
        except Exception:
            raise RouterError(
                "Bell browser request failed; inspect state before retrying"
            ) from None
