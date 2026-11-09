"""Use the attached Bell GUI session; no credentials or cookies leave Chromium."""

from ...gateway import gateway_origin
from ...models import RouterError
from .protocol import allowed

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
