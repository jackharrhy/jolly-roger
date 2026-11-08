"""Exercise the real browser bridge against a synthetic native GUI client."""

import pytest
from playwright.sync_api import sync_playwright

from jolly_roger.bell import BellRouter
from jolly_roger.bell_transport import BellBrowserTransport
from jolly_roger.router import RouterError

HTML = """<script>
window.rows = [{uid: 1200, Description: 'web', Enable: true, Protocol: 'TCP',
    InternalClient: '192.168.2.30', InternalPort: 443, ExternalPort: 443,
    ExternalPortEndRange: 0}];
window.calls = [];
window.jQuery = {gui: {client: {
    user: 'admin', isConnected: () => true,
    newRequest: options => {
        if (options.ajaxRetry !== false) throw Error('retries must be disabled');
        if (options.ajaxTimeout !== 30000) throw Error('timeout must use milliseconds');
        let execute;
        const target = path => rows.find(r => r.uid === Number(path.match(/@uid='([0-9]+)'/)[1]));
        return {
            getValue: (path, ok) => {execute = () => ok(JSON.parse(JSON.stringify({PortMapping: rows})));},
            setValue: (path, value, ok) => {execute = () => {calls.push(path);
                target(path)[path.split('/').pop()] = value; ok({});};},
            deleteElement: (path, ok) => {execute = () => {calls.push(path);
                rows.splice(rows.indexOf(target(path)), 1); ok({});};},
            send: () => execute()
        };
    }
}}};
</script>"""


def test_existing_browser_native_callbacks_and_guest_refusal():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.route(
            "http://127.0.0.1/**", lambda route: route.fulfill(body=HTML, content_type="text/html")
        )
        page.goto("http://127.0.0.1/")
        router = BellRouter(BellBrowserTransport(page, "http://127.0.0.1"))
        assert router.status().rules[0].enabled is True
        assert router.set_enabled(1200, False).enabled is False
        assert len(page.evaluate("calls")) == 1
        page.evaluate("jQuery.gui.client.user = 'guest'")
        with pytest.raises(RouterError):
            router.remove(1200)
        assert len(page.evaluate("calls")) == 1
        assert not page.is_closed()
        browser.close()
