# jolly-roger

Port forward your router without the app.

A Python CLI for local Rogers/RDK and Bell/Sagemcom gateways. Detect the gateway,
list mappings, and add, remove, enable or disable individual rules. Unknown router
interfaces are rejected before login; every write requires confirmation and readback.

Rogers CGM4981COM was tested live. Bell Giga Hub web UI 7.3.28 detection is verified
live; its forwarding backend is experimental, derived from that firmware's public
web client and tested in simulation. Authenticated Bell inventory and live forwarding
acceptance are still pending. Other models/firmware are not automatically supported.

## Run

Install [uv](https://docs.astral.sh/uv/), then:

```sh
uv sync --locked --no-dev
uv run --no-dev jolly-roger detect
cp .env.example .env
chmod 600 .env
```

Fill in `JOLLY_ROGER_PASSWORD` locally, or omit it for a terminal password prompt.
The gateway defaults to Linux's IPv4 default route. Use `--gateway http://192.168.2.1`
or `JOLLY_ROGER_GATEWAY` to override it; `--backend rdk|bell` requires that fingerprint.
An existing `.env` gateway setting still takes precedence over route discovery.

```sh
uv run --no-dev jolly-roger list
uv run --no-dev jolly-roger add --name minecraft --protocol TCP --ip 192.168.2.30 --start 25565 --yes
uv run --no-dev jolly-roger disable RULE_ID --yes
uv run --no-dev jolly-roger enable RULE_ID --yes
uv run --no-dev jolly-roger remove RULE_ID --yes
```

With the browser extra installed, `--cdp-url` attaches an already-authenticated
Chromium page on the gateway origin without exporting its cookies or closing it.
Bell uses its native GUI session; guest sessions are refused.

`scan --max-id N` and global forwarding toggles are RDK-only. Gated RDK inventories
remain incomplete and refuse individual writes. Bell reports `enabled: null` because
it has no exposed global forwarding switch, and preserves translated internal ports.
New rules use equal internal/external ranges; DMZ and UPnP-owned entries are protected.

Writes are not retried. Bell creation is multi-step: a failure may leave an incomplete,
disabled rule. Inspect the router before retrying; do not assume a failed command was
rolled back. Readback does not prove Internet reachability—test from another network.

Based on the [RDK web interface](https://github.com/rdkcentral/webui) and the local
Bell web client (`/gui/js/gui-api.js`, `/gui/js/gui-core.js`, `/main-bundle.js`).
Not affiliated with either provider. Never put router credentials in issues or PRs.
