# jolly-roger

Local port forwarding for Rogers gateways, without the phone app. Inspect rules,
add or remove forwards, and enable or disable them from a Python CLI.

Targets the CGM4981COM's RDK web interface. HTTP login and a temporary TCP
forward were verified on Rogers firmware `CGM4981COM_8.5p10s1_PROD_sey`:
closed → open → disabled → deleted, checked from outside the LAN.
That test used the Python transport API with external verification. The regular
CLI still refuses individual changes when firmware hides fields it needs to
verify them; `scan` reports the available details.

## Run

Install [uv](https://docs.astral.sh/uv/), then:

```sh
uv sync --locked --no-dev
cp .env.example .env
chmod 600 .env
```

Fill in `JOLLY_ROGER_PASSWORD` in `.env` and adjust gateway/username if needed.
The CLI logs in automatically. Leave the password blank for a hidden terminal
prompt. `.env` is gitignored; don't share it. Environment variables override
`.env`, which is loaded from the current directory.

```sh
uv run --no-dev jolly-roger status
uv run --no-dev jolly-roger list
uv run --no-dev jolly-roger scan --max-id 20
uv run --no-dev jolly-roger add --name my-server --protocol TCP --ip 10.0.0.42 --start 25565
uv run --no-dev jolly-roger disable RULE_ID
uv run --no-dev jolly-roger enable RULE_ID
uv run --no-dev jolly-roger remove RULE_ID
```

Use the actual returned rule ID. Writes ask for confirmation; `--yes` skips it.
Global forwarding is separate: `global-enable`/`global-disable`. Only IPv4,
same-port forwarding is supported; `--end` adds an inclusive range.
Use a trusted LAN: HTTP sends credentials unencrypted.

An authenticated Chromium session is an optional fallback:
`uv run --extra browser jolly-roger --cdp-url http://127.0.0.1:9222 status`.
Keep that debugging port private.

## Development

```sh
uv sync --locked
uv run playwright install chromium
uv run pytest
uv run ruff check .
uv build
```

Based on the [RDK web interface](https://github.com/rdkcentral/webui), not affiliated
with Rogers. Tests never contact the real router.
