# jolly-roger

Port forward a Rogers router without the stupid app.

List rules, add/remove, enable/disable 'em, from a Python CLI.

Interfaces with the RDK gateway web interface.

Tested on a Rogers CGM4981COM; other models and firmware may work but are untested.

## Run

Install [uv](https://docs.astral.sh/uv/), then:

```sh
uv sync --locked --no-dev
cp .env.example .env
chmod 600 .env
```

Fill in `JOLLY_ROGER_PASSWORD` in `.env` and adjust gateway/username if needed.

```sh
uv run --no-dev jolly-roger status
uv run --no-dev jolly-roger list
uv run --no-dev jolly-roger scan --max-id 20
uv run --no-dev jolly-roger add --name my-server --protocol TCP --ip 10.0.0.42 --start 25565
uv run --no-dev jolly-roger disable RULE_ID
uv run --no-dev jolly-roger enable RULE_ID
uv run --no-dev jolly-roger remove RULE_ID
```

Based on the [RDK web interface](https://github.com/rdkcentral/webui), not affiliated
with Rogers.
