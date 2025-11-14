# DM Subscription Aggregator

This repository aggregates multiple Clash-compatible subscription sources and
produces a curated configuration tailored for use with
[Clash Party](https://github.com/clash-party). The generated configuration:

- fetches the upstream subscription feeds listed in `scripts/update_subscriptions.py`
- removes duplicated nodes and filters out nodes whose TCP handshake latency is
overwhelmingly high (default threshold: 500 ms)
- organises the remaining nodes into useful proxy groups for services such as
  YouTube, Netflix, ChatGPT and Cloudflare
- writes the resulting configuration to `generated/clash.yaml`

The configuration is refreshed automatically by GitHub Actions every three
hours. Each successful run publishes an updated YAML file as a downloadable
asset on the `latest` GitHub release.

## Local development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python scripts/update_subscriptions.py --verbose
```

The script regenerates `generated/clash.yaml`. Adjust the latency threshold or
the output path with `--threshold` and `--output` if required.

## GitHub Actions automation

The workflow defined in `.github/workflows/update.yml` runs every three hours
and on manual dispatch. It executes the update script, commits configuration
changes back to the repository, and uploads the generated YAML file to the
`latest` release so it can be downloaded directly from the Releases page.
