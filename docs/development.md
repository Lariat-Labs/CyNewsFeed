# Development

## Layout

```
backend/            Go module (cmd/cynews, internal/*)
frontend/           React SPA (builds into backend/internal/web/dist)
infra/terraform/    Azure infrastructure
scripts/deploy.sh   ACR build + Terraform apply
docs/               This documentation (MkDocs)
```

## Common tasks

```bash
make install        # npm ci + go mod download
make dev-api        # API on :8080 against Azurite
make dev-web        # Vite on :5173
make test           # go vet + go test + tsc
make test-azurite   # + Azure Table/Blob integration test
make build          # SPA + single binary in ./bin/cynews
make run-once       # one aggregation pass
```

A fresh clone builds without the frontend. The binary then serves a "UI not built" page while the API works.

## Tests

- Unit tests for parsing, IOC extraction, rules, frameworks, clustering and trends, detection validation, STIX/TAXII,
  MISP and MCP.
- Pipeline tests with an in-memory store, a fake AI provider and `httptest` feed and Slack servers. These cover
  enrichment, alerts, retries, the off-by-default AI policy, on-demand summaries, detections and the weekly brief.
- Claude client tests against a fake Messages API, including streaming tool use and **byte-exact thinking-block replay**
  on resume.
- An Azure store integration test against Azurite (`AZURITE=1`).

## Documentation

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r docs/requirements.txt
mkdocs serve          # http://127.0.0.1:8000
mkdocs build --strict
```

The **Docs** GitHub Actions workflow (`.github/workflows/docs.yml`) builds with `--strict` and deploys to GitHub Pages
on pushes to `main` that touch `docs/` or `mkdocs.yml`. Enable it once under *Settings → Pages → Source: GitHub Actions*.

## Adding a source kind

1. Add a `FeedKind` in `internal/model`.
2. Implement fetching in `internal/feeds`, returning normalised `model.Item`s with stable IDs.
3. Branch on the kind in `pipeline.fetchFeed` and allow it in `api.validateFeed`.
4. Add defaults to `internal/feeds/defaults.yaml`. Existing installs pick up new defaults once.

## Adding an agent / MCP tool

Register it in `internal/agent` (`registerDataset`, `registerAnalysis` or `registerIntel`) with a JSON schema and a
`Run` function that decodes arguments strictly. It's then available to the agent, `cynews query` and MCP. Keep tools
read-only.
