# Observability

Nothing is collected from the deployment today. This page describes the configurations that exist and what would have to be wired for them to produce data.

Current state:

- `infrastructure/prometheus/prometheus.yml` targets the Docker Compose hostnames `api-service:3000`, `github-service:3002`, and `analysis-service:8001`. It scrapes nothing that is deployed.
- `infrastructure/grafana-agent/agent.yaml` is a Grafana Agent scrape and remote-write config. No workflow and no compose service references it, and its Dockerfile still mentions a platform the project no longer uses.
- `infrastructure/remediation/grafana/alerts/remediation-rules.yaml` and `dashboards/remediation-overview.json` are files. Nothing provisions them. The `mitig8it-remediation-pending` rule group queries metric names no service emits; import the rules with "No data" handled as NoData or OK.
- No deploy workflow sets `OTEL_EXPORTER_OTLP_ENDPOINT`, so the OpenTelemetry instrumentation in the API, the API worker, and the repair service is inert in the deployment. The compose `otel-collector` receives spans locally and keeps nothing.
- `/metrics` requires `x-internal-secret` in production, so any future scraper needs that token in its `authorization` block.

## Grafana Agent scrape config

Set these environment variables on the Grafana Agent service when remote-writing service metrics to Grafana Cloud:

- `API_TARGET_HOST`: Host and optional port for API service metrics. Use the host only, without scheme or path.
- `GITHUB_TARGET_HOST`: Host and optional port for GitHub service metrics. Use the host only, without scheme or path.
- `ANALYSIS_TARGET_HOST`: Host and optional port for analysis service metrics. Use the host only, without scheme or path.
- `PROM_REMOTE_WRITE_URL`, `PROM_REMOTE_WRITE_USER`, `PROM_REMOTE_WRITE_PASS`: Your Prometheus/Grafana Cloud remote write endpoint and credentials.

Notes:
- Targets must be host (and port) only, no scheme or path. Paths are controlled by the `*_METRICS_PATH` envs.
- Keep `/metrics` reachable to the agent. If you restrict it, use a shared token and add it in the agent scrape config’s `authorization` block.
- If services use HTTP instead of HTTPS, set `scheme: http` in the scrape config for that target.
