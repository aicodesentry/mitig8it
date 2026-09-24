# Observability

> The API's metrics are now collected. See [runbooks/observability.md](../runbooks/observability.md)
> for the deployed path: a managed Prometheus sidecar scrapes the API into Cloud
> Monitoring, and the alert policies in `infrastructure/monitoring/` read it. This page
> covers what remains unwired: the local Prometheus and Grafana Agent configurations,
> the unscraped github and analysis services, and trace export.

Current state:

- `infrastructure/prometheus/prometheus.yml` targets the Docker Compose hostnames `api-service:3000`, `github-service:3002`, and `analysis-service:8001`. It scrapes nothing that is deployed.
- `infrastructure/grafana-agent/agent.yaml` is a Grafana Agent scrape and remote-write config. No workflow and no compose service references it, and its Dockerfile still mentions a platform the project no longer uses.
- `infrastructure/remediation/grafana/alerts/remediation-rules.yaml` now holds three rules that all query metrics the API emits. Nothing in this repository provisions them into Grafana; the Cloud Monitoring policies in `infrastructure/monitoring/` are the provisioned path. `dashboards/remediation-overview.json` is still a file nothing installs.
- No deploy workflow sets `OTEL_EXPORTER_OTLP_ENDPOINT`, so the OpenTelemetry instrumentation in the API, the API worker, and the repair service is inert in the deployment. The compose `otel-collector` receives spans locally and keeps nothing.
- The public `/metrics` route requires `x-internal-secret` in production, so any external scraper needs that token in its `authorization` block. The managed Prometheus sidecar does not: it reads a separate loopback listener on port 9091 that carries no header and is not reachable from outside the instance.
- The github and analysis services expose `/metrics` and nothing scrapes them. Only `codesentry-api` runs the sidecar.

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
