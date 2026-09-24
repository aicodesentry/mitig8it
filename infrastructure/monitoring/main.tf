# Cloud Monitoring alert policies for Mitig8it.
#
# These are the same two questions the Grafana rules in
# infrastructure/remediation/grafana/alerts/remediation-rules.yaml ask, expressed as
# Cloud Monitoring policies so the owner can be paged without running Grafana at all.
# The metrics arrive through the managed Prometheus sidecar on codesentry-api, so the
# PromQL here is the same PromQL Grafana would evaluate.
#
# This module creates alerting configuration and one email notification channel. It
# creates no Cloud Run service, no database and no project.

locals {
  notification_channels = concat(
    [google_monitoring_notification_channel.owner_email.id],
    var.notification_channel_ids,
  )

  runbook = "https://github.com/aicodesentry/mitig8it/blob/main/docs/runbooks/observability.md"
}

resource "google_monitoring_notification_channel" "owner_email" {
  project      = var.project_id
  display_name = "Mitig8it owner"
  type         = "email"

  labels = {
    email_address = var.alert_email
  }
}

# Reviews are running and most of them are failing.
#
# A transient re-queue is excluded through the `reason` label: that run has not failed
# for the pull request author yet, and counting it would page for work that is still on
# its way to succeeding.
#
# No-data behaviour: a PromQL condition evaluates to nothing when the series are
# missing, so this policy stays inactive when no analysis run started in the window at
# all. That is deliberate. "Nothing ran" is the stall policy's question, and the same
# silence must not page twice.
resource "google_monitoring_alert_policy" "reviews_failing" {
  project      = var.project_id
  display_name = "mitig8it_reviews_failing"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "More than ${var.failure_ratio_threshold * 100} percent of security reviews failed over 15 minutes"

    condition_prometheus_query_language {
      query = <<-EOT
        (
          sum(increase(mitig8it_analysis_runs_failed_total{reason!="transient_retried"}[15m]))
          /
          sum(increase(mitig8it_analysis_runs_started_total[15m]))
        ) > ${var.failure_ratio_threshold}
        and
        sum(increase(mitig8it_analysis_runs_started_total[15m])) >= ${var.minimum_started_runs}
      EOT

      duration            = "300s"
      evaluation_interval = "60s"
      alert_rule          = "AlwaysOn"
      rule_group          = "mitig8it-reviews"
    }
  }

  alert_strategy {
    # A failing pipeline stays failing. Auto-closing it after an hour of no data would
    # read as recovery when it is more likely to be a scrape that stopped.
    auto_close = "86400s"
  }

  documentation {
    subject   = "Mitig8it: security reviews are failing"
    content   = <<-EOT
      More than ${var.failure_ratio_threshold * 100} percent of the analysis runs that
      started in the last 15 minutes ended without publishing a review, across at least
      ${var.minimum_started_runs} runs.

      Break the failures down by the `reason` label:

      - `analysis_incomplete`: one of our own analysis tiers returned an unusable
        response. Ours to fix.
      - `github_files_invalid` or `publication_incomplete`: GitHub returned something
        we could not use, or the review could not be published.
      - `infrastructure`: network or a cold downstream. Check whether codesentry-github
        or codesentry-analysis is scaled to zero and slow to wake.
      - `unhandled`: a bug. Read the log lines for the failing `analysis_run_id`.

      Runbook: ${local.runbook}#reviews-are-failing
    EOT
    mime_type = "text/markdown"
  }

  notification_channels = local.notification_channels
}

# Work is waiting and nothing is picking it up.
#
# The service derives the join of "queue is old" and "nothing started" into one gauge,
# so the policy reads a single series.
#
# No-data behaviour: a PromQL condition alone cannot fire on an absent series, and an
# API that is down reports neither a backlog nor a start. That silence is the outage,
# so this policy carries a second, absence condition alongside the gauge: if the
# started counter stops arriving for fifteen minutes, the policy fires. The two
# conditions are combined with OR, so either the queue stalled or the service stopped
# telling us anything, and both wake the same person.
resource "google_monitoring_alert_policy" "reviews_stalled" {
  project      = var.project_id
  display_name = "mitig8it_reviews_stalled"
  combiner     = "OR"
  severity     = "CRITICAL"

  conditions {
    display_name = "Analysis runs are queued but none has started"

    condition_prometheus_query_language {
      query               = "max(mitig8it_analysis_runs_stalled) > 0"
      duration            = "300s"
      evaluation_interval = "60s"
      alert_rule          = "AlwaysOn"
      rule_group          = "mitig8it-reviews"
    }
  }

  # The scrape itself stopping. A PromQL condition cannot see an absent series, so the
  # absence is asserted separately against the metric as Managed Prometheus ingests it.
  conditions {
    display_name = "codesentry-api stopped reporting analysis metrics"

    condition_absent {
      filter   = "resource.type = \"prometheus_target\" AND metric.type = \"prometheus.googleapis.com/mitig8it_analysis_runs_started_total/counter\""
      duration = "900s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  alert_strategy {
    auto_close = "86400s"
  }

  documentation {
    subject   = "Mitig8it: security reviews are stalled"
    content   = <<-EOT
      Pending analysis runs are older than ten minutes and no run has moved into the
      running state for ten minutes. Pull requests are waiting for a review that is not
      coming.

      Check, in order:

      1. Is at least one codesentry-api instance serving? `gcloud run services describe
         codesentry-api --region <region>`.
      2. Did the queue worker start? Look for the "Analysis queue worker started" log
         line on the newest instance.
      3. Is the database reachable? The claim query is the first thing a database
         outage stops, and it fails quietly into the queue.

      If this policy fires with no data at all, the sidecar scrape has stopped rather
      than the queue; that is the same outage from the operator's side and is handled
      the same way.

      Runbook: ${local.runbook}#reviews-are-stalled
    EOT
    mime_type = "text/markdown"
  }

  notification_channels = local.notification_channels
}

# A warning, deliberately: one reclaim is normal recovery after an instance restart.
# Several in half an hour mean workers are dying mid-job, which usually precedes an
# outage rather than being one.
#
# No-data behaviour: absent series leave this policy inactive, which is correct here. A
# deployment that runs no remediation worker emits no reclaims, and that is a
# configuration choice rather than an incident. Set enable_lease_reclaim_alert = false
# in such a deployment so the policy is not carried at all.
resource "google_monitoring_alert_policy" "remediation_lease_reclaim" {
  count = var.enable_lease_reclaim_alert ? 1 : 0

  project      = var.project_id
  display_name = "mitig8it_remediation_lease_reclaim"
  combiner     = "OR"
  severity     = "WARNING"

  conditions {
    display_name = "Remediation worker leases reclaimed repeatedly"

    condition_prometheus_query_language {
      query               = "increase(mitig8it_remediation_lease_reclaims_total[30m]) > 3"
      duration            = "600s"
      evaluation_interval = "60s"
      alert_rule          = "AlwaysOn"
      rule_group          = "mitig8it-remediation"
    }
  }

  documentation {
    subject   = "Mitig8it: remediation worker leases are being reclaimed"
    content   = <<-EOT
      More than three remediation job leases expired and were reclaimed in half an hour.
      Workers are most likely being killed mid-job. Check instance restarts and memory
      limits before the next deploy.

      Runbook: https://github.com/aicodesentry/mitig8it/blob/main/docs/runbooks/remediation.md#expired-worker-lease
    EOT
    mime_type = "text/markdown"
  }

  notification_channels = local.notification_channels
}
