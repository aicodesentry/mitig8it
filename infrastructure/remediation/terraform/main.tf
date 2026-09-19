data "google_project" "current" {}

resource "google_project_service" "required" {
  for_each = toset([
    "cloudtasks.googleapis.com",
    "cloudscheduler.googleapis.com",
    "cloudkms.googleapis.com",
    "iamcredentials.googleapis.com",
    "storage.googleapis.com",
  ])
  service            = each.value
  disable_on_destroy = false
}

resource "google_service_account" "task_invoker" {
  account_id   = "remediation-task-${var.environment}"
  display_name = "Mitig8it remediation Cloud Tasks OIDC invoker (${var.environment})"
}

resource "google_service_account" "scheduler_invoker" {
  account_id   = "remediation-scheduler-${var.environment}"
  display_name = "Mitig8it remediation Scheduler OIDC invoker (${var.environment})"
}

resource "google_service_account" "remediation_api_artifacts" {
  # Google service-account IDs are capped at 30 characters.
  account_id   = "remediation-api-art-${var.environment}"
  display_name = "Mitig8it remediation API artifact identity (${var.environment})"
}

resource "google_service_account" "remediation_worker_artifacts" {
  account_id   = "remediation-worker-art-${var.environment}"
  display_name = "Mitig8it remediation worker artifact identity (${var.environment})"
}

# The GCS service agent is looked up, never created.
data "google_storage_project_service_account" "gcs" {}

resource "google_kms_crypto_key_iam_member" "gcs_bucket_cmek" {
  crypto_key_id = var.artifact_kms_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_storage_bucket" "remediation_artifacts" {
  name                        = var.artifact_bucket_name
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  encryption {
    default_kms_key_name = var.artifact_kms_key_name
  }

  versioning { enabled = true }

  lifecycle_rule {
    condition {
      age            = 7
      matches_prefix = ["remediation-inputs/"]
    }
    action { type = "Delete" }
  }
  lifecycle_rule {
    condition {
      age            = 30
      matches_prefix = ["remediation-results/"]
    }
    action { type = "Delete" }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_bucket_cmek]
}

locals {
  artifact_principals = {
    api    = google_service_account.remediation_api_artifacts.email
    worker = google_service_account.remediation_worker_artifacts.email
  }
}

resource "google_storage_bucket_iam_member" "artifact_creator" {
  for_each = local.artifact_principals
  bucket   = google_storage_bucket.remediation_artifacts.name
  role     = "roles/storage.objectCreator"
  member   = "serviceAccount:${each.value}"
}

resource "google_storage_bucket_iam_member" "artifact_viewer" {
  for_each = local.artifact_principals
  bucket   = google_storage_bucket.remediation_artifacts.name
  role     = "roles/storage.objectViewer"
  member   = "serviceAccount:${each.value}"
}

resource "google_service_account_iam_member" "api_workload_identity" {
  service_account_id = google_service_account.remediation_api_artifacts.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[mitig8it-remediation/remediation-service]"
}

resource "google_service_account_iam_member" "worker_workload_identity" {
  service_account_id = google_service_account.remediation_worker_artifacts.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[mitig8it-remediation/remediation-worker]"
}

resource "google_project_iam_member" "control_plane_can_enqueue" {
  project = var.project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${var.api_control_plane_service_account_email}"
}

# Cloud Tasks and Scheduler mint OIDC tokens as these identities; neither is
# granted application, storage, Kubernetes, database, or GitHub authority here.
resource "google_service_account_iam_member" "cloud_tasks_token_creator" {
  service_account_id = google_service_account.task_invoker.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudtasks.iam.gserviceaccount.com"
}

resource "google_service_account_iam_member" "cloud_scheduler_token_creator" {
  service_account_id = google_service_account.scheduler_invoker.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloudscheduler.iam.gserviceaccount.com"
}

# Gated by enable_cloud_tasks_dispatch. The control plane currently polls its
# PostgreSQL outbox and exposes no dispatch endpoint, so the queue stays
# uncreated by default.
resource "google_cloud_tasks_queue" "remediation" {
  count      = var.enable_cloud_tasks_dispatch ? 1 : 0
  name       = "remediation-${var.environment}"
  location   = var.region
  depends_on = [google_project_service.required]

  rate_limits {
    max_concurrent_dispatches = var.queue_max_concurrent_dispatches
    max_dispatches_per_second = 10
  }

  retry_config {
    max_attempts       = 8
    min_backoff        = "5s"
    max_backoff        = "300s"
    max_doublings      = 5
    max_retry_duration = "3600s"
  }

}

# Gated by the same variable: a scheduled POST to an unimplemented
# reconciliation endpoint would produce failing invocations, not reconciliation.
resource "google_cloud_scheduler_job" "remediation_reconciler" {
  count       = var.enable_cloud_tasks_dispatch ? 1 : 0
  name        = "remediation-reconciler-${var.environment}"
  description = "Triggers bounded remediation reconciliation; endpoint authorization is enforced by the control plane."
  schedule    = "* * * * *"
  time_zone   = "Etc/UTC"
  region      = var.region
  depends_on  = [google_project_service.required]

  http_target {
    http_method = "POST"
    uri         = var.remediation_reconciler_url
    body        = base64encode(jsonencode({ source = "cloud-scheduler" }))
    headers     = { "Content-Type" = "application/json" }
    oidc_token {
      service_account_email = google_service_account.scheduler_invoker.email
      audience              = var.remediation_reconciler_audience
    }
  }
}
