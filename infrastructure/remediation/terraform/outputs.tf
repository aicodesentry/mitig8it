output "remediation_queue_name" {
  description = "Null while enable_cloud_tasks_dispatch is false."
  value       = one(google_cloud_tasks_queue.remediation[*].name)
}

output "remediation_reconciler_job_name" {
  description = "Null while enable_cloud_tasks_dispatch is false."
  value       = one(google_cloud_scheduler_job.remediation_reconciler[*].name)
}

output "task_invoker_service_account" {
  value = google_service_account.task_invoker.email
}

output "scheduler_invoker_service_account" {
  value = google_service_account.scheduler_invoker.email
}

output "artifact_bucket_name" {
  value = google_storage_bucket.remediation_artifacts.name
}

output "artifact_kms_key_name" {
  value = var.artifact_kms_key_name
}

output "remediation_service_workload_identity" {
  value = google_service_account.remediation_api_artifacts.email
}

output "remediation_worker_workload_identity" {
  value = google_service_account.remediation_worker_artifacts.email
}

output "future_cloud_tasks_dispatch_contract" {
  description = "Supply these values per task when the control-plane Cloud Tasks transport is implemented; no queue-level HTTP target exists."
  value = {
    url                    = var.remediation_dispatch_url
    audience               = var.remediation_dispatch_audience
    oidc_service_account   = google_service_account.task_invoker.email
    required_http_method   = "POST"
    required_payload_scope = "job/stage IDs and event version only"
  }
}
