variable "project_id" {
  description = "Existing GCP project ID. This module never creates a project."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id is required."
  }
}

variable "region" {
  description = "Existing target region for Cloud Tasks and Cloud Scheduler."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.region)) > 0
    error_message = "region is required."
  }
}

variable "environment" {
  description = "Deployment environment name, for example staging."
  type        = string
  default     = "staging"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,30}$", var.environment))
    error_message = "environment must be a DNS-safe name."
  }
}

variable "api_control_plane_service_account_email" {
  description = "Existing API control-plane GCP service account that may enqueue remediation tasks."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[^@]+@[^@]+\\.iam\\.gserviceaccount\\.com$", var.api_control_plane_service_account_email))
    error_message = "api_control_plane_service_account_email must be a GCP service-account email."
  }
}

variable "remediation_dispatch_url" {
  description = "Authenticated control-plane dispatch endpoint. It must validate the OIDC audience and task identity."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^https://[^/]+/.+", var.remediation_dispatch_url))
    error_message = "remediation_dispatch_url must use HTTPS and include a path."
  }
}

variable "remediation_dispatch_audience" {
  description = "Expected OIDC audience for Cloud Tasks dispatches."
  type        = string
  nullable    = false
}

variable "remediation_reconciler_url" {
  description = "Authenticated control-plane reconciliation endpoint called by Cloud Scheduler."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^https://", var.remediation_reconciler_url))
    error_message = "remediation_reconciler_url must use HTTPS."
  }
}

variable "remediation_reconciler_audience" {
  description = "Expected OIDC audience for the scheduled reconciliation endpoint."
  type        = string
  nullable    = false
}

variable "queue_max_concurrent_dispatches" {
  description = "Global ceiling; per-installation/PR limits remain enforced by the control plane."
  type        = number
  default     = 20
  validation {
    condition     = var.queue_max_concurrent_dispatches >= 1 && var.queue_max_concurrent_dispatches <= 100
    error_message = "queue concurrency must be 1-100."
  }
}

variable "artifact_bucket_name" {
  description = "Globally unique GCS bucket for durable remediation request/result artifacts."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$", var.artifact_bucket_name))
    error_message = "artifact_bucket_name must be a valid lowercase GCS bucket name."
  }
}

variable "artifact_kms_key_name" {
  description = "Existing regional Cloud KMS CryptoKey resource name for bucket CMEK."
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.artifact_kms_key_name))
    error_message = "artifact_kms_key_name must be a full CryptoKey resource name."
  }
}

variable "enable_cloud_tasks_dispatch" {
  description = "Create the Cloud Tasks queue and the Cloud Scheduler reconciliation job. Default false: the control-plane dispatch and reconciliation endpoints these resources call are not implemented, so creating them would schedule requests against endpoints that do not exist. Enable only after the authenticated OIDC handlers are deployed and their audiences are verified."
  type        = bool
  default     = false
}
