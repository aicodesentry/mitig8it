variable "project_id" {
  description = "Existing GCP project that receives the metrics. This module never creates a project."
  type        = string
  nullable    = false
  validation {
    condition     = length(trimspace(var.project_id)) > 0
    error_message = "project_id is required."
  }
}

variable "alert_email" {
  description = <<-EOT
    The address that receives every page from these policies. One address, on purpose:
    an alert that goes to a list nobody owns is an alert nobody answers. Change it to a
    rotation address once there is a rotation.
  EOT
  type        = string
  nullable    = false
  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.alert_email))
    error_message = "alert_email must be a single email address."
  }
}

variable "notification_channel_ids" {
  description = <<-EOT
    Existing Cloud Monitoring notification channels to notify in addition to the email
    channel this module creates, in the form
    projects/<project>/notificationChannels/<id>. Use this for a PagerDuty or Slack
    channel that was created outside Terraform.
  EOT
  type        = list(string)
  default     = []
}

variable "failure_ratio_threshold" {
  description = "Fraction of started analysis runs that may fail over 15 minutes before paging."
  type        = number
  default     = 0.3
  validation {
    condition     = var.failure_ratio_threshold > 0 && var.failure_ratio_threshold < 1
    error_message = "failure_ratio_threshold is a fraction strictly between 0 and 1."
  }
}

variable "minimum_started_runs" {
  description = <<-EOT
    How many analysis runs must have started in the window before the failure ratio is
    allowed to page. One failure out of one run is 100 percent and means almost nothing.
  EOT
  type        = number
  default     = 3
  validation {
    condition     = var.minimum_started_runs >= 1
    error_message = "minimum_started_runs must be at least 1."
  }
}

variable "enable_lease_reclaim_alert" {
  description = <<-EOT
    The remediation lease reclaim warning. Turn it off in a deployment that runs no
    remediation worker, where the metric is legitimately absent.
  EOT
  type        = bool
  default     = true
}
