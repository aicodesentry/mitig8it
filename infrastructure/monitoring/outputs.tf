output "notification_channel_id" {
  description = "The email notification channel this module created."
  value       = google_monitoring_notification_channel.owner_email.id
}

output "alert_policy_names" {
  description = "The alert policies that are active after an apply."
  value = compact([
    google_monitoring_alert_policy.reviews_failing.name,
    google_monitoring_alert_policy.reviews_stalled.name,
    var.enable_lease_reclaim_alert ? google_monitoring_alert_policy.remediation_lease_reclaim[0].name : "",
  ])
}
