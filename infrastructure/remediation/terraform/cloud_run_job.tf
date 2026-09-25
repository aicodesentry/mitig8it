# The Cloud Run Jobs sandbox: the isolation the verification level `isolated_job` claims.
#
# Nothing here is applied automatically. `docs/runbooks/sandbox-cloud-run-job.md` has the order
# the owner runs, including the image build that has to happen between `terraform apply` and a
# working job.
#
# Two buckets, not one bucket with IAM conditions on object prefixes. A condition of the form
# `resource.name.startsWith(".../objects/snapshots/")` does express the same intent, but it
# expresses it as a predicate on a principal that still holds a role over the whole bucket: a
# condition that is dropped, mis-typed, or evaluated on an API surface that does not carry
# `resource.name` leaves the job identity reading every tenant's snapshots and every other
# execution's results. Two buckets make the boundary structural instead of conditional, and
# they let the job identity hold `objectCreator` on results with no read and no list at all,
# which no single-bucket arrangement can express.

locals {
  sandbox_snapshot_bucket = "${var.sandbox_bucket_prefix}-snapshots"
  sandbox_result_bucket   = "${var.sandbox_bucket_prefix}-results"
}

# --------------------------------------------------------------------------------------
# Inputs
# --------------------------------------------------------------------------------------

variable "enable_cloud_run_job_sandbox" {
  description = "Create the Cloud Run Jobs sandbox: two buckets, a dedicated job identity, an isolated VPC, and the job itself. Default false so an existing installation plans clean; the owner enables it deliberately, following docs/runbooks/sandbox-cloud-run-job.md."
  type        = bool
  default     = false
}

variable "sandbox_bucket_prefix" {
  description = "Name prefix for the two sandbox buckets. Terraform creates <prefix>-snapshots and <prefix>-results; GCS bucket names are globally unique, so this has to be unique to the installation."
  type        = string
  default     = "mitig8it-sandbox"
  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,50}[a-z0-9]$", var.sandbox_bucket_prefix))
    error_message = "sandbox_bucket_prefix must be a valid lowercase GCS bucket name prefix."
  }
}

variable "sandbox_job_name" {
  description = "Name of the Cloud Run job that runs one check variant per task."
  type        = string
  default     = "codesentry-remediation-sandbox"
  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,47}[a-z0-9])?$", var.sandbox_job_name))
    error_message = "sandbox_job_name must be a valid Cloud Run resource name."
  }
}

variable "sandbox_job_image" {
  description = "Digest-pinned image the sandbox job runs. A tag is refused: the driver compares the digest each task reports against SANDBOX_IMAGE_DIGEST, and a tag would make that comparison prove nothing. Apply once with the placeholder digest, then build the image and follow the runbook's update step."
  type        = string
  nullable    = false
  default     = "us-central1-docker.pkg.dev/codesentry-260311-9f2b/codesentry/remediation-job@sha256:0000000000000000000000000000000000000000000000000000000000000000"
  validation {
    condition     = can(regex("^[^@:]+@sha256:[0-9a-f]{64}$", var.sandbox_job_image))
    error_message = "sandbox_job_image must be a complete registry/image@sha256:digest reference."
  }
}

variable "sandbox_subnet_cidr" {
  description = "Subnet range for the sandbox VPC. Direct VPC egress allocates instance addresses from it; /26 is the smallest Cloud Run accepts."
  type        = string
  default     = "10.90.0.0/24"
  validation {
    condition     = can(cidrhost(var.sandbox_subnet_cidr, 0))
    error_message = "sandbox_subnet_cidr must be a valid CIDR range."
  }
}

variable "remediation_service_account_email" {
  description = "Existing GCP service account the remediation Cloud Run service runs as. It uploads snapshots, reads results, and starts and cancels executions of the sandbox job."
  type        = string
  default     = ""
  validation {
    condition     = var.remediation_service_account_email == "" || can(regex("^[^@]+@[^@]+\\.iam\\.gserviceaccount\\.com$", var.remediation_service_account_email))
    error_message = "remediation_service_account_email must be a GCP service-account email."
  }
}

resource "google_project_service" "sandbox_job" {
  for_each = var.enable_cloud_run_job_sandbox ? toset([
    "run.googleapis.com",
    "compute.googleapis.com",
    "vpcaccess.googleapis.com",
  ]) : toset([])
  service            = each.value
  disable_on_destroy = false
}

# --------------------------------------------------------------------------------------
# Object transport
# --------------------------------------------------------------------------------------

# Snapshots: the repository trees a job task downloads. One day of lifetime because the driver
# deletes each object as its verification ends and this rule only catches the ones a crashed
# driver left behind. Versioning stays off deliberately: a retained non-current version of a
# customer's source tree is exactly what the one-day rule exists to prevent.
resource "google_storage_bucket" "sandbox_snapshots" {
  count                       = var.enable_cloud_run_job_sandbox ? 1 : 0
  name                        = local.sandbox_snapshot_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition { age = 1 }
    action { type = "Delete" }
  }

  depends_on = [google_project_service.sandbox_job]
}

# Results: the HMAC-signed check results a job task writes. The remediation service reads them
# and never writes them; the job identity writes them and can neither read nor list them.
resource "google_storage_bucket" "sandbox_results" {
  count                       = var.enable_cloud_run_job_sandbox ? 1 : 0
  name                        = local.sandbox_result_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  lifecycle_rule {
    condition { age = 1 }
    action { type = "Delete" }
  }

  depends_on = [google_project_service.sandbox_job]
}

# --------------------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------------------

# The identity every sandbox task runs as. Its whole authority is: read one snapshots bucket,
# write one results bucket, read the definition of the job it is running. It can do nothing to
# the repository, the database, the control plane, or any other Google resource. A check that
# defeats the unprivileged user and the network namespace and reaches the metadata server
# obtains exactly this and nothing else.
resource "google_service_account" "sandbox_job" {
  count        = var.enable_cloud_run_job_sandbox ? 1 : 0
  account_id   = "remediation-sandbox-${var.environment}"
  display_name = "Mitig8it sandbox Cloud Run job identity (${var.environment})"

  lifecycle {
    # `remediation_service_account_email` defaults to empty so an installation that leaves the
    # sandbox disabled plans clean. Enabling the sandbox without it would otherwise produce IAM
    # members of the literal form `serviceAccount:`, which fails deep inside the apply with an
    # error that names none of this. Terraform cannot express a cross-variable `validation`
    # below 1.9, so the check lives here, on the first resource the sandbox creates.
    precondition {
      condition     = var.remediation_service_account_email != ""
      error_message = "enable_cloud_run_job_sandbox requires remediation_service_account_email: the remediation service's own identity is what uploads snapshots, reads results, and runs the job."
    }
  }
}

resource "google_storage_bucket_iam_member" "sandbox_job_reads_snapshots" {
  count  = var.enable_cloud_run_job_sandbox ? 1 : 0
  bucket = google_storage_bucket.sandbox_snapshots[0].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.sandbox_job[0].email}"
}

# objectCreator, not objectAdmin and not objectUser: a task may add its own result object and
# may not read one, list the bucket, overwrite one, or delete one. A task that wanted to
# replace another execution's result would also need that execution's nonce, which never
# leaves the driver and the task that was given it.
resource "google_storage_bucket_iam_member" "sandbox_job_writes_results" {
  count  = var.enable_cloud_run_job_sandbox ? 1 : 0
  bucket = google_storage_bucket.sandbox_results[0].name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.sandbox_job[0].email}"
}

# The task reads the job's own definition to report which image it is running, so the driver
# can compare that against the digest the deployment pinned. Scoped to this one job.
resource "google_cloud_run_v2_job_iam_member" "sandbox_job_reads_itself" {
  count    = var.enable_cloud_run_job_sandbox ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sandbox[0].name
  role     = "roles/run.viewer"
  member   = "serviceAccount:${google_service_account.sandbox_job[0].email}"
}

# The remediation service's own identity: it packages and uploads snapshots, deletes them when
# a verification ends, reads results, and starts and cancels executions of this one job.
resource "google_storage_bucket_iam_member" "remediation_writes_snapshots" {
  count  = var.enable_cloud_run_job_sandbox ? 1 : 0
  bucket = google_storage_bucket.sandbox_snapshots[0].name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${var.remediation_service_account_email}"
}

resource "google_storage_bucket_iam_member" "remediation_reads_results" {
  count  = var.enable_cloud_run_job_sandbox ? 1 : 0
  bucket = google_storage_bucket.sandbox_results[0].name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${var.remediation_service_account_email}"
}

# A custom role rather than a predefined one, because no predefined role is the right size.
# The driver needs four permissions: read the job, start an execution with container overrides,
# poll that execution, and cancel it when a verification is abandoned. `roles/run.invoker` plus
# `roles/run.viewer` covers the first three and not the fourth; the smallest predefined role
# that adds `run.executions.cancel` is `roles/run.developer`, which would also let the
# remediation service change this job's image and its service account. The verification level
# rests on the image digest being pinned by the deployment, so the one identity that must never
# be able to change that image is the one asking for the verification.
resource "google_project_iam_custom_role" "sandbox_job_operator" {
  count       = var.enable_cloud_run_job_sandbox ? 1 : 0
  role_id     = "remediation_sandbox_job_operator_${replace(var.environment, "-", "_")}"
  title       = "Mitig8it remediation sandbox job operator (${var.environment})"
  description = "Start, poll, and cancel executions of the remediation sandbox job. Grants nothing that can change the job, its image, or its service account."
  permissions = [
    "run.jobs.get",
    "run.jobs.run",
    "run.executions.get",
    "run.executions.cancel",
  ]
}

resource "google_cloud_run_v2_job_iam_member" "remediation_operates_the_job" {
  count    = var.enable_cloud_run_job_sandbox ? 1 : 0
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_job.sandbox[0].name
  role     = google_project_iam_custom_role.sandbox_job_operator[0].id
  member   = "serviceAccount:${var.remediation_service_account_email}"
}

# The job identity runs the tasks; the remediation identity has to be allowed to act as it in
# order to start an execution at all.
resource "google_service_account_iam_member" "remediation_acts_as_sandbox_job" {
  count              = var.enable_cloud_run_job_sandbox ? 1 : 0
  service_account_id = google_service_account.sandbox_job[0].name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${var.remediation_service_account_email}"
}

# --------------------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------------------

# A network of its own, with no peering, no Cloud NAT, and no route to the internet. Private
# Google Access is the one thing reachable from it, which is what lets the task download its
# snapshot and upload its result without any other egress existing.
#
# This is the network *configuration*. It is not the thing the verification level relies on:
# the task measures what its check can actually reach and the driver refuses evidence whose
# probes came back anything but unreachable. The configuration makes the measurement likely to
# succeed; the measurement is what the level claims.
resource "google_compute_network" "sandbox" {
  count                           = var.enable_cloud_run_job_sandbox ? 1 : 0
  name                            = "remediation-sandbox-${var.environment}"
  auto_create_subnetworks         = false
  delete_default_routes_on_create = false
  depends_on                      = [google_project_service.sandbox_job]
}

resource "google_compute_subnetwork" "sandbox" {
  count                    = var.enable_cloud_run_job_sandbox ? 1 : 0
  name                     = "remediation-sandbox-${var.environment}"
  region                   = var.region
  network                  = google_compute_network.sandbox[0].id
  ip_cidr_range            = var.sandbox_subnet_cidr
  private_ip_google_access = true
}

# Deny every egress the default allow-all rule would otherwise permit, except to the two
# Private Google Access ranges. Without this the absence of Cloud NAT is the only thing
# stopping internet egress, and the absence of a component is not a control.
resource "google_compute_firewall" "sandbox_allow_google_apis" {
  count     = var.enable_cloud_run_job_sandbox ? 1 : 0
  name      = "remediation-sandbox-${var.environment}-allow-google"
  network   = google_compute_network.sandbox[0].name
  direction = "EGRESS"
  priority  = 1000

  destination_ranges = ["199.36.153.8/30", "199.36.153.4/30", "34.126.0.0/18"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}

resource "google_compute_firewall" "sandbox_deny_egress" {
  count     = var.enable_cloud_run_job_sandbox ? 1 : 0
  name      = "remediation-sandbox-${var.environment}-deny-egress"
  network   = google_compute_network.sandbox[0].name
  direction = "EGRESS"
  priority  = 65000

  destination_ranges = ["0.0.0.0/0"]

  deny { protocol = "all" }
}

# --------------------------------------------------------------------------------------
# The job
# --------------------------------------------------------------------------------------

# `image` is the digest-pinned job image. It is a variable rather than a tag because the
# driver compares the digest a task reports against `SANDBOX_IMAGE_DIGEST`, and a tag would
# make that comparison meaningless. The runbook's build step is what updates it.
#
# max_retries = 0: a task that failed is evidence about the sandbox, and a retry would produce
# a second result object for the same check under the same nonce. The entrypoint exits 0
# whenever it wrote a result, so a non-zero task is always an infrastructure failure.
resource "google_cloud_run_v2_job" "sandbox" {
  count               = var.enable_cloud_run_job_sandbox ? 1 : 0
  name                = var.sandbox_job_name
  location            = var.region
  deletion_protection = false
  depends_on          = [google_project_service.sandbox_job]

  template {
    task_count  = 1
    parallelism = 0

    template {
      service_account = google_service_account.sandbox_job[0].email
      max_retries     = 0
      timeout         = "600s"

      vpc_access {
        network_interfaces {
          network    = google_compute_network.sandbox[0].id
          subnetwork = google_compute_subnetwork.sandbox[0].id
        }
        egress = "ALL_TRAFFIC"
      }

      containers {
        image   = var.sandbox_job_image
        command = ["python3", "-m", "src.sandbox.job_entrypoint"]

        resources {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
        }
      }
    }
  }

  lifecycle {
    # Every execution overrides the container's environment, and the deploy workflow updates
    # the image with `gcloud run jobs update`. Terraform owns the job's shape, not its
    # current image, so a plan run between deploys does not try to roll the image back.
    ignore_changes = [template[0].template[0].containers[0].image]
  }
}

# --------------------------------------------------------------------------------------
# Outputs
# --------------------------------------------------------------------------------------

output "sandbox_snapshot_bucket" {
  description = "Set as SANDBOX_BUCKET on the remediation service. Null while enable_cloud_run_job_sandbox is false."
  value       = one(google_storage_bucket.sandbox_snapshots[*].name)
}

output "sandbox_result_bucket" {
  description = "Set as SANDBOX_RESULTS_BUCKET on the remediation service. Null while enable_cloud_run_job_sandbox is false."
  value       = one(google_storage_bucket.sandbox_results[*].name)
}

output "sandbox_job_name" {
  description = "Set as SANDBOX_JOB_NAME on the remediation service."
  value       = one(google_cloud_run_v2_job.sandbox[*].name)
}

output "sandbox_job_service_account" {
  description = "The identity every sandbox task runs as. Its whole authority is one bucket read, one bucket create, and reading this job's own definition."
  value       = one(google_service_account.sandbox_job[*].email)
}

output "sandbox_job_operator_role" {
  description = "The custom role the remediation service holds on the sandbox job: start, poll, and cancel executions, and nothing that can change the image."
  value       = one(google_project_iam_custom_role.sandbox_job_operator[*].id)
}

output "sandbox_network" {
  description = "The isolated VPC the job egresses through. No Cloud NAT, no internet route, Private Google Access on."
  value       = one(google_compute_network.sandbox[*].name)
}
