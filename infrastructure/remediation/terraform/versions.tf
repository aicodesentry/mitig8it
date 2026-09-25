# google 6 rather than 5 because `google_cloud_run_v2_job.deletion_protection` exists only from
# provider 6, and the sandbox job sets it: the job is rebuilt from this module on every
# environment teardown, so a delete Terraform cannot perform is a job that has to be removed by
# hand. Nothing else in the module needed changing for the major version, and `terraform
# validate` on the whole module passes against 6.50.0 unmodified. The lock file records
# checksums for linux_amd64 and darwin_arm64, so CI and a developer laptop init from the same
# pinned build.
terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
