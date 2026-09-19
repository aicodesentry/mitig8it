#!/usr/bin/env python3
"""Render the remediation Kustomize base with deployment-specific safe values.

The base intentionally contains mandatory tokens rather than a runnable default.
This prevents an operator from accidentally applying mutable images or broad
network egress. This script validates every override before copying the base.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import shutil
from pathlib import Path


TOKEN_PATTERN = re.compile(r"__[A-Z0-9_]+__")
IMAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$")
GSA_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z0-9-]+\.iam\.gserviceaccount\.com$")


def image(value: str) -> str:
    if not IMAGE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("image must be a lowercase immutable @sha256 digest reference")
    return value


def service_account(value: str) -> str:
    if not GSA_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError("must be a valid Google service-account email")
    return value


def cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be a CIDR") from error
    if network.version != 4 or network.prefixlen == 0 or network.is_multicast or network.is_unspecified:
        raise argparse.ArgumentTypeError("must be a bounded IPv4 CIDR, never 0.0.0.0/0")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--remediation-service-image", required=True, type=image)
    parser.add_argument("--remediation-worker-image", required=True, type=image)
    parser.add_argument("--sandbox-broker-image", required=True, type=image)
    parser.add_argument("--otel-collector-image", required=True, type=image)
    parser.add_argument("--remediation-api-gcp-service-account", required=True, type=service_account)
    parser.add_argument("--remediation-worker-gcp-service-account", required=True, type=service_account)
    parser.add_argument("--kubernetes-api-cidr", required=True, type=cidr)
    parser.add_argument("--remediation-external-egress-cidr", required=True, type=cidr)
    parser.add_argument("--remediation-database-cidr", required=True, type=cidr)
    arguments = parser.parse_args()

    source = Path(__file__).with_name("kubernetes")
    destination = arguments.output.resolve()
    if destination == source.resolve() or source.resolve() in destination.parents:
        parser.error("--output must not be the checked-in source or its child")
    if destination.exists():
        parser.error("--output must not already exist")

    replacements = {
        "__REMEDIATION_SERVICE_IMAGE__": arguments.remediation_service_image,
        "__REMEDIATION_WORKER_IMAGE__": arguments.remediation_worker_image,
        "__SANDBOX_BROKER_IMAGE__": arguments.sandbox_broker_image,
        "__OTEL_COLLECTOR_IMAGE__": arguments.otel_collector_image,
        "__REMEDIATION_API_GCP_SERVICE_ACCOUNT__": arguments.remediation_api_gcp_service_account,
        "__REMEDIATION_WORKER_GCP_SERVICE_ACCOUNT__": arguments.remediation_worker_gcp_service_account,
        "__KUBERNETES_API_CIDR__": arguments.kubernetes_api_cidr,
        "__REMEDIATION_EXTERNAL_EGRESS_CIDR__": arguments.remediation_external_egress_cidr,
        "__REMEDIATION_DATABASE_CIDR__": arguments.remediation_database_cidr,
    }
    shutil.copytree(source, destination)
    for path in destination.rglob("*.yaml"):
        rendered = path.read_text(encoding="utf-8")
        for token, value in replacements.items():
            rendered = rendered.replace(token, value)
        unknown = TOKEN_PATTERN.findall(rendered)
        if unknown:
            raise RuntimeError(f"unresolved required token(s) in {path}: {', '.join(sorted(set(unknown)))}")
        path.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
