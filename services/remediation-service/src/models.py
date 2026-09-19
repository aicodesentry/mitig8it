from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .digests import content_sha256, git_blob_sha1

SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST_PINNED_IMAGE_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]+@sha256:[0-9a-f]{64}$")
SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SnapshotFile(StrictModel):
    path: str = Field(min_length=1, max_length=512)
    content: str
    sha: str | None = None

    @model_validator(mode="after")
    def verify_hash(self) -> "SnapshotFile":
        if self.sha is None:
            return self
        raw = self.content.encode("utf-8")
        supplied = self.sha.lower()
        if supplied.startswith("sha256:"):
            actual = content_sha256(self.content)
        elif re.fullmatch(r"[0-9a-f]{64}", supplied):
            actual = content_sha256(self.content).removeprefix("sha256:")
        elif re.fullmatch(r"[0-9a-f]{40}", supplied):
            actual = git_blob_sha1(raw)
        else:
            raise ValueError("sha must be a Git blob SHA-1 or SHA-256")
        if actual != supplied:
            raise ValueError("file content does not match sha")
        return self


class GitTreeEntry(StrictModel):
    path: str = Field(min_length=1, max_length=512)
    mode: Literal["040000", "100644", "100755", "120000", "160000"]
    type: Literal["blob", "tree", "commit"]
    sha: str = Field(pattern=r"^[0-9a-f]{40}$")


class FindingSnapshot(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: str | int | None = None
    finding_id: str | int | None = None
    snapshot_id: str | int | None = None
    rule_id: str = Field(default="", max_length=200)
    cwe_id: str = Field(default="", max_length=40)
    category: str = Field(default="", max_length=120)
    title: str = Field(default="", max_length=500)
    message: str = Field(default="", max_length=4000)
    file_path: str | None = Field(default=None, max_length=512)
    path: str | None = Field(default=None, max_length=512)
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    trace: list[dict[str, Any]] = Field(default_factory=list, max_length=100)

    @property
    def stable_id(self) -> str:
        value = self.snapshot_id or self.finding_id or self.id
        return str(value) if value is not None else ""

    @property
    def affected_path(self) -> str:
        return self.file_path or self.path or ""

    @model_validator(mode="after")
    def validate_identity(self) -> "FindingSnapshot":
        if not self.stable_id:
            raise ValueError("finding requires id, finding_id, or snapshot_id")
        if self.line_end is not None and self.line_start is not None and self.line_end < self.line_start:
            raise ValueError("line_end precedes line_start")
        return self


class VerificationCheck(StrictModel):
    check_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    kind: Literal["existing_test", "typecheck", "build", "scanner", "exploit", "behavior"]
    argv: list[str] = Field(min_length=1, max_length=32)
    timeout_seconds: int = Field(default=120, ge=1, le=900)

    @field_validator("argv")
    @classmethod
    def validate_argv(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 1024 or "\x00" in item for item in value):
            raise ValueError("argv contains an empty, oversized, or NUL-containing argument")
        return value


class RepairPolicy(StrictModel):
    policy_version: str = Field(default="v1", min_length=1, max_length=100)
    max_files: int = Field(default=5, ge=1, le=20)
    max_changed_lines: int = Field(default=200, ge=1, le=2000)
    max_snapshot_files: int = Field(default=500, ge=1, le=5000)
    max_file_bytes: int = Field(default=512_000, ge=1, le=5_000_000)
    max_snapshot_bytes: int = Field(default=10_000_000, ge=1, le=100_000_000)
    max_tool_calls: int = Field(default=20, ge=1, le=50)
    max_attempts: int = Field(default=3, ge=1, le=5)
    max_context_chars: int = Field(default=128_000, ge=1000, le=1_000_000)
    max_output_chars: int = Field(default=2_000_000, ge=10_000, le=10_000_000)
    max_total_tokens: int = Field(default=120_000, ge=1_000, le=1_000_000)
    max_output_tokens_per_call: int = Field(default=4_096, ge=256, le=32_000)
    max_spend_usd: float = Field(default=2.0, ge=0, le=100)
    input_usd_per_million_tokens: float = Field(default=0, ge=0, le=1000)
    output_usd_per_million_tokens: float = Field(default=0, ge=0, le=1000)
    request_timeout_seconds: int = Field(default=900, ge=10, le=1800)
    supported_platform: Literal["linux"] = "linux"
    allowed_rule_families: list[Literal["sql_parameterization", "command_arguments", "path_containment"]] = Field(
        default_factory=lambda: ["sql_parameterization", "command_arguments", "path_containment"]
    )
    sandbox_image_digest: str | None = None
    allow_development_verification: bool = False
    # Plan section 8 step 4: the agent must ship a reproducer that distinguishes a real repair
    # from disabling the feature. With this set, an empty `verification_checks` is allowed,
    # because the generated regression test supplies the exploit check.
    require_generated_regression_test: bool = True
    # Runs the repository's own `npm test` script as a behavior check when the snapshot proves
    # one exists. Off by default: the sandbox has no network, so most repositories cannot
    # install their dependencies and the run would be a recorded limitation instead.
    run_repository_tests: bool = False
    verification_checks: list[VerificationCheck] = Field(default_factory=list, max_length=20)
    forbidden_path_prefixes: list[str] = Field(
        default_factory=lambda: [
            ".github/",
            ".gitlab/",
            "infrastructure/",
            "tests/",
            "test/",
            "__tests__/",
        ]
    )
    forbidden_filenames: list[str] = Field(
        default_factory=lambda: [
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lockb",
            ".semgrep.yml",
            ".semgrep.yaml",
        ]
    )

    @field_validator("sandbox_image_digest")
    @classmethod
    def validate_image_digest(cls, value: str | None) -> str | None:
        if value is not None and not DIGEST_PINNED_IMAGE_RE.fullmatch(value):
            raise ValueError("sandbox_image_digest must be a complete registry/image@sha256:digest reference")
        return value


class RepairLimits(StrictModel):
    max_files: int | None = Field(default=None, ge=1, le=20)
    max_changed_lines: int | None = Field(default=None, ge=1, le=2000)
    max_attempts: int | None = Field(default=None, ge=1, le=5)
    max_tool_calls: int | None = Field(default=None, ge=1, le=50)
    max_context_tokens: int | None = Field(default=None, ge=1000, le=200_000)
    max_spend_usd: float | None = Field(default=None, ge=0, le=100)


class RepairRequest(StrictModel):
    schema_version: Literal["v1"] = "v1"
    job_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    repository_id: str = Field(min_length=1, max_length=256)
    repository_full_name: str | None = Field(default=None, max_length=300)
    installation_id: str | None = Field(default=None, max_length=256)
    pull_request_id: str | None = Field(default=None, max_length=256)
    pull_request_number: int | None = Field(default=None, ge=1)
    analysis_run_id: str | None = Field(default=None, max_length=256)
    head_sha: str
    base_sha: str
    findings: list[FindingSnapshot] = Field(min_length=1, max_length=100)
    files: list[SnapshotFile] = Field(min_length=1)
    head_tree_oid: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    tree_entries: list[GitTreeEntry] = Field(default_factory=list, max_length=100_000)
    tree_truncated: bool = False
    profile: dict[str, Any] = Field(default_factory=dict)
    policy: RepairPolicy = Field(default_factory=RepairPolicy)
    versions: dict[str, str] = Field(min_length=1)
    stage: str | None = Field(default=None, max_length=40)
    fencing_token: int = Field(default=0, ge=0)
    attempt: int | None = Field(default=None, ge=1)
    limits: RepairLimits | None = None

    @field_validator("head_sha", "base_sha")
    @classmethod
    def validate_commit_sha(cls, value: str) -> str:
        value = value.lower()
        if not SHA_RE.fullmatch(value):
            raise ValueError("commit SHA must be 40 or 64 lowercase hexadecimal characters")
        return value

    @field_validator("versions")
    @classmethod
    def validate_versions(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 40 or any(not k or not v or len(k) > 100 or len(v) > 200 for k, v in value.items()):
            raise ValueError("versions must contain 1-40 non-empty bounded entries")
        return value

    @model_validator(mode="after")
    def validate_tenant_and_limits(self) -> "RepairRequest":
        for name in ("job_id", "tenant_id", "repository_id"):
            if not SAFE_ID_RE.fullmatch(getattr(self, name)):
                raise ValueError(f"{name} contains unsupported characters")
        if self.installation_id is not None and self.installation_id != self.tenant_id:
            raise ValueError("installation_id must match tenant_id")
        if self.limits:
            if self.limits.max_files is not None:
                self.policy.max_files = min(self.policy.max_files, self.limits.max_files)
            if self.limits.max_changed_lines is not None:
                self.policy.max_changed_lines = min(self.policy.max_changed_lines, self.limits.max_changed_lines)
            if self.limits.max_tool_calls is not None:
                self.policy.max_tool_calls = min(self.policy.max_tool_calls, self.limits.max_tool_calls)
            if self.limits.max_attempts is not None:
                self.policy.max_attempts = min(self.policy.max_attempts, self.limits.max_attempts)
            if self.limits.max_context_tokens is not None:
                self.policy.max_context_chars = min(self.policy.max_context_chars, self.limits.max_context_tokens * 4)
            if self.limits.max_spend_usd is not None:
                self.policy.max_spend_usd = min(self.policy.max_spend_usd, self.limits.max_spend_usd)
        return self


class FilePatch(StrictModel):
    path: str
    base_sha256: str
    replacement_content: str
    contents_base64: str
    new_sha256: str
    unified_diff: str


class VerificationSummary(StrictModel):
    status: Literal["passed", "failed", "inconclusive", "unsupported"]
    evidence_digest: str | None = None


class Candidate(StrictModel):
    candidate_id: str
    finding_ids: list[str]
    hypothesis: str
    intended_behavior: str
    assumptions: list[str]
    citations: list[dict[str, Any]]
    patch: list[FilePatch]
    file_manifest: list[dict[str, Any]]
    # Generated regression tests are tracked apart from the application files they exercise:
    # they are verification artifacts, never part of the tree the batch applies.
    generated_tests: list[dict[str, Any]] = Field(default_factory=list)
    artifact_digest: str
    context_manifest_digest: str
    verified_tree_oid: str
    verification: VerificationSummary
    preview: dict[str, Any]


class RepairResponse(StrictModel):
    schema_version: Literal["v1"] = "v1"
    state: Literal["ready", "unsupported", "inconclusive"]
    job_id: str
    tenant_id: str
    repository_id: str
    head_sha: str
    base_sha: str
    request_digest: str
    candidates: list[Candidate] = Field(default_factory=list)
    manifest_digest: str | None = None
    evidence: dict[str, Any]
    reason: dict[str, str] | None = None
    # Findings the request could not repair automatically, each with a machine readable
    # reason. Partial coverage is reported here instead of refusing the whole request.
    skipped: list[dict[str, str]] = Field(default_factory=list)
