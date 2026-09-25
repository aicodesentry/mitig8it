# The Mitig8it GitHub Action: the review pipeline in one image, run by the customer's own runner.
#
# Build context is the repository root, because the image bundles two services and the action
# that drives them. Everything the review needs is baked in: no package is fetched at run time,
# so a job that has network access to nothing but api.github.com still works.
#
# Python 3.11 is the base because the analysis service pins and tests against it, and the
# remediation service's sources parse and run on it. One interpreter serves both.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MITIG8IT_ANALYSIS_SRC=/opt/mitig8it/services/analysis-service/src \
    MITIG8IT_REMEDIATION_ROOT=/opt/mitig8it/services/remediation-service \
    MITIG8IT_GITHUB_SERVICE_ROOT=/opt/mitig8it/services/github-service \
    MITIG8IT_PUBLISHER=/opt/mitig8it/action/publisher/publish.js \
    SANDBOX_BROKER_MODE=inprocess \
    SANDBOX_DRIVER=local \
    SANDBOX_LOCAL_WORKSPACE_ROOT=/tmp/mitig8it-sandbox

# git is required by semgrep. The rest of the scan needs nothing else from the distribution.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# A pinned Node runtime, verified against a per-architecture SHA-256. Node is needed three times
# over: the repair engine runs `node --check` on every patched JavaScript file, loads the patched
# module to prove it still imports, and runs the repository's own checks as subprocesses when it
# verifies a fix. The publisher is Node too, because it reuses the github-service's publishing
# code rather than reimplementing it.
#
# The version is the remediation service's, and it has to be exactly the remediation service's.
# This image used to pin 20.20.2 while services/remediation-service/Dockerfile pinned 22, and the
# comment here claimed the two matched. They did not, and the cost was silent: the sandbox test
# harness loads its generated proofs through Node's own type stripper
# (`module.stripTypeScriptTypes`, 22.6) and resolves their imports through `module.registerHooks`
# (22.15), so on 20 it refused every JavaScript and TypeScript verification. The September 2026
# trial produced zero fixes on all four JavaScript repositories for this one reason, including
# findings in the supported `command_arguments` and `path_containment` families.
#
# tests/test_action_definition.py compares these three values against the remediation service's
# Dockerfile, so a bump there that is not mirrored here fails the build rather than turning
# JavaScript repair off again. The capability probe at the end of the layer is the second guard:
# it fails the image build rather than the pull request.
ARG NODE_VERSION=22.23.3
ARG NODE_SHA256_X64=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
ARG NODE_SHA256_ARM64=a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl xz-utils; \
    case "$(dpkg --print-architecture)" in \
      amd64) NODE_ARCH=x64; NODE_SHA256="${NODE_SHA256_X64}" ;; \
      arm64) NODE_ARCH=arm64; NODE_SHA256="${NODE_SHA256_ARM64}" ;; \
      *) echo "unsupported architecture for the pinned Node runtime" >&2; exit 1 ;; \
    esac; \
    curl -fsSLo /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"; \
    echo "${NODE_SHA256}  /tmp/node.tar.xz" | sha256sum -c -; \
    tar -xJf /tmp/node.tar.xz -C /usr/local --strip-components=1 --no-same-owner \
        --exclude='*/include' --exclude='*/share/doc' --exclude='*/share/man' \
        --exclude='*/CHANGELOG.md' --exclude='*/LICENSE' --exclude='*/README.md'; \
    rm -f /tmp/node.tar.xz; \
    rm -rf /usr/local/lib/node_modules/npm/docs /usr/local/lib/node_modules/npm/man; \
    apt-get purge -y --auto-remove curl xz-utils; \
    rm -rf /var/lib/apt/lists/*; \
    node --version; \
    npm --version; \
    node --experimental-strip-types --disable-warning=ExperimentalWarning \
        -e "const m = require('node:module'); m.stripTypeScriptTypes('const x: number = 1;'); if (typeof m.registerHooks !== 'function') { throw new Error('this Node cannot resolve TypeScript imports for the sandbox harness'); }"

WORKDIR /opt/mitig8it

COPY action/requirements.txt action/requirements.txt
RUN pip install --no-cache-dir -r action/requirements.txt

# The publisher needs the github-service's runtime dependencies, but none of its devDependencies
# and none of the services it never starts here. `--omit=dev` keeps jest and eslint out of a
# customer's image.
COPY services/github-service/package.json services/github-service/package-lock.json \
     services/github-service/
RUN cd services/github-service && npm ci --omit=dev && npm cache clean --force

COPY services/analysis-service/src services/analysis-service/src
COPY services/remediation-service/src services/remediation-service/src
COPY services/github-service/src services/github-service/src
COPY services/api-service/src/services/prAnalysisOrchestrator.js \
     services/api-service/src/services/suggestedFixValidator.js \
     services/api-service/src/services/
COPY action action

# Prove at build time that the scanner is present and both services import. A missing semgrep
# would otherwise surface as a failed scan in someone else's pull request.
RUN semgrep --version \
    && python -c "import sys; sys.path.insert(0, '/opt/mitig8it/services/analysis-service/src'); import main" \
    && python -c "import sys; sys.path.insert(0, '/opt/mitig8it/services/remediation-service'); import src.engine" \
    && node -e "require('/opt/mitig8it/services/github-service/src/services/githubInternalOperations')"

ENTRYPOINT ["/opt/mitig8it/action/entrypoint.sh"]
