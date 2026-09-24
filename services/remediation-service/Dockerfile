FROM python:3.12.12-slim

# The compose stack mounts a named volume at the local backend's data directory. Docker
# initializes that mount from the image, so the directory must already exist in the image with
# the runtime UID's ownership; otherwise the mount root is created root-owned and the service,
# which runs as 65532, cannot write its SQLite database or artifacts. The default matches the
# compose mount path, and the build argument keeps a different deployment path buildable.
ARG REMEDIATION_DATA_DIR=/var/lib/remediation

# The image builds twice from this file. The service image runs unprivileged as 65532, as it
# always has. The Cloud Run job image is built with RUNTIME_UID=0 because its entrypoint
# (src/sandbox/job_entrypoint.py) has to drop the repository's check to a *different*
# unprivileged user, and only a process that starts as root can change uid. Cloud Run offers
# no way to override a container's user, so the difference has to live in the image.
#
# Root in the job image is not a loosening of the sandbox: the entrypoint is trusted code that
# never executes repository content, and the check itself runs as `sandboxcheck`, which holds
# none of the task's credentials and cannot read the entrypoint's environment or /proc entries.
ARG RUNTIME_UID=65532

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REMEDIATION_DATA_DIR=${REMEDIATION_DATA_DIR}
WORKDIR /app

# A pinned Node 22 LTS runtime. The development-only local subprocess sandbox driver runs a
# repository's own checks (`node tests/verify.js`, `node --check`) as subprocesses inside this
# container, so the interpreter has to be present. It is 22 rather than 20 because the generated
# proofs load TypeScript modules through Node's own type stripper, which arrived in 22.6, and
# resolve their imports through `module.registerHooks`, which arrived in 22.15; `node --version`
# below is what fails the build if either is missing. The official tarball is verified against a
# pinned SHA-256 per architecture; the build tools are removed in the same layer.
ARG NODE_VERSION=22.23.3
ARG NODE_SHA256_X64=df450af89261115ef9f9e3830c3eeb2cc9213b63c720b1af623cb5dcbe2e02de
ARG NODE_SHA256_ARM64=a44aeb94849a299b22df10b9e622ec2f605c2183501bc40590705131de7c740f
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl xz-utils; \
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

COPY requirements.txt .
# `sandboxcheck` owns nothing and is a member of no group. It exists so the Cloud Run job
# entrypoint has an identity to run repository checks as that is not the identity holding the
# job's Google credentials and the per-execution result nonce. It is created in both images so
# the two stay byte-comparable apart from the runtime user.
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system --gid 65532 app \
    && adduser --system --uid 65532 --gid 65532 --no-create-home app \
    && addgroup --system --gid 65533 sandboxcheck \
    && adduser --system --uid 65533 --gid 65533 --no-create-home --shell /usr/sbin/nologin sandboxcheck \
    && mkdir -p "${REMEDIATION_DATA_DIR}" \
    && chown 65532:65532 "${REMEDIATION_DATA_DIR}" \
    && chmod 700 "${REMEDIATION_DATA_DIR}"
COPY src ./src
USER ${RUNTIME_UID}
EXPOSE 8002
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8002", "--no-access-log"]
