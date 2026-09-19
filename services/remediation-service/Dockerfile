FROM python:3.12.12-slim

# The compose stack mounts a named volume at the local backend's data directory. Docker
# initializes that mount from the image, so the directory must already exist in the image with
# the runtime UID's ownership; otherwise the mount root is created root-owned and the service,
# which runs as 65532, cannot write its SQLite database or artifacts. The default matches the
# compose mount path, and the build argument keeps a different deployment path buildable.
ARG REMEDIATION_DATA_DIR=/var/lib/remediation
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REMEDIATION_DATA_DIR=${REMEDIATION_DATA_DIR}
WORKDIR /app

# A pinned Node 20 LTS runtime. The development-only local subprocess sandbox driver runs a
# repository's own checks (`node tests/verify.js`, `node --check`) as subprocesses inside this
# container, so the interpreter has to be present. The official tarball is verified against a
# pinned SHA-256 per architecture; the build tools are removed in the same layer.
ARG NODE_VERSION=20.20.2
ARG NODE_SHA256_X64=df770b2a6f130ed8627c9782c988fda9669fa23898329a61a871e32f965e007d
ARG NODE_SHA256_ARM64=73093db209e4e9e09dd7d15a47aeaab1b74833830df03efa5f942a1122c5fa71
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
    npm --version

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup --system --gid 65532 app \
    && adduser --system --uid 65532 --gid 65532 --no-create-home app \
    && mkdir -p "${REMEDIATION_DATA_DIR}" \
    && chown 65532:65532 "${REMEDIATION_DATA_DIR}" \
    && chmod 700 "${REMEDIATION_DATA_DIR}"
COPY src ./src
USER 65532:65532
EXPOSE 8002
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8002", "--no-access-log"]
