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
