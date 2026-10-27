FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for OpenGrep
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Keep Semgrep's dependency graph out of the network-facing application interpreter. Only its
# executable is exposed; the runner invokes it as an offline subprocess.
COPY src/requirements.txt src/requirements-scanner.txt ./
RUN python -m venv /opt/mitig8it/scanner \
    && /opt/mitig8it/scanner/bin/pip install --no-cache-dir -r requirements-scanner.txt \
    && ln -s /opt/mitig8it/scanner/bin/semgrep /usr/local/bin/semgrep \
    && pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

RUN semgrep --version \
    && test "$(command -v python)" != /opt/mitig8it/scanner/bin/python \
    && test "$(readlink -f "$(command -v semgrep)")" = /opt/mitig8it/scanner/bin/semgrep \
    && python -c "import importlib.util; assert importlib.util.find_spec('semgrep') is None"

# Expose default local port
EXPOSE 8001

# Cloud Run injects PORT; use src as app dir for reliable module import.
CMD ["sh", "-c", "uvicorn main:app --app-dir src --host 0.0.0.0 --port ${PORT:-8001}"]
