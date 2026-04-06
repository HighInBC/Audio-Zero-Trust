FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/
COPY src /app/src

RUN pip install --no-cache-dir .

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD test -f /data/recordings/.azt-recorder-heartbeat || exit 1

ENTRYPOINT ["azt-recorder"]
CMD ["--config", "/app/config/recorder.yaml"]
