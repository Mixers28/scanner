FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir ".[hub]"

VOLUME ["/data"]

EXPOSE 8765

ENV HUB_PORT=8765 \
    HUB_DATA_DIR=/data

CMD python -m scanner hub \
    --host 0.0.0.0 \
    --port ${HUB_PORT} \
    --api-key ${HUB_API_KEY} \
    --data-dir ${HUB_DATA_DIR}
