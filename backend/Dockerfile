FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FRAUDMESH_DATA_DIR=/data \
    FRAUDMESH_MODELS_DIR=/models

# libgomp1: OpenMP runtime for XGBoost; libglib2.0-0: OpenCV headless runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 libglib2.0-0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /srv/backend
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app ./app

# least privilege: run as an unprivileged user that owns only its data/model volumes
RUN useradd --system --uid 10001 --create-home fraudmesh \
 && mkdir -p /data /models && chown fraudmesh:fraudmesh /data /models
USER fraudmesh

EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=20 \
  CMD python -c "import urllib.request,json,sys; sys.exit(0 if json.load(urllib.request.urlopen('http://localhost:8000/api/health'))['ready'] else 1)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
