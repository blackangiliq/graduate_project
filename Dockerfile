# syntax=docker/dockerfile:1

FROM python:3.12-slim-bookworm AS jadx

# The checksum is published with the pinned GitHub release asset.
ADD --checksum=sha256:1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3 https://github.com/skylot/jadx/releases/download/v1.5.7/jadx-1.5.7.zip /tmp/jadx.zip
RUN python -m zipfile -e /tmp/jadx.zip /opt/jadx \
    && chmod 0755 /opt/jadx/bin/jadx

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    SCA_HOSTED=1 \
    SCA_SKIP_INTRO=1 \
    SCA_JADX=/opt/jadx/bin/jadx \
    JADX_OPTS="-Xmx768m -XX:ActiveProcessorCount=2" \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_MAX_UPLOAD_SIZE=128 \
    STREAMLIT_SERVER_FILE_WATCHER_TYPE=none

RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --user-group --no-create-home --home-dir /tmp sca

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
COPY --from=jadx /opt/jadx /opt/jadx
COPY app.py README.md LICENSE THIRD_PARTY_NOTICES.md ./
COPY .streamlit/config.toml ./.streamlit/config.toml
COPY sca ./sca
COPY docs ./docs
COPY samples ./samples

USER 10001:10001
EXPOSE 8501
HEALTHCHECK --interval=15s --timeout=5s --start-period=15s \
    CMD ["python", "-c", "from urllib.request import urlopen; urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3).close()"]
CMD ["python", "-m", "streamlit", "run", "app.py"]
