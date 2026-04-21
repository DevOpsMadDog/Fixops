FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    curl \
    jq \
    python3 \
    py3-pip \
    git \
    && pip3 install --no-cache-dir --break-system-packages requests

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
