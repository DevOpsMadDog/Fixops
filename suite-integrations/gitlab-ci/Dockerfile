FROM alpine:3.20

LABEL maintainer="DevOpsMadDog <info@devopsai.co>"
LABEL description="ALDECI ASPM scanner for GitLab CI/CD — SAST, SCA, and IaC security scanning"
LABEL org.opencontainers.image.source="https://github.com/DevOpsMadDog/Fixops"

RUN apk add --no-cache \
    bash \
    curl \
    jq \
    python3 \
    py3-pip \
    git \
    tar \
    && pip3 install --no-cache-dir --break-system-packages requests

RUN mkdir -p /opt/aldeci

COPY scan.sh /opt/aldeci/scan.sh
RUN chmod +x /opt/aldeci/scan.sh

# GitLab CI runs as the gitlab-runner user; ensure script is world-executable
RUN chmod a+rx /opt/aldeci/scan.sh

ENTRYPOINT ["/opt/aldeci/scan.sh"]
