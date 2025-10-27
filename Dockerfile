# Dockerfile: Simple approach using strings + Python
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /work

# Install dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-setuptools \
    unzip \
    binutils \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

# Copy scripts
COPY entrypoint.sh /work/entrypoint.sh
COPY scripts /work/scripts
RUN chmod +x /work/entrypoint.sh /work/scripts/*.sh

VOLUME ["/work/input", "/work/output"]

ENTRYPOINT ["/work/entrypoint.sh"]
CMD []
