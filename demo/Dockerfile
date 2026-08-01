# Gateway image for the nftconf docker lab.
FROM b4f-debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        nftables \
        iproute2 \
        iputils-ping \
        curl \
        netcat-openbsd \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/nftconf
ENV PYTHONPATH=/opt/nftconf
ENV PATH="/opt/nftconf:${PATH}"

# Source is bind-mounted at runtime; keep a thin image.
CMD ["/opt/nftconf/demo/scripts/entrypoint.sh"]
