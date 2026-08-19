# Gateway image for the nftconf docker lab.
# b4f-rocky:10-amd64 is Rocky Linux 10 with a faster CDN.
FROM b4f-rocky:10-amd64

RUN dnf -y --setopt=install_weak_deps=False install \
        python3 \
        nftables \
        iproute \
        iputils \
        curl \
        nmap-ncat \
        procps-ng \
        ca-certificates \
    && dnf clean all \
    && rm -rf /var/cache/dnf

WORKDIR /opt/nftconf
ENV PYTHONPATH=/opt/nftconf
ENV PATH="/opt/nftconf:${PATH}"

# Base image uses an interactive bash entrypoint; reset so compose `command:` runs as-is.
ENTRYPOINT ["/usr/bin/env"]
# Source is bind-mounted at runtime; keep a thin image.
CMD ["/opt/nftconf/demo/scripts/entrypoint.sh"]
