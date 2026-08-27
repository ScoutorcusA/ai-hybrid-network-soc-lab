FROM zeek/zeek:8.0.10

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        coreutils \
        iproute2 \
        jq \
        procps \
        suricata \
        tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY start-sensor.sh /usr/local/bin/start-sensor

RUN chmod 0755 /usr/local/bin/start-sensor

ENTRYPOINT ["/usr/local/bin/start-sensor"]
