FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    python3 \
    python3-pip \
    curl \
    wget \
    iputils-ping \
    iproute2 \
    netcat-openbsd \
    tcpdump \
    nmap \
    hping3 \
    hydra \
    nikto \
    sqlmap \
    net-tools \
    dnsutils \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
