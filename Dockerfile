FROM python:3.13-slim-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 iptables dnsmasq-base systemd dbus-bin && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY engine.py server.py ./
COPY static ./static
COPY reefy/icon.png ./reefy/icon.png
# Runtime needs the manifest's explicit host-network permissions. The private
# builder always overrides this to UID 65534 with all capabilities dropped.
USER 0
EXPOSE 8080
LABEL org.opencontainers.image.title="Reefy IP Router" org.opencontainers.image.version="v2026.10.28-04"
CMD ["python3", "server.py"]
