FROM debian:8

RUN apt-get update && apt-get install -y \
    curl \
    dbus \
    dbus-x11 \
    jq \
    libdbus-1-3 \
    openssl \
    lshw \
  && rm -rf /var/lib/apt/lists/*

COPY sota_client /usr/bin/
COPY sota_start.sh /usr/bin/
COPY sota_certificates /etc/
COPY sota_sysinfo.sh /usr/bin/
COPY sota_ostree.sh /usr/bin/

EXPOSE 8888 9999
CMD ["/usr/bin/sota_start.sh"]
