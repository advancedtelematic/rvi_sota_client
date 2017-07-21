FROM debian:jessie-slim

RUN apt-get update && apt-get install -y \
    curl \
    dbus \
    dbus-x11 \
    jq \
    libdbus-1-3 \
    openssl \
    lshw \
  && rm -rf /var/lib/apt/lists/*

ARG bin_dir=/usr/bin/
ARG conf_dir=/usr/etc/

COPY sota_client $bin_dir
COPY sota_start.sh $bin_dir
COPY sota_sysinfo.sh $bin_dir
COPY sota_certificates $conf_dir

EXPOSE 8888 9999
CMD ["/usr/bin/sota_start.sh"]
