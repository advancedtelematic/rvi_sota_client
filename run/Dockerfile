FROM debian:8

RUN apt-get update && apt-get install -y \
    dbus \
    dbus-x11 \
    gettext \
    httpie \
    jq \
    libdbus-1-3 \
    libdbus-glib-1-2 \
    openssl \
    lshw \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir /var/sota

COPY sota_client /usr/bin/
COPY sota.toml.template /etc/
COPY sota_certificates /etc/
COPY run.sh /usr/bin/
COPY system_info.sh /usr/bin/
COPY sota_ostree.sh /usr/bin/

EXPOSE 8888 9080
CMD ["/usr/bin/run.sh"]
