FROM debian:8

RUN apt-get update \
 && apt-get install -y openssl dbus libdbus-1-3 dbus-x11 libdbus-glib-1-2 \
 && mkdir /var/sota

COPY sota_client /bin/sota_client
COPY run.sh /bin/run.sh
COPY client.toml /var/sota/client.toml

EXPOSE 9080
CMD ["/bin/run.sh"]
