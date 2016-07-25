FROM advancedtelematic/fpm

COPY sota_client /usr/bin/
COPY sota.toml.template /etc/
COPY start-up.sh /usr/bin/

ENV LANG="en_US.UTF-8"
WORKDIR /build
EXPOSE 8888

CMD start-up.sh
