FROM jimmycuadra/rust:1.15.0

RUN apt-get update && apt-get install -y \
    libdbus-1-3 \
    libdbus-1-dev \
    dbus-x11 \
    python3 \
    python3-pip \
    libssl-dev \
    openssl \
   && rm -rf /var/lib/apt/lists/*

RUN pip3 install canonicaljson

ARG bin_dir=/usr/local/bin
ARG conf_dir=/usr/local/etc

COPY canonical_json.py $bin_dir

ENTRYPOINT ["/usr/local/bin/cargo"]
