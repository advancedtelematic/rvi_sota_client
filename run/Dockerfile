FROM debian:jessie-slim

RUN apt-get update && apt-get install -y \
    autoconf \
    bison \
    build-essential \
    e2fslibs-dev \
    git \
    gtk-doc-tools \
    libarchive-dev \
    libattr1-dev \
    libcap-dev \
    libfuse-dev \
    libgirepository1.0-dev \
    libglib2.0-dev \
    libgpgme11-dev \
    liblzma-dev \
    libsoup2.4-dev \
    libsystemd-journal-dev \
    curl \
    dbus \
    dbus-x11 \
    jq \
    libdbus-1-3 \
    lshw \
    openssl \
    python \
    python-pip \
  && pip install canonicaljson \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src/

ENV LIBGSYSTEM_VERSION v2015.1
ENV OSTREE_VERSION     v2017.5

RUN git clone git://git.gnome.org/libgsystem \
	&& cd libgsystem \
	&& git checkout $LIBGSYSTEM_VERSION \
	&& ./autogen.sh --prefix=/usr --enable-gtk-doc \
	&& make -j $(nproc) \
	&& make install \
  && git clone https://github.com/ostreedev/ostree.git \
	&& cd ostree \
	&& git checkout $OSTREE_VERSION \
	&& ./autogen.sh --prefix=/usr \
	&& make -j $(nproc) \
  && make install \
  && rm -rf /src \
  && apt-get --purge autoremove -y \
     autoconf \
     bison \
     build-essential \
     git \
     gtk-doc-tools \
     python-pip

ARG bin_dir=/usr/local/bin
ARG conf_dir=/usr/local/etc

COPY canonical_json.py $bin_dir
COPY sota_client $bin_dir
COPY sota_start.sh $bin_dir
COPY sota_sysinfo.sh $bin_dir

COPY sota_certificates $conf_dir

EXPOSE 8888 9999
CMD ["/usr/local/bin/sota_start.sh"]
