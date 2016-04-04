FROM debian:8

ENV RUST_VER=1.7.0
ENV FPM_VER=1.4.0

RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y \
    curl \
    openssl \
    file \
    gcc \
    libdbus-1-dev \
    libssl-dev \
    make \
    patch \
    rpm \
    ruby \
    ruby-dev \
  && rm -rf /var/lib/apt/lists/*

# install rust
COPY rustup.sha1 rustup.sha1
RUN curl -o rustup.sh https://static.rust-lang.org/rustup.sh \
  && sha1sum -c rustup.sha1 \
  && sh rustup.sh --revision=${RUST_VER} --disable-sudo --yes

# install fpm
RUN gem install fpm -v ${FPM_VER}
# apply patch to add --rpm-service flag
COPY pr862.patch /
RUN patch -i /pr862.patch /var/lib/gems/2.1.0/gems/fpm-${FPM_VER}/lib/fpm/package/rpm.rb

WORKDIR /build
CMD ["make", "deb"]
