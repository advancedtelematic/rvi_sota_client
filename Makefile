NAME=sota_client
VERSION=0.2.0
PREFIX=/opt/ats

SRCS := $(wildcard src/*.rs)
SRCS += Cargo.toml

.PHONY: release debug docker all clean

target/release/sota_client: $(SRCS)
	cargo build --release

target/debug/sota_client: $(SRCS)
	cargo build

docker/sota_client: target/release/sota_client
	cp target/release/sota_client docker/run

.PHONY: docker
docker: docker/run/sota_client docker/run/client.toml
	docker build -t advancedtelematic/sota-client docker/run

.PHONY: deb
deb: target/release/sota_client docker/pkg/sota-client.conf client.toml
	fpm -s dir -t deb -n $(NAME) -v $(VERSION) --prefix $(PREFIX) -a native \
		--deb-upstart docker/pkg/sota-client.conf \
		target/release/sota_client=sota_client client.toml

.PHONY: rpm
rpm: target/release/sota_client docker/pkg/sota-client.service client.toml
	fpm -s dir -t rpm -n $(NAME) -v $(VERSION) --prefix $(PREFIX) -a native \
		--rpm-service docker/pkg/sota-client.service \
		target/release/sota_client=sota_client client.toml

clean:
	rm -f docker/run/sota_client
	rm -f *.deb
	rm -f *.rpm
	cargo clean

# aliases
debug: target/debug/sota_client
release: target/release/sota_client
all: docker
