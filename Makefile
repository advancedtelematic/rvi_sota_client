# set client version for logs and packages
LOG_VERSION := $(shell git rev-parse HEAD | cut -c-7)
PACKAGE_VERSION := $(shell git describe --tags | cut -c2-)

# command for running the rust docker image
RUST_IN_DOCKER := \
	@docker run --rm \
		--env SOTA_VERSION=$(LOG_VERSION) \
		--env CARGO_HOME=/cargo \
		--volume ~/.cargo:/cargo \
		--volume $(CURDIR):/build \
		--workdir /build \
		advancedtelematic/rust:latest

CARGO := $(RUST_IN_DOCKER) cargo

# function for building new packages
define make-pkg
	@docker run --rm \
		--env-file run/sota.toml.env \
		--env AUTH_SERVER=$(AUTH_SERVER) \
		--env CORE_SERVER=$(CORE_SERVER) \
		--env PACKAGE_VERSION=$(PACKAGE_VERSION) \
		--env CARGO_HOME=/cargo \
		--volume ~/.cargo:/cargo \
		--volume $(CURDIR):/build \
		--workdir /build \
		advancedtelematic/fpm:latest \
		run/pkg.sh $@
endef


.PHONY: help run clean test client image deb rpm version for-meta-rust
.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

run: image ## Run the client inside a Docker container.
	@docker run --rm -it --net=host \
		--env-file run/sota.toml.env \
		--env AUTH_SECTION=$(AUTH_SECTION) \
		--env AUTH_SERVER=$(AUTH_SERVER) \
		--env CORE_SERVER=$(CORE_SERVER) \
		--env CONFIG_ONLY=$(CONFIG_ONLY) \
		--env DEVICE_UUID=$(DEVICE_UUID) \
		--env DEVICE_VIN=$(DEVICE_VIN) \
		--env OUTPUT_PATH=$(OUTPUT_PATH) \
		--env REGISTRY_SERVER=$(REGISTRY_SERVER) \
		--env RUST_LOG=$(RUST_LOG) \
		--env TEMPLATE_PATH=$(TEMPLATE_PATH) \
		advancedtelematic/sota-client:latest

clean: ## Remove all compiled libraries, builds and temporary files.
	$(CARGO) clean
	@rm -f .tmp* *.deb *.rpm run/*.deb run/*.rpm run/*.toml run/sota_client /tmp/sota_credentials.toml
	@rm -rf rust-openssl .cargo

test: rust-openssl ## Run all cargo tests.
	$(CARGO) test

clippy: ## Run clippy lint checks using the nightly compiler.
	@docker run --rm --volume $(CURDIR):/build advancedtelematic/rust \
		rustup run nightly cargo clippy -- -Dclippy

client: rust-openssl src/ ## Compile a new release build of the client.
	$(CARGO) build --release
	@cp target/release/sota_client run/

image: client ## Build a Docker image for running the client.
	@docker build --tag advancedtelematic/sota-client run

deb: client ## Create a new DEB package of the client.
	$(make-pkg)

rpm: client ## Create a new RPM package of the client.
	$(make-pkg)

version: ## Print the version that will be used for building packages.
	@echo $(PACKAGE_VERSION)

for-meta-rust:
	$(RUST_IN_DOCKER) /bin/bash -c "\
		/root/.cargo/bin/rustup override set 1.7.0 && \
		cargo clean && \
		cargo test"

rust-openssl:
	@git clone https://github.com/sfackler/rust-openssl $@
	@cd $@ && git checkout df30e9e700225fb981d8a3cdfaf0b359722a4c9a
	@mkdir -p .cargo
	@echo 'paths = ["$@/openssl", "$@/openssl-sys", "$@/openssl-sys-extras"]' > .cargo/config
