# target client binary format
TARGET := x86_64-unknown-linux-gnu

# set version for client logs and new packages
SOTA_VERSION    := $(shell git rev-parse HEAD | cut -c-7)
PACKAGE_VERSION := $(shell git describe --tags | cut -c2-)

DOCKER := \
	@docker run --rm \
		--env RUST_LOG=$(RUST_LOG) \
		--env SOTA_VERSION=$(SOTA_VERSION) \
		--env PACKAGE_VERSION=$(PACKAGE_VERSION) \
		--env CONFIG_PATH=$(CONFIG_PATH) \
		--env AUTH_SERVER=$(AUTH_SERVER) \
		--env REGISTRY_SERVER=$(REGISTRY_SERVER) \
		--env DEVICE_UUID=$(DEVICE_UUID) \
		--env CARGO_HOME=/cargo \
		--volume ~/.cargo:/cargo \
		--volume $(CURDIR):/src \
		--workdir /src

CARGO := $(DOCKER) advancedtelematic/rust:latest cargo

define make-pkg
	$(DOCKER) advancedtelematic/fpm:latest run/make_package.sh $@
endef


.PHONY: help new old clean test doc client image deb rpm sota-version package-version
.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

new: image ## Generate a new config then run the client.
	$(DOCKER) --net=host advancedtelematic/sota-client

old: image ## Use a config file at `./sota.toml` to run the client.
	$(DOCKER) --net=host -v $(CURDIR)/sota.toml:/tmp/sota.toml advancedtelematic/sota-client

test: ## Run all unit tests.
	$(CARGO) test --target=$(TARGET)

doc: ## Generate documentation for the sota crate.
	$(CARGO) doc --lib --no-deps --release

clean: ## Remove all compiled libraries, builds and temporary files.
	$(CARGO) clean
	@rm -f run/sota_client {,run/}*.{deb,rpm} /tmp/sota-tpm*

client: src/ ## Compile a new release build of the client.
	$(CARGO) build --release --target=$(TARGET)
	@cp target/$(TARGET)/release/sota_client run/

image: client ## Build a Docker image for running the client.
	@docker build --tag advancedtelematic/sota-client run

deb: client ## Create a new DEB package of the client.
	$(make-pkg)

rpm: client ## Create a new RPM package of the client.
	$(make-pkg)

sota-version: ## Print the version displayed inside the sota client logs.
	@echo $(SOTA_VERSION)

package-version: ## Print the version used for building packages.
	@echo $(PACKAGE_VERSION)
