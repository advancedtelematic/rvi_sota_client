# set version for client logs and new packages
SOTA_VERSION    := $(shell git rev-parse HEAD | cut -c-7)
PACKAGE_VERSION := $(shell git describe --tags | cut -c2-)

# docker images
IMAGE_RUST := advancedtelematic/rust:x86-1.15.1
IMAGE_SOTA := advancedtelematic/sota-client:latest
IMAGE_FPM  := advancedtelematic/fpm:latest

# target client binary format
TARGET := x86_64-unknown-linux-gnu

DOCKER_RUN := \
	@docker run --rm \
		--env RUST_LOG=$(RUST_LOG) \
		--env SOTA_VERSION=$(SOTA_VERSION) \
		--env PACKAGE_VERSION=$(PACKAGE_VERSION) \
		--env CONFIG_PATH=$(CONFIG_PATH) \
		--env AUTH_SERVER=$(AUTH_SERVER) \
		--env CORE_SERVER=$(CORE_SERVER) \
		--env REGISTRY_SERVER=$(REGISTRY_SERVER) \
		--env DEVICE_UUID=$(DEVICE_UUID) \
		--env RUST_BACKTRACE=1 \
		--volume ~/.cargo/git:/root/.cargo/git \
		--volume ~/.cargo/registry:/root/.cargo/registry \
		--volume $(CURDIR):/src \
		--workdir /src

CARGO := $(DOCKER_RUN) $(IMAGE_RUST) cargo


.PHONY: help build new old clean test doc doc-dev client image deb rpm sota-version package-version
.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

new: image ## Generate a new config then run the client.
	$(DOCKER_RUN) --net=host $(IMAGE_SOTA)

old: image ## Use a local `sota.toml` config file to run the client.
	$(DOCKER_RUN) --net=host --volume sota.toml:/usr/local/etc/sota.toml $(IMAGE_SOTA)

test: ## Run all unit tests.
	$(CARGO) test --target=$(TARGET)

doc: ## Generate documentation for the sota crate.
	$(CARGO) doc --lib --no-deps --release

doc-dev: ## Generate development documentation for the sota crate.
	$(CARGO) doc --lib

clean: ## Remove all compiled libraries, builds and temporary files.
	$(CARGO) clean
	@rm -f run/sota_client {,run/}*.{deb,rpm} /tmp/sota-tpm*

client: src/ ## Compile a new release build of the client.
	$(CARGO) build --release --target=$(TARGET)
	@cp target/$(TARGET)/release/sota_client run/

client-dev: ## Compile a new development build of the client
	$(CARGO) build --target=$(TARGET)

image: client ## Build a Docker image for running the client.
	@docker build --tag advancedtelematic/sota-client run

deb: client ## Create a new DEB package of the client.
	$(DOCKER_RUN) $(IMAGE_FPM) run/make_package.sh deb

rpm: client ## Create a new RPM package of the client.
	$(DOCKER_RUN) $(IMAGE_FPM) run/make_package.sh rpm

sota-version: ## Print the version displayed inside the sota client logs.
	@echo $(SOTA_VERSION)

package-version: ## Print the version used for building packages.
	@echo $(PACKAGE_VERSION)
