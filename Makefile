# set version for client logs and new packages
SOTA_VERSION    := $(shell git rev-parse HEAD | cut -c-7)
PACKAGE_VERSION := $(shell git describe --tags | cut -c2-)

# docker images
IMAGE_RUST := advancedtelematic/rust:x86-1.15.1
IMAGE_SOTA := advancedtelematic/sota-client:latest
IMAGE_FPM  := advancedtelematic/fpm:latest

# client binary target triple
TARGET := x86_64-unknown-linux-gnu
# client binary features
FEATURES := default

DOCKER_DIR := $(CURDIR)/sota-client/docker
DOCKER_RUN := \
	@docker run --rm \
		--env RUST_LOG=$(RUST_LOG) \
		--env RUST_BACKTRACE=$(RUST_BACKTRACE) \
		--env SOTA_VERSION=$(SOTA_VERSION) \
		--env PACKAGE_VERSION=$(PACKAGE_VERSION) \
		--env CONFIG_PATH=$(CONFIG_PATH) \
		--env AUTH_SERVER=$(AUTH_SERVER) \
		--env CORE_SERVER=$(CORE_SERVER) \
		--env REGISTRY_SERVER=$(REGISTRY_SERVER) \
		--env DEVICE_UUID=$(DEVICE_UUID) \
		--volume ~/.cargo/git:/root/.cargo/git \
		--volume ~/.cargo/registry:/root/.cargo/registry \
		--volume $(CURDIR)/sota-client:/src \
		--workdir /src
CARGO := $(DOCKER_RUN) $(IMAGE_RUST) cargo

.PHONY: help start generate test doc client image image-uptane deb rpm sota-version package-version
.DEFAULT_GOAL := help

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%16s\033[0m : %s\n", $$1, $$2}' $(MAKEFILE_LIST)

start: image ## Use a local `sota.toml` config file to run the client.
	$(DOCKER_RUN) --net=host --volume sota.toml:/usr/local/etc/sota.toml $(IMAGE_SOTA)

generate: image ## Generate a new config then run the client.
	$(DOCKER_RUN) --net=host $(IMAGE_SOTA)

test: ## Run all unit tests.
	$(CARGO) test --target=$(TARGET) --features=docker

doc: ## Generate documentation for the sota crate.
	$(CARGO) doc --lib --no-deps --release --features=$(FEATURES)

client: sota-client/src ## Compile a new release build of the client.
	$(CARGO) build --release --target=$(TARGET) --features=$(FEATURES)
	@cp target/$(TARGET)/release/sota_client sota-client/docker/

image: client ## Build a Docker image for running the client.
	@docker build --tag advancedtelematic/sota-client $(DOCKER_DIR)

image-uptane: image ## Build a Docker image for running the client with uptane.
	@docker build --tag advancedtelematic/sota-client-uptane -f $(DOCKER_DIR)/DockerfileUptane .

clean: ## Remove all compiled libraries, builds and temporary files.
	$(CARGO) clean
	@rm -rf $(DOCKER_DIR)/sota_client $(DOCKER_DIR)/*.{deb,rpm} /tmp/sota-*

deb: client ## Create a new DEB package of the client.
	$(DOCKER_RUN) $(IMAGE_FPM) docker/make_package.sh deb

rpm: client ## Create a new RPM package of the client.
	$(DOCKER_RUN) $(IMAGE_FPM) docker/make_package.sh rpm

sota-version: ## Print the version displayed inside the sota client logs.
	@echo $(SOTA_VERSION)

package-version: ## Print the version used for building packages.
	@echo $(PACKAGE_VERSION)
