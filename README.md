# OTA+ client

The OTA+ client source repository.

## Prerequisites

A stable installation of Rust with Cargo is required. Docker is used for compiling a statically linked binary, however to do this locally a MUSL build target is also needed.

The easiest way to get both is via [Rustup](https://www.rustup.rs):

1. `curl https://sh.rustup.rs -sSf | sh` (feel free to inspect the script first)
2. `rustup target add x86_64-unknown-linux-musl`

## Makefile targets

Run `make help` (or simply `make`) to see a list of Makefile targets. The following targets are available:

Target         | Description
-------------: | :----------
all            | Clean, test and make new DEB and RPM packages.
run            | Run the client inside a Docker container.
clean          | Remove all compiled libraries, builds and temporary files.
test           | Run all Cargo tests.
client-release | Make a release build of the client.
client-musl    | Make a statically linked release build of the client.
image          | Build a Docker image from a statically linked binary.
deb            | Make a new DEB package inside a Docker container.
rpm            | Make a new RPM package inside a Docker container.

## Customization

Assuming an up-to-date Docker image (built with `make image`), you can configure how the client starts using the following environment variables:

Variable             | Default value
-------------------: | :--------------------
`OTA_AUTH_URL`       | http://localhost:9001
`OTA_WEB_URL`        | http://localhost:9000
`OTA_CORE_URL`       | http://localhost:8080
`OTA_WEB_USER`       | `demo@advancedtelematic.com`
`OTA_WEB_PASSWORD`   | `demo`
`OTA_CLIENT_VIN`     | (generated)
`OTA_AUTH_CLIENT_ID` | (generated)
`OTA_AUTH_SECRET`    | (generated)
`PACKAGE_MANAGER`    | `dpkg`
`OTA_HTTP`           | `false`
`PROVISION`          | `false`

### Provisioning

Setting `PROVISION=true` will output a newly generated `sota.toml` to STDOUT then quit, rather than starting the client.

### Example

```
docker run --rm -it --net=host \
  --env OTA_AUTH_URL="http://auth-plus-staging.gw.prod01.advancedtelematic.com" \
  --env OTA_WEB_URL="http://ota-plus-web-staging.gw.prod01.advancedtelematic.com" \
  --env OTA_CORE_URL="http://ota-plus-core-staging.gw.prod01.advancedtelematic.com" \
  advancedtelematic/sota-client:latest
```

The `--net=host` flag is only required if the Docker container needs to communicate with other containers running on the same host.
