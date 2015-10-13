# sota-client

This is the client (in-vehicle) portion of the SOTA project. It is provided as an RPM that can be installed on a target system. See the [main SOTA Server project](https://github.com/advancedtelematic/rvi_sota_server) and [associated architecture document](http://advancedtelematic.github.io/rvi_sota_server/dev/architecture.html) for more information.

## Building and running

To see the SOTA client in action, you will need some supporting components running. The general steps are:

1. Build and run RVI server and client nodes
2. Build and run rvi_sota_client
3. Build and run rvi_sota_demo

### Building and running RVI nodes

You can build RVI directly from [its GitHub repo](https://github.com/PDXostc/rvi_core), or simply run our docker image. These instructions assume you are running the docker image.

1. Pull the image: `docker pull advancedtelematic/rvi`.
2. In two terminal windows, run the rvi client and server nodes
  * Client: `docker run -it --name rvi-client --expose 8901 --expose 8905-8908 -p 8901:8901 -p 8905:8905 -p 8906:8906 -p 8907:8907 -p 8908:8908 advancedtelematic/rvi client`
  * Server: `docker run -it --name rvi-server --expose 8801 --expose 8805-8808 -p 8801:8801 -p 8805:8805 -p 8806:8806 -p 8807:8807 -p 8808:8808 advancedtelematic/rvi server`

### Building and running SOTA client

The SOTA client builds as a docker container. As long as you have `rust` and `cargo` installed, `make docker` should build a docker image called `sota-client`.

You can also build the SOTA client from within a docker container; this will be necessary if your build environment is not running linux. From the project root, run `docker run -it --rm -v $PWD:/build advancedtelematic/rust:1.2.0 /bin/bash`. Once you are at a bash prompt, run the following commands:

```
apt-get install -y libssl-dev
cd /build
cargo build --release
exit
```
Now you can run `make docker` from your normal build environment.

Once the sota-client docker image is built (by either of the two methods above), you can run it with `docker run -it --name sota-client -p 9000:9000 --link rvi-client:rvi-client -e RUST_LOG=info advancedtelematic/sota-client`.

### Packaging the SOTA client

[FPM](https://github.com/jordansissel/fpm) is used to package the SOTA client into DEB or RPM packages.

The easiest way to build a package is by using the Dockerfile which has been set up with the correct libraries. The image can be built from the project root with `docker build -t sota-packager docker/pkg`, then executed with `docker run -it --rm -v $PWD:/build sota-packager make rpm`.

Alternatively, assuming FPM and the correct libraries are installed, packages can be built for the same architecture using `make deb` and `make rpm` in the project root.

### Run the demo

To watch the client in action, you can run a demo with a dummy server. Clone the [rvi_sota_demo](https://github.com/PDXostc/rvi_sota_demo) project, then run `python sota_server.py http://<docker_ip_address>:8801`.

### Documentation

To create a static HTML version of the module documentation run `cargo doc`.
Unfortunately this will only create documentation for the public interface. If
you want the full documentation you need to run `cargo doc -v` extract the
`rustdoc` command from the output and append `--no-defaults --passes
"collapse-docs" --passes "unindent-comments" --passes strip-hidden` to it.
