# Sota Client in Docker

First you need to spawn two working and connected rvi nodes. One server and one
client. See the [rvi documentation](https://github.com/PDXostc/rvi_core) for
instructions. We assume you've named them `rvi-server` and `rvi-client`
respectively.

Then you can run the Sota client with

```
docker run -it --name sota-client -p 9000:9000 --link rvi-client:rvi-client advancedtelematic/sota-client
```

The generated image accepts several environment variables for configuration.

* `RVI_ADDR`: the address under which the RVI client node can be reached,
  defaults to `rvi_client`
* `RVI_PORT`: the port under which the Service Edge of the RVI client node can
  be reached, defaults to `8901`
* `SOTA_CLIENT_ADDR`: The address the client should listen on and advertise,
  defaults to the address of `eth0` in the running container
* `SOTA_CLIENT_PORT`: The port the client should advertise and listen on,
  defaults to `9000`

## Known Issues

* The address is both the listening and advertised address. That means you
  currently can't connect the client to a RVI node, thats running on a different
  docker host machine.
