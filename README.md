# Kong Debug Tool

A tool for collecting debug information for Kong Gateway and Kong Mesh / Kuma.

Currently supports docker and k8s deployments. Mesh and VM not currently supported.

## What is collected

The tool collects the following information and saves it as a `.tar.gz` file:

- Logs for all Kong gateway containers (K8s / Docker)
- Logs for all Kong Ingress Controller instances (K8s)
- Pod spec for all Kong gateway & ingress controller instances (K8s)
- Docker inspect information for all Kong gateway instances (Docker)
- Logs for all Kuma / Kong Mesh control-plane instances (K8s / Docker)
- Logs for all Kuma / Kong Mesh dataplanes (K8s / Docker)
- Pod spec for Kuma / Kong Mesh control-plane instances (K8s)
- Docker inspect information for all Kuma / Kong Mesh control-plane instances (Docker)
- Summary entity information for all workspaces (Not config, purely counts)
- Status endpoint metrics
- Workspace config dumps if `ENABLE_CONFIG_DUMP` is set to true

## Privacy 

This tool _does not_ send any collected information outside of the machine where it was executed. It is the responsibility of the user executing this tool to ensure that sensitive information is not unintentionally collected _before_ they transmit the output file (s) to Kong. 

Examples of sensitive data that should be checked for include (but are not limited to):

- Keys
- Passwords
- Other secret data

## Security / Access

This tool runs with the privileges of the _executing user_ and does not elevate privileges at any time.

## Environemnt Variables
`ENABLE_CONFIG_DUMP` - Enables dumping of workspace config. Default is to not create workspace config dumps.<br/>
`KONG_ADDR` - For directing the collector to the address of the admin-api (Used to dump Kong config)<br/>
`DECK_HEADERS` - As with deck, used for RBAC credential headers for admin-api<br/>
`LOG_LEVEL` - "debug" will enable debug logging on the stdout of the container, otherwise info level logging only.<br/>
`KONG_RUNTIME` - Currently only 'docker' and 'kubernetes' are supported. IF left empty, application will attempt to find one or the other.<br/>
`KUBECONFIG` - Needs to point to a volume containing the ~/.kube/config or similar kubernetes config file.<br/>

Either the docker socket or the kubeconfig file need to be added as a volume to the container in order to extract logs from either deployment framework.

## Volume Mounts
`-v ~/config_dumps:/tmp` - Used to extract the dump files when they are collected. The KDT will put them in the /tmp directory.<br/>
`-v /var/run/docker.sock:/var/run/docker.sock` - Necessary if you are running Kong inside docker and want to extract logs.<br/>
`-v ~/.kube/docker_config:/kube/config` - Necessary if you are running Kong in K8s. Used alongside the `KUBECONFIG` environment variable.<br/>

## Running the container

```
docker run \
-e KONG_ADDR=https://admin-api.my.domain:8444 \
-e DECK_HEADERS=kong-admin-token:admin \
-e LOG_LEVEL=debug \
-e KONG_RUNTIME=docker \
-e KUBECONFIG=/kube/config \
-e ENABLE_CONFIG_DUMP=true \
-v ~/config_dumps:/tmp \
-v /var/run/docker.sock:/var/run/docker.sock \
-v ~/.kube/docker_config:/kube/config \
--name kdt kdt:1.0
```
This will show usage information. 

`collect` is the only supported feature currently.

The collect command will contact the k8s api obtained by the KUBECONFIG, or the Docker api obtained through the docker socket to retrieve the logs associated with all containers that are running one of our Kong images in either deployment environment.

It will then bundle the files up and make them available in the /tmp path inside the container.

## Building the image

To build the image

```
docker build . -t kdt:1.0
```
