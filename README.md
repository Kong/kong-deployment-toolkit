# Kong Deployment Toolkit

A companion application to the Kong Gateway for extracting logs and config information for ease of collection and speedy case resolution.

Currently supports docker and k8s deployments. VM installs not currently supported.

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
- License endpoint metrics
- Workspace config dumps if `DUMP_WORKSPACE_CONFIGS` is set to true

## Privacy 

This tool _does not_ send any collected information outside of the machine where it was executed. It is the responsibility of the user executing this tool to ensure that sensitive information is not unintentionally collected _before_ they transmit the output file (s) to Kong. 

Examples of sensitive data that should be checked for include (but are not limited to):

- Keys
- Passwords
- Other secret data

## Security / Access

This tool runs with the privileges of the _executing user_ and does not elevate privileges at any time.

## Environment Variables
`KUBECONFIG` - Needs to point to a volume containing the `~/.kube/config` or similar kubernetes config file.<br/>

`NOTE:` Either the docker socket or the kubeconfig file need to be added as a volume to the container in order to extract logs from either deployment framework.

## Volume Mounts
`-v ~/config_dumps:/kdt` - Used to extract the dump files when they are collected. The KDT will put them in the `/kdt` directory inside the container.<br/>
`-v /var/run/docker.sock:/var/run/docker.sock` - Necessary if you are running Kong inside docker and want to extract logs.<br/>
`-v ~/.kube/docker_config:/kube/config` - Necessary if you are running Kong in K8s. Used alongside the `KUBECONFIG` environment variable.<br/>

## Running the container

```
docker run --rm \
-e KUBECONFIG=/kube/config \
-v ~/config_dumps:/kdt \
-v /var/run/docker.sock:/var/run/docker.sock \
-v ~/.kube/config:/kube/config \
--name kdt kdt:1.0 collect
```

## Commands

| Command Name | Flags                    | Description                                                                                                  | Environment Variable Overrides |
|--------------|--------------------------|--------------------------------------------------------------------------------------------------------------|--------------------------------|
| collect      | --kong-addr              | The address to reach the admin-api of the Kong instance in question. Default: http://localhost:8001          | KONG_ADDR                      |
|              | --rbac-header            | RBAC header required to contact the admin-api.                                                               | RBAC_HEADER                    |
|              | --mesh-images            | Override default gateway images to scrape logs from. Default: "kong-gateway","kubernetes-ingress-controller" |                                |
|              | --gateway-images         | Override default gateway images to scrape logs from. Default: "kuma-dp","kuma-cp","kuma-init"                |                                |
|              | --dump-workspace-configs | Dump workspace configs to yaml files. Default: false.                                                        | DUMP_WORKSPACE_CONFIGS         |
|              | --runtime                | Runtime to extract logs from (kubernetes or docker). Runtime is auto detected if omitted.                    | KONG_RUNTIME                   |
|              | --target-pods            | CSV list of pod names to target when extracting logs. Default is to scan all running pods for Kong images.   | TARGET_PODS                    |
|              | --since                  | Return logs newer than a relative duration like 5s, 2m, or 3h. Default is 24h of logs. Docker only.          | LOGS_SINCE                     |
|              | --since-seconds          | Return logs newer than the seconds past. Defaults to 86400. The last 24hrs of logs. K8s only.                | LOGS_SINCE_SECONDS             |

## Building the image

To build the image

```
docker build . -t kdt:1.0
```
```
make build-docker
```

## Building the binary

MacOS
```
make build-macos
```
```
env GOOS=darwin GOARCH=amd64 go build -o bin/kdt
```

Linux
```
make build-linux
```
```
env GOOS=linux GOARCH=amd64 go build -o bin/kdt
```