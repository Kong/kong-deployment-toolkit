# Kong Deployment Toolkit

A companion application to the Kong Gateway for extracting logs and config information for ease of collection and speedy case resolution.

Currently supports Docker, Kubernetes and VM log extraction.

## What is collected

The tool can collect the following information and saves it as a `.tar.gz` file:

- Logs for all Kong gateway containers (K8s / Docker)
- Logs for all Kong Ingress Controller instances (K8s)
- Pod spec for all Kong gateway & ingress controller instances (K8s)
- Docker inspect information for all Kong gateway instances (Docker)
- Logs for all Kuma / Kong Mesh control-plane instances (K8s / Docker)
- Logs for all Kuma / Kong Mesh dataplanes (K8s / Docker)
- Pod spec for Kuma / Kong Mesh control-plane and dataplane instances (K8s)
- Docker inspect information for all Kuma / Kong Mesh control-plane instances (Docker)
- Summary entity information for all workspaces (Not config, purely counts)
- Status endpoint metrics
- License endpoint metrics
- Workspace config deck dumps

## Caveats

VM log collection can only be done on a VM by VM basis and the application needs to be run on the node itself. It requires access to the Kong prefix directory environment file to discover the VM log locations and then gathers them accordingly.

## How can it be run

You have the option of compiling the application into the binary architecture of your choice and running as a standalone binary, but you can also compile it into a custom docker container and run it that way.

## What is KDD.json

If you include the admin-api endpoint and an RBAC header (If needed to contact the admin-api successfully), then the log collection will also trigger a config collection and summary. This is an initiative we are starting to allow you to upload these log collections and config dumps to our support portal when raising a case, that allow the config details to be parsed and saved against particular Kong installations that you have in Test / Prod / UAT etc.

This information is then used to speed up case resolution in cases involving these environments by providing immediate environmental and configuration context without the need to ask further details.

There is an option to disable the attempt to collect the KDD information entirely should you need to.

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

`NOTE:` Either the docker socket or the kubeconfig file need to be added as a volume to the container in order to extract logs from either deployment framework from inside the container.

## Volume Mounts
`-v ~/config_dumps:/kdt` - Used to extract the dump files when they are collected. The KDT will put them in the `/kdt` directory inside the container.<br/>
`-v /var/run/docker.sock:/var/run/docker.sock` - Necessary if you are running Kong inside docker and want to extract logs.<br/>
`-v ~/.kube/docker_config:/kube/config` - Necessary if you are running Kong in K8s. Used alongside the `KUBECONFIG` environment variable.<br/>

## Building the container

To build the container

```
docker build . -t kdt:1.0
```
```
make build-docker
```

## Running the container

This example shows both KUBECONFIG and Docker socket volume bindings for reference.

```
docker run --rm \
-e KUBECONFIG=/kube/config \
-v ~/config_dumps:/kdt \
-v /var/run/docker.sock:/var/run/docker.sock \
-v ~/.kube/config:/kube/config \
--name kdt kdt:1.0 collect
```

The config_dumps volume mount is where you will find the resulting files.

## Building the binary

MacOS - amd64
```
make build-macos
```
```
env GOOS=darwin GOARCH=amd64 go build -o bin/kdt
```

Linux - amd64
```
make build-linux
```
```
env GOOS=linux GOARCH=amd64 go build -o bin/kdt
```

## Commands

You can use the --help flag to show you these options but they're also below for your convenience.

| Command Name | Flags                    | Description                                                                                                                                                                           | Environment Variable Overrides |
|--------------|--------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| collect      | --kong-addr              | The address to reach the admin-api of the Kong instance in question. Default: http://localhost:8001                                                                                   | KONG_ADDR                      |
|              | --rbac-header            | RBAC header required to contact the admin-api.                                                                                                                                        | RBAC_HEADER                    |
|              | --target-images          | Override default images to scrape logs from. Default: "kong-gateway","kubernetes-ingress-controller","kuma-dp","kuma-cp","kuma-init"                                                  |                                |
|              | --disable-kdd            | Disable KDD config collection. Default: false.                                                                                                                                        |                                |
|              | --dump-workspace-configs | Deck dump workspace configs to yaml files. Default: false. NOTE: Will not work if --disable-kdd=true                                                                                  | DUMP_WORKSPACE_CONFIGS         |
|              | --runtime                | Runtime to extract logs from (kubernetes, docker, vm). Runtime is auto detected if omitted.                                                                                           | KONG_RUNTIME                   |
|              | --target-pods            | CSV list of pod names to target when extracting logs. Default is to scan all running pods for Kong images.                                                                            | TARGET_PODS                    |
|              | --docker-since           | Return logs newer than a relative duration like 5s, 2m, or 3h. Default is 24h of logs. Used with docker runtime only.                                                                 | DOCKER_LOGS_SINCE              |
|              | --k8s-since-seconds      | Return logs newer than the seconds past. Defaults to 86400, the last 24hrs of logs. Used with K8s runtime only.                                                                       | K8S_LOGS_SINCE_SECONDS         |
|              | --prefix-dir             | The path to your prefix directory for determining VM log locations. Default: /usr/local/kong                                                                                          |                                |
|              | --redact-logs            | CSV list of terms to redact during log extraction.                                                                                                                                    |                                |
|              | --line-limit             | Return logs with this amount of lines retrieved. Defaults to 1000 lines. Used with all runtimes as a default. --k8s-since-seconds and --docker-since will both override this setting. |                                |

## Usage

./kdt collect --runtime kubernetes --kong-addr http://admin-api.kong.lan --rbac-header kong-admin-token:Sup3r@dmin 

This will extract all logs and podspec from all containers in the k8s cluster that contain image names that contain the following: "kong-gateway","kubernetes-ingress-controller","kuma-dp","kuma-cp","kuma-init"
This will also grab the configuration data from the admin-api.