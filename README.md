# Kong Debug Tool

A tool for collecting debug information for Kong Gateway and Kong Mesh / Kuma.

Currently supports docker and k8s deployments. Mesh and VM not currently supported.

## What is collected

The tool collects the following information and saves it as a `.tar.gz` file:

- Logs for all Kong gateway instances (K8s / VM / Docker)
- Logs for all Kong Ingress Controller instances (K8s)
- Pod spec for all Kong gateway & ingress controller instances (K8s)
- Docker inspect information for all Kong gateway instances (Docker)
- kong.conf file (VM)
- Logs for all Kuma / Kong Mesh control-plane instances (K8s / Docker)
- Logs for all Kuma / Kong Mesh dataplanes (K8s / Docker)
- Pod spec for Kuma / Kong Mesh control-plane instances (K8s)
- Docker inspect information for all Kuma / Kong Mesh control-plane instances (Docker)
- Dataplane configuration files (VM)
- Dataplane (Envoy) logs (K8s / VM / Docker)
- Dataplane (Envoy) configuration dumps (K8s / VM / Docker)

## Privacy 

This tool _does not_ send any collected information outside of the machine where it was executed. It is the responsibility of the user executing this tool to ensure that sensitive information is not unintentionally collected _before_ they transmit the output file (s) to Kong. 

Examples of sensitive data that should be checked for include (but are not limited to):

- Keys
- Passwords
- Other secret data
- PII

## Security / Access

This tool runs with the privileges of the _executing user_ and does not elevate privileges at any time.

## Enrironemnt Variables
KONG_ADDR : For directing the container to the address of the admin-api (Used to dump Kong config)
DECK_HEADERS : As with deck, used for RBAC credential headers for admin-api
LOG_LEVEL : "debug" will enable debug logging on the stdout of the container, otherwise info level logging only.
KONG_RUNTIME : Currently only 'docker' and 'kubernetes' are supported. IF left empty, application will attempt to find one or the other.
KUBECONFIG : Needs to point to a volume containing the ~/.kube/config or similar kubernetes config file.

Either the docker socket or the kubeconfig file need to be added as a volume to the container in order to extract logs from either deployment framework.

## Running the container

docker run \ 
-p 8080:8080 \ 
-e KONG_ADDR=https://docker.for.mac.localhost:8444 \
-e DECK_HEADERS=kong-admin-token:admin \
-e LOG_LEVEL=debug \
-e KONG_RUNTIME=kubernetes \
-v /var/run/docker.sock:/var/run/docker.sock \
-v ~/.kube/docker_config:/kube/config \
-e KUBECONFIG=/kube/config \
--name kdt \
kdt:1.0