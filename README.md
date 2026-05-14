# Kong Deployment Toolkit (`kdt`)

A companion tool for Kong Gateway that collects logs, configuration, and environment data into a single archive to speed up support case resolution.

Supported runtimes: **Docker**, **Kubernetes**, and **VM**.

---

## ⚠️ Pre-release / Testing Warning

> **This is an early release intended for testing and feedback only. Do NOT run it against production systems.**
>
> The output archive can contain sensitive data that is **not** automatically redacted, including but not limited to:
>
> - The contents of Kong's `.kong_env` file (VM mode) — typically includes `pg_password`, `cluster_cert_key`, license data, vault credentials, SMTP credentials, etc.
> - Container/pod environment variables passed inline (`docker inspect` output and pod YAML).
> - Process command lines (VM mode) — may include credentials passed as arguments.
> - Application logs — Kong access logs commonly include `Authorization` headers, JWTs, cookies, and request bodies.
>
> The `--sanitize` flag (default: on) only scrubs a small set of known fields in the Kong root configuration and the deck workspace dumps. It does **not** sanitize `.kong_env`, env vars, log lines, or `docker inspect` output.
>
> **Before sharing the archive with anyone, extract it and review the contents.** Use `--redact-logs` to redact known sensitive terms from log output.

---

## What gets collected

For every Kong-matching container / pod / VM the tool gathers:

- Container or pod logs (line- or time-limited)
- `/etc/resolv.conf`, `/etc/hosts`, `/etc/os-release`
- `top`, `ps aux`, `df -h`, `free -h`, `uname -a`, `ulimit -n`, and a listing of Kong's Lua templates directory
- Docker mode: `docker inspect` JSON per Kong container
- Kubernetes mode: pod YAML per Kong pod
- VM mode: `.kong_env` (verbatim), Kong access/error logs, plus host memory, CPU, disk, process, and network summaries

If the Kong Admin API is reachable (KDD enabled, the default), the tool also collects:

- Root configuration (sanitized denylist for `pg_password`, `cassandra_password`, `*_session_conf`, `*_cert_key`, `vitals_tsdb_address`)
- `/status` output
- `/license/report` output
- Per-workspace entity counts (consumers, services, routes, plugins, etc.)
- Optionally, full per-workspace deck dumps (`--dump-workspace-configs`), sanitized through `deck sanitize`

Everything is bundled into `<timestamp>-support.tar.gz` in the current working directory.

> Log collection from Docker and Kubernetes relies on Kong logs going to stdout/stderr. File-based logs are not collected in those modes.

---

## How it runs

`kdt` runs locally with the privileges of the executing user. It never elevates privileges and never sends data anywhere — it only reads from the Docker socket, the Kubernetes API, and/or the local filesystem (VM mode), and writes a tar.gz to disk.

---

## Installation

Pre-built binaries are published as release assets:

- `kdt` — Linux amd64
- `kdt-darwin-arm64` — macOS arm64
- `kdt-win-amd64.exe` — Windows amd64

Make the binary executable and place it on your `PATH`.

### Build from source

Requires Go 1.26.0 or later.

```sh
# Linux amd64
GOOS=linux  GOARCH=amd64 go build -o bin/kdt

# macOS arm64
GOOS=darwin GOARCH=arm64 go build -o bin/kdt

# Windows amd64
GOOS=windows GOARCH=amd64 go build -o bin/kdt.exe
```

### Build the container image

```sh
docker build -t kdt:latest .
```

---

## Usage

```
kdt collect [flags]
```

### Examples

Auto-detect runtime, no Admin API:

```sh
kdt collect
```

Docker, with Admin API and a 1h log window:

```sh
kdt collect \
  --runtime docker \
  --kong-addr http://localhost:8001 \
  --docker-since 1h
```

Konnect:

```sh
kdt collect \
  --konnect-mode \
  --konnect-control-plane-name my-cp \
  --kong-addr https://us.api.konnect.tech \
  --rbac-header "Authorization:Bearer $KONNECT_TOKEN" \
  --dump-workspace-configs
```

VM, with a non-default prefix and a custom redact list:

```sh
kdt collect \
  --runtime vm \
  --prefix-dir /opt/kong \
  --redact-logs "secret-token-1,secret-token-2"
```

> **Tip:** prefer the `RBAC_HEADER` environment variable over `--rbac-header` to keep credentials out of shell history and process listings.

---

## Flags

### Global

| Flag | Description |
|------|-------------|
| `--debug` | Enable verbose debug logging. **Note:** in `--konnect-mode`, debug-level logs currently include the bearer token. Do not share debug logs. |

### `collect`

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--runtime` | `-r` | _auto-detect_ | Force the runtime: `docker`, `kubernetes`, or `vm`. |
| `--kong-addr` | `-a` | `http://localhost:8001` | Kong Admin API address (or Konnect base URL when `--konnect-mode` is set). |
| `--rbac-header` | `-H` | _none_ | Header(s) for Kong Admin API auth. Format `Header-Name:value`. Repeat the flag for multiple headers. |
| `--target-images` | `-i` | `kong-gateway,kubernetes-ingress-controller` | Container image substrings used to identify Kong workloads. |
| `--target-pods` | `-p` | _all matching_ | CSV list of pod names to collect from (Kubernetes only). |
| `--namespace` | `-n` | _none_ | Kubernetes namespace to collect from. Required when `--runtime=kubernetes`. |
| `--konnect-mode` | `-x` | `false` | Collect from Konnect instead of a self-managed Admin API. |
| `--konnect-control-plane-name` | `-c` | _none_ | Required with `--konnect-mode`. |
| `--disable-kdd` | `-q` | `false` | Skip the Admin API / KDD collection step. |
| `--dump-workspace-configs` | `-d` | `false` | Dump each workspace's configuration via deck. Ignored if `--disable-kdd` is set. |
| `--sanitize` | `-s` | `true` | Redact a denylist of sensitive fields in the KDD root config and run deck dumps through `deck sanitize`. **Does not cover `.kong_env`, env vars, log lines, or `docker inspect`.** |
| `--redact-logs` | `-R` | _none_ | CSV list of substrings to replace with `<REDACTED>` in collected logs. Case-insensitive. |
| `--line-limit` | | `1000` | Maximum log lines collected per source. Overridden by `--docker-since` / `--k8s-since-seconds` when set. |
| `--docker-since` | | _none_ | Collect Docker logs newer than this relative duration (e.g. `5s`, `2m`, `3h`). Docker mode only. |
| `--k8s-since-seconds` | | `0` | Collect Kubernetes logs newer than this many seconds. Kubernetes mode only. |
| `--prefix-dir` | `-k` | `/usr/local/kong` | Kong prefix directory used to locate `.kong_env` and log paths. VM mode only. |

### Environment variable overrides

These variables override the corresponding flags for standalone usage:

| Variable | Equivalent flag | Notes |
|----------|-----------------|-------|
| `KONG_RUNTIME` | `--runtime` | Only applied when `--runtime` is not set. |
| `KONG_ADDR` | `--kong-addr` | |
| `RBAC_HEADER` | `--rbac-header` | Comma-separated; one header per entry. |
| `KONG_KONNECT_MODE` + `KONG_KDD_KONNECT` | `--konnect-mode` | `KONG_KONNECT_MODE` must be non-empty to engage; `KONG_KDD_KONNECT` must parse as a boolean (`true`/`false`). Split exists to avoid collision with Kong Gateway's own `KONG_KONNECT_MODE`. |
| `DISABLE_KDD` | `--disable-kdd` | Set to `true`. |
| `DUMP_WORKSPACE_CONFIGS` | `--dump-workspace-configs` | Set to `true`. |
| `DOCKER_LOGS_SINCE` | `--docker-since` | |
| `TARGET_PODS` | `--target-pods` | Comma-separated. |
| `K8S_NAMESPACE` | `--namespace` | Only applied when `--namespace` is not set. |
| `K8S_LOGS_SINCE_SECONDS` | `--k8s-since-seconds` | |

### Other commands

| Command | Description |
|---------|-------------|
| `kdt support` | Prints instructions for working with Kong Support (log collection, JWT issues, HAR files, version support policy). |

---

## Running in a container

The container image needs access to whichever runtime you are collecting from:

```sh
# Docker collection
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":/out -w /out \
  kdt:latest collect --runtime docker

# Kubernetes collection
docker run --rm \
  -e KUBECONFIG=/kube/config \
  -v ~/.kube/config:/kube/config:ro \
  -v "$PWD":/out -w /out \
  kdt:latest collect --runtime kubernetes --namespace kong
```

The resulting `<timestamp>-support.tar.gz` is written to the mounted working directory.

---

## Known issues (pre-release)

- **TLS verification is hard-disabled** for Admin API calls (`InsecureSkipVerify: true`). There is no flag to re-enable it yet.
- **`--sanitize` coverage is partial.** Specifically, the following are written to the archive verbatim:
  - `.kong_env` (VM mode)
  - Pod env vars in pod YAML
  - Container env vars in `docker inspect` output
  - Process command lines and network connection details (VM mode)
  - Log lines (unless `--redact-logs` is used)
- **`--redact-logs` lowercases the log line** while matching, which alters the captured log content even when nothing is redacted.
- **Debug mode** (`--debug`) logs the full `--rbac-header` slice when running in `--konnect-mode`.
- **The Makefile build targets still reference the old `kdt` binary name.** Build with the `go build -o bin/kdt …` commands above until the Makefile is updated.

Please file feedback against these issues — they are on the punch list before the tool can be recommended for production environments.

---

## Privacy

`kdt` does not transmit collected data anywhere. The archive stays on the machine that ran the tool until you choose to upload or share it.

**It is your responsibility to review the archive before sharing it.** See the warning at the top of this README for the categories of sensitive data that may be present.

---

## License

See [LICENSE](LICENSE).
