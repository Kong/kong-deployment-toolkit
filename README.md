# Kong Deployment Toolkit (`kdt`)

A companion tool for Kong Gateway that collects logs, configuration, and environment data into a single archive to speed up support case resolution.

Supported runtimes: **Docker**, **Kubernetes**, and **VM**.

---

## ⚠️ Pre-release / Testing Warning

> **This is an early release intended for testing and feedback only. Do NOT run it against production systems.**
>
> The output archive can still contain sensitive data that requires care before sharing, including but not limited to:
>
> - Process command lines (VM mode) — may include credentials passed as arguments. Not covered by `--sanitize`.
> - Application logs — Kong access logs commonly include `Authorization` headers, JWTs, cookies, and request bodies. Use `--redact-logs` to redact known sensitive terms from log output.
>
> The `--sanitize` flag (default: on) redacts values for keys/env vars matching common secret-name patterns (`password`, `secret`, `token`, `*_key`, `*_conf`, `cert`, `license`) across the Kong root configuration, deck workspace dumps, the VM `.kong_env` file, `docker inspect` output, and pod YAML env vars. It is pattern-based, not exhaustive — a secret stored under an unusual key name may not be caught. Collected files and the final archive are created with `0600` permissions (owner read/write only).
>
> **Before sharing the archive with anyone, extract it and review the contents.**

---

## What gets collected

For every Kong-matching container / pod / VM the tool gathers:

- Container or pod logs (line- or time-limited)
- `/etc/resolv.conf`, `/etc/hosts`, `/etc/os-release`
- `top`, `ps aux`, `df -h`, `free -h`, `uname -a`, `ulimit -n`, and a listing of Kong's Lua templates directory
- Docker mode: `docker inspect` JSON per Kong container
- Kubernetes mode: pod YAML per Kong pod
- VM mode: `.kong_env` (sanitized when `--sanitize` is set), Kong access/error logs, plus host memory, CPU, disk, process, and network summaries

If the Kong Admin API is reachable (KDD enabled, the default), the tool also collects:

- Root configuration (sanitized: explicit denylist plus pattern-based redaction of any key matching `password`, `secret`, `*_key`, `*_conf`, `token`, or `license_data`)
- `/status` output
- `/license/report` output
- Per-workspace entity counts (consumers, services, routes, plugins, etc.)
- Optionally, full per-workspace deck dumps (`--dump-workspace-configs`), sanitized through `deck sanitize`

Everything is bundled into `<timestamp>-support.tar.gz` in the current working directory.

> Log collection from Docker and Kubernetes relies on Kong logs going to stdout/stderr. File-based logs are not collected in those modes.
>
> All intermediate files are written to a private temporary directory for the duration of the run (not the current working directory) and removed automatically once the archive is created — a pre-existing file in your working directory that happens to share a name with a collected file (e.g. `ps`, `top`, `hosts`) is never read, overwritten, or deleted.

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

Requires Go 1.26.0 or later (the module's `go.mod` declares this minimum so it stays compatible with other consumers of this module; 1.26.5 or later is recommended, since earlier 1.26.x patch releases have known stdlib vulnerabilities. Released binaries and the container image are built with 1.26.5+).

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
| `--debug` | Enable verbose debug logging. |

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
| `--sanitize` | `-s` | `true` | Redact sensitive fields (denylist + secret-name pattern match) in the KDD root config, deck dumps (via `deck sanitize`), the VM `.kong_env` file, `docker inspect` env vars, and pod YAML env vars. **Does not cover log lines or process command lines.** |
| `--redact-logs` | `-R` | _none_ | CSV list of substrings to replace with `<REDACTED>` in collected logs. Case-insensitive. |
| `--line-limit` | | `1000` | Maximum log lines collected per source. Overridden by `--docker-since` / `--k8s-since-seconds` when set. |
| `--docker-since` | | _none_ | Collect Docker logs newer than this relative duration (e.g. `5s`, `2m`, `3h`). Docker mode only. |
| `--k8s-since-seconds` | | `0` | Collect Kubernetes logs newer than this many seconds. Kubernetes mode only. |
| `--prefix-dir` | `-k` | `/usr/local/kong` | Kong prefix directory used to locate `.kong_env` and log paths. VM mode only. |
| `--tls-skip-verify` | | `false` | Skip TLS certificate verification when connecting to the Kong Admin API. **Insecure** — allows an on-path attacker to intercept RBAC/Konnect credentials. Only use against trusted networks/hosts. |
| `--ca-cert` | | _none_ | Path to a PEM-encoded CA certificate bundle used to verify the Kong Admin API's TLS certificate, for self-signed or private-CA deployments. |

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

The image runs as a non-root, distroless user (no shell, no package manager). It needs access to whichever runtime you are collecting from:

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

> **Docker mode + non-root image:** the Docker daemon socket is typically owned by `root:docker` and not world-accessible, so the container's non-root user may get `permission denied` connecting to a mounted `/var/run/docker.sock`. If that happens, either add the socket's group to the container (`--group-add $(stat -c '%g' /var/run/docker.sock)` on Linux) or override the user for that run (`docker run --user root ...`). Kubernetes and VM mode are unaffected.

The resulting `<timestamp>-support.tar.gz` is written to the mounted working directory.

---

## Known issues (pre-release)

- **`--sanitize` coverage is pattern-based, not exhaustive.** The following are still written to the archive verbatim:
  - Process command lines and network connection details (VM mode)
  - Log lines (unless `--redact-logs` is used)
  - Any secret stored under a key/env-var name that doesn't match the `password`/`secret`/`token`/`*_key`/`*_conf`/`cert`/`license` patterns
- **`govulncheck` in CI is informational, not a hard gate.** `github.com/docker/docker` currently has reachable findings with no client-side fix available upstream (daemon-side moby issues); see the workflow comment in `.github/workflows/build-and-compress.yaml`.

Please file feedback against these issues — they are on the punch list before the tool can be recommended for production environments.

---

## Privacy

`kdt` does not transmit collected data anywhere. The archive stays on the machine that ran the tool until you choose to upload or share it.

**It is your responsibility to review the archive before sharing it.** See the warning at the top of this README for the categories of sensitive data that may be present.

---

## License

See [LICENSE](LICENSE).
