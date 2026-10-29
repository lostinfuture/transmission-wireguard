# transmission-wireguard

Transmission and kernel WireGuard in one container. The torrent client starts after a fresh handshake. A kill switch drops traffic that would leave any other way.

The image is Alpine, with Transmission 4.1.4, wireguard-tools 1.0.20260223 (`wg` only), wireguard-go 0.0.20250522, Rustnet 1.7.0 on amd64 and arm64, and a static Go supervisor. It runs on `linux/amd64`, `linux/arm64`, and `linux/arm/v7`. The dataplane is the kernel unless you set `WG_IMPLEMENTATION=userspace`.

`docker-compose.yml` uses `ghcr.io/lostinfuture/transmission-wireguard:edge`. `main` publishes `edge` and `sha-<12>` after the image scan reports no Critical and no High findings. A version tag also publishes `latest`. Until that tag exists, build locally and point `image:` at `twg:dev`.

## What it does

The supervisor reads one WireGuard file, pins the endpoint to a single address, installs the kill switch, and brings `wg0` up. Transmission starts only after `wg show` reports a handshake that is at most five seconds old. On stop, Transmission exits first, then the device is deleted and the firewall is removed.

`LOCAL_NETWORK` keeps a route to your LAN on the original gateway. The kill switch is on unless `ENABLE_KILLSWITCH=false`. `AllowedIPs` chooses what is routed into the tunnel. It does not open the clearnet.

## Before you start

The host needs Linux 5.6 or newer with `CONFIG_WIREGUARD`. The container has `NET_ADMIN` and can autoload the module when the kernel allows it. This image does not run `modprobe`, and a missing module does not fall back to `wireguard-go`. If autoload is blocked (some SELinux policies, rootless Docker, user namespaces), load it on the host:

```bash
sudo modprobe wireguard
echo wireguard | sudo tee /etc/modules-load.d/wireguard.conf
```

A missing module exits 1 with `host kernel has no WireGuard device type (need Linux >= 5.6 with CONFIG_WIREGUARD loaded). This image does not modprobe and does not fall back to wireguard-go.`

A host that has no kernel module can opt in to userspace. See [Userspace WireGuard](#userspace-wireguard). Anything other than `kernel` or `userspace` exits 1 with `WG_IMPLEMENTATION must be kernel or userspace`.

Mount a directory on `/etc/wireguard`, read-only. `WIREGUARD_CONFIG=wg0` reads `/etc/wireguard/wg0.conf`. The directory and the file must be owned by root, must not be symlinks, and must not be writable by group or other. The file has one `[Interface]` and one `[Peer]`. `PostUp`, `PreUp`, `PostDown`, `PreDown`, `Table`, `SaveConfig`, and `FwMark` are rejected, including `Table=off` and `SaveConfig=false`. The operator file is never passed to `wg-quick` or `wg setconf`.

With `ENABLE_IPV6=false` (the default), an IPv6 address in `Address`, `DNS`, `AllowedIPs`, `Endpoint`, or `LOCAL_NETWORK` exits 1. It is not stripped. The Compose file sets `net.ipv6.conf.all.disable_ipv6=1`. Delete that sysctl before setting `ENABLE_IPV6=true`.

`stop_grace_period: 45s` (`--stop-timeout 45`). A stop runs the Transmission scripts and then a 10 second wait before `SIGKILL`. Docker's default 10 seconds cuts that off.

Port `9091` is the web UI. With no RPC username or password, anyone who can reach that port can add and remove torrents. Keep it off your router's port-forwarding list.

Do not set any `OPENVPN_*` variable, `CREATE_TUN_DEVICE`, `ENABLE_UFW`, `PORT_FORWARD`, or the NordVPN and PIA variables from transmission-openvpn. Those names are fatal even when the value is `false` or empty. The message is `this image is not transmission-openvpn; unset <NAME>`. Other unknown variables are not fatal.

The kernel dataplane does not use `/dev/net/tun`. The userspace opt-in does. See [Userspace WireGuard](#userspace-wireguard).

## Start

`docker-compose.yml` is the example. Edit the three paths. The WireGuard directory is `root:root` mode `0700`, and `wg0.conf` is mode `0600`.

```bash
docker compose up -d
```

`LOCAL_NETWORK` has to cover the machine you open the UI from. The example uses `192.168.1.0/24`. Without that prefix, the browser's reply is `ESTABLISHED` and then follows `default dev wg0`, so the UI hangs.

`restart: unless-stopped` is Docker's restart policy. `SELFHEAL` is a different switch. It defaults to false, and this file does not set it.

### Docker CLI

```bash
docker run -d \
  --name transmission-wireguard \
  --restart unless-stopped \
  --cap-add=NET_ADMIN \
  --security-opt no-new-privileges:true \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  --stop-timeout 45 \
  -p 9091:9091 \
  --tmpfs /run \
  -v /path/to/downloads:/data \
  -v /path/to/transmission/config:/config \
  -v /path/to/wireguard:/etc/wireguard:ro \
  -e LOCAL_NETWORK=192.168.1.0/24 \
  -e PUID=1000 -e PGID=1000 \
  twg:dev
```

`PUID` and `PGID` default to 1000. Explicit `0` runs Transmission as root and logs a warning.

### Check it

Open `http://<server-ip>:9091/`.

```bash
docker logs -f transmission-wireguard
docker exec transmission-wireguard wg show wg0 latest-handshakes
docker exec transmission-wireguard wg show wg0 endpoints
```

Do not run `wg show dump`. That command prints the private key.

Startup logs `endpoint pinned`, then `tunnel up`, then `transmission started`. `unused=<n>` is how many resolved addresses were not used.

## One address, and the pin does not roam

A hostname is resolved once, before the kill switch is installed. The supervisor keeps the first IPv4. When IPv6 is enabled and there is no IPv4 answer, it keeps the first IPv6. The rest are logged as `unused=<n>` and are not tried. If that first address is dead, pin a literal `Endpoint` in the WireGuard file.

The firewall allow and the host route use that IP. Kernel WireGuard can learn a new endpoint from an authenticated packet. This firewall drops that packet, so the peer entry stays on the pin.

`SELFHEAL` defaults to false. While it is false, the pin stays until the container restarts. Set it to true to restart WireGuard inside this process. The supervisor handshakes the pinned IP first. When `Endpoint` is a hostname and that handshake times out, it looks the name up through a temporary resolver path and moves the pin when the address changed. A literal `Endpoint` stays as written. An idle tunnel with no keepalive reaches a handshake age of 180 seconds and, with the flag set, restarts Transmission on the next 30 second tick. Leave the flag false on a quiet box, set a keepalive, or set `HEALTH_CHECK_HOST`. Do not run autoheal while `SELFHEAL=true`.

## If something feels wrong

- **The container exits before Transmission.** The mount is missing, the file is not `root`-owned, or a forbidden key is still in the file. `wg0` means `/etc/wireguard/wg0.conf`.
- **`handshake timed out`.** The pinned endpoint did not answer UDP within `WG_HANDSHAKE_TIMEOUT` (default 30 seconds). The device is deleted and the process exits 1. Transmission was not started.
- **The web UI does not load from another machine.** Publish `9091:9091`. Set `LOCAL_NETWORK` to the LAN prefix that contains the browser. A prefix shorter than `/8`, including `/0`, is rejected. `/8` through `/15` are accepted and logged as wider than `/16`.
- **Docker kills the container around 10 seconds after stop.** Set `stop_grace_period: 45s`.
- **`ENABLE_KILLSWITCH=false`.** The tunnel still comes up. Egress is not dropped, and a warning is logged. Narrow `AllowedIPs` does not do this. The flag does.
- **A hook did not run.** The file must be owned by root, must not be a symlink, and must not be writable by group or other. Each script is killed after 10 seconds.
- **`iptables -S` inside the container does not show Docker's DNS redirect.** Alpine's `iptables` is the nft wrapper. A dockerd that still uses iptables-legacy installs that DNAT in the legacy table. Both hooks run, so the `WG_OUT` drop still drops. Check the legacy table on the host. This image does not install `iptables-legacy`.

## Environment

Bool values are `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`, in any case. Anything else exits 1. Empty or unset means the default.

| Variable | Default | What to set |
| :--- | :--- | :--- |
| `WIREGUARD_CONFIG` | `wg0` | Basename in `/etc/wireguard`, without `.conf`. |
| `WG_IMPLEMENTATION` | `kernel` | `kernel` or `userspace`. Empty is `kernel`. There is no `auto`. |
| `WG_HANDSHAKE_TIMEOUT` | `30` | Seconds to wait for the first handshake and for each SELFHEAL handshake. Integer 5–120. |
| `LOCAL_NETWORK` | empty | Comma-separated prefixes via the original gateway. Required for a LAN web UI. |
| `PUID`, `PGID` | `1000` | User and group for Transmission. `0` is root, with a warning. Setting one copies it to the other. |
| `ENABLE_KILLSWITCH` | `true` | `false` disables the egress drop and logs a warning. |
| `ENABLE_IPV6` | `false` | `true` mirrors the kill switch for IPv6. Remove the Compose sysctl when you set this. |
| `PEER_DNS` | `true` | `true` writes `DNS=` from the WireGuard file into `/etc/resolv.conf` after the handshake. `false` leaves Docker's resolver. |
| `DROP_DEFAULT_ROUTE` | `false` | `true` deletes the original default route when it is still installed. `AllowedIPs` of `0.0.0.0/0` already replaced it, so the flag deletes nothing in that case. A later route add bypasses the delete. The OUTPUT drop does not. |
| `GLOBAL_APPLY_PERMISSIONS` | `true` | `false` does not chown `/data`. |
| `TRANSMISSION_HOME` | `/config/transmission-home` | Daemon config directory. |
| `LOG_TO_STDOUT` | `true` | `false` sends the daemon log to `$TRANSMISSION_HOME/transmission.log`. The supervisor's own lines stay on stdout. |
| `OPEN_FILES_LIMIT` | `8192` | `RLIMIT_NOFILE` for Transmission when it is not root. |
| `ALLOW_UPNP` | `false` | `true` lets Transmission map ports on the LAN. The default is forced back off while the daemon runs. |
| `ALLOW_TORRENT_SCRIPTS` | `false` | `true` lets RPC clients enable torrent scripts. Otherwise they are forced off. |
| `TRANSMISSION_RPC_PORT` | `9091` | Must match the port you publish. |
| `TRANSMISSION_RPC_USERNAME`, `TRANSMISSION_RPC_PASSWORD` | empty | Set both to require a login, or set neither. `TRANSMISSION_RPC_USER` is an alias for the username. |
| `TRANSMISSION_WEB_UI` | empty | Empty is the stock UI. `flood-for-transmission` (alias `flood`) or `transmissionic`. |
| `TRANSMISSION_WEB_HOME` | empty | When set, wins over `TRANSMISSION_WEB_UI`. |
| `TRANSMISSION_MESSAGE_LEVEL` | Transmission's own default, `4` | Not forced. `2` is error on the 4.x scale. |
| `TRANSMISSION_CACHE_SIZE_MIB` | Transmission's own default, `4` | Disk cache in MiB. `0` turns it off. `TRANSMISSION_CACHE_SIZE_MB` sets the same value. If both are set they must be equal. |
| `SELFHEAL` | `false` | `true` stops Transmission, revokes the device accept, and handshakes the pinned IP. A hostname is looked up only if that handshake times out, through a temporary resolver path that is removed before Transmission starts. A literal is left as written. The log line is `restarting wireguard` with reason `wg address is missing`, `handshake is stale`, or `health dial failed three times`. The process stays up, so Docker `restart:` does not fire. Do not combine with autoheal. |
| `HEALTH_CHECK_HOST` | empty | When set, the healthcheck dials this host on port 443, bound to the WireGuard address. With `SELFHEAL=true`, three failed dials also restart the tunnel. |
| `ENABLE_RUSTNET` | `false` | `true` starts the headless monitor. On armv7 the binary is absent: `true` logs `this arch has no Rustnet` and continues. The interactive TUI does not need this variable. |
| `RUSTNET_REFRESH_MS` | `5000` | Integer ≥ 1000. A bad value exits 1. |
| `RUSTNET_PCAP` | empty | Absolute path under `/config`, or empty. |

`TRANSMISSION_*` names that match a Transmission setting still apply, including `TRANSMISSION_PEER_PORT` and `TRANSMISSION_DOWNLOAD_DIR`.

These names exit 1 if they are set: `ENABLE_UFW`, `UFW_EXTRA_PORTS`, `UFW_ALLOW_GW_NET`, `CREATE_TUN_DEVICE`, `OPENVPN_PROVIDER`, `OPENVPN_CONFIG`, `OPENVPN_USERNAME`, `OPENVPN_PASSWORD`, `OPENVPN_OPTS`, `OPENVPN_DCO`, `VPN_CONFIG_SOURCE`, `GITHUB_CONFIG_SOURCE_REPO`, `GITHUB_CONFIG_SOURCE_REVISION`, `PORT_FORWARD`, `DISABLE_PORT_UPDATER`, `PIA_TOKEN`, `NORDVPN_COUNTRY`, `NORDVPN_CATEGORY`, `NORDVPN_PROTOCOL`.

## Web UI

An empty `TRANSMISSION_WEB_UI` leaves the stock UI. `TRANSMISSION_WEB_HOME`, when set, wins.

`flood-for-transmission` serves `/opt/transmission-ui/flood-for-transmission` (v1.0.1). `transmissionic` serves `/opt/transmission-ui/transmissionic` (v1.9.0). Other UI names exit 1.

## Hooks

Optional POSIX scripts, at fixed paths:

- `/scripts/wireguard-pre-start.sh`
- `/scripts/transmission-pre-start.sh`
- `/scripts/transmission-post-start.sh`
- `/scripts/transmission-pre-stop.sh`
- `/scripts/transmission-post-stop.sh`

A missing file is success. A symlink, a file that is not owned by root, or a file that is writable by group or other is an error. `wireguard-pre-start.sh` failure exits the container. `transmission-pre-start.sh` failure leaves the tunnel up and the supervisor running. Each script is killed after 10 seconds. They run as root. Their environment does not include passwords or key material, and those values are redacted from script output.

The six arguments are `<dev> <mtu> <empty> <wg-ipv4> <endpoint-ip> <context>`. `context` is `init` for the WireGuard script, `up` for the Transmission start scripts, and `stop` for the stop scripts.

The Compose file does not mount `/scripts`. The supervisor does not reap a process a hook backgrounds.

## Userspace WireGuard

`WG_IMPLEMENTATION=userspace` runs `/usr/bin/wireguard-go -f <dev>` from tag 0.0.20250522. The same `wg set` path and the same kill switch follow. It creates a TUN device. It does not also run `ip link add type wireguard`. The process needs `/dev/net/tun` in the container. It does not need `NET_RAW` or `SYS_MODULE`.

On stop the supervisor sends SIGTERM and SIGKILL after 5 seconds. On an architecture without the binary, userspace exits 1 with `this arch has no wireguard-go`. Kernel mode on that architecture is unchanged. This image builds the binary for amd64, arm64, and armv7.

`wireguard-go` prints a warning on stderr when it starts on Linux. That warning is upstream text. It does not fail the start. The lines are logged as `component=wg`.

`examples/userspace.override.yml` adds the TUN device and sets the variable. It does not add `NET_RAW`.

```bash
docker compose -f docker-compose.yml -f examples/userspace.override.yml up -d
```

The kernel stays the default. A missing module still exits 1 until you set `userspace` yourself.

## Rustnet

`ENABLE_RUSTNET` defaults to false. The supervisor starts the headless monitor after the kill switch and before the WireGuard device, so the capture sees the original interface. It does not restart the capture when the handshake completes. On an image without `/usr/bin/rustnet` (armv7), `true` logs once and continues.

The arguments are `rustnet --headless --output jsonl --interface any --no-resolve-dns --no-geoip --refresh-interval <RUSTNET_REFRESH_MS>`. `RUSTNET_REFRESH_MS` defaults to 5000. A value below 1000, or a value that is not an integer, is a fatal error. Stdout and stderr are prefixed `component=rustnet`, and the JSONL is left intact.

`RUSTNET_PCAP` defaults to empty. When set, it must be an absolute path under `/config`. The supervisor refuses a symlink, creates a regular file mode `0600`, and passes it as `--pcap-export`. If Rustnet exits, the tunnel stays up. The supervisor restarts it with backoff at most five times in ten minutes, then logs an error and leaves it down until the next container start. The healthcheck does not read Rustnet.

The interactive TUI is a second process. Leave `ENABLE_RUSTNET` unset and run:

```bash
docker exec -it transmission-wireguard rustnet --interface any --no-resolve-dns --no-geoip
```

The binary has no file capabilities. The image does not build the `kubernetes` Cargo feature. The supervisor and Rustnet do not inherit password or key variables.

The TUI needs `NET_RAW`, `BPF`, and `PERFMON` in addition to `NET_ADMIN`, plus a read-only `/sys/kernel/btf` mount. `examples/rustnet.override.yml` adds those and sets `ENABLE_RUSTNET=true` for the headless process. Compose replaces `cap_add`, so that file repeats `NET_ADMIN`. For the TUI only, use the capabilities and the mount from that file and leave the variable unset. The capture can name host processes. kprobes are host-wide.

```bash
docker compose -f docker-compose.yml -f examples/rustnet.override.yml up -d
```

## Recovery

Three mechanisms. The root Compose file enables only the first.

- **Docker `restart:`** starts a new container after this process exits. `docker-compose.yml` sets `unless-stopped`. A handshake timeout on startup exits 1, so Docker restarts it. An unexpected Transmission exit also exits 1.
- **`willfarrell/autoheal`** restarts containers whose healthcheck fails. The image sets the `autoheal=true` label. The label does nothing unless you run that sidecar.
- **`SELFHEAL`** restarts WireGuard inside this process. It does not exit PID 1, so `restart:` does not fire. The default is false, and the root Compose file does not set it. Do not run autoheal and `SELFHEAL` together. Both react to a dead peer, and autoheal restarts the container while the heal still owns the interface.

The Docker healthcheck is interval 30s, timeout 15s, retries 3, start period 210s. An idle handshake older than 180 seconds is provoked once. The probe fails only if that initiation does not land within 3 seconds, and the configured keepalive is restored either way.

## Pull the image

GitHub Container Registry is published from this repo. `edge` moves on `main` and on the Monday rebuild, after the scan. A version tag such as `v0.1.0` also publishes `0.1.0`, `v0.1.0`, `0.1`, `0`, and `latest`. The Monday rebuild does not move `latest`.

```bash
docker pull ghcr.io/lostinfuture/transmission-wireguard:edge
```

Docker Hub uses the same tags when the repository secret `DOCKER_PASSWORD` is set. `DOCKER_USERNAME` defaults to `lostinfuture`.

## Build from source

The workstation in this repo's dev loop has no Docker. `scripts/remote.sh` syncs the tree and runs on the Docker host (`lostinfuture@192.168.1.15` unless `TWG_HOST` is set):

```bash
scripts/remote.sh test
scripts/remote.sh build
scripts/remote.sh selftest
scripts/remote.sh e2e
```

`build` tags `twg:dev` and does not push. The Docker context includes `sbom/`. A copy that omits it fails on `COPY sbom/rustnet.cdx.json`. A local Docker engine can do the same:

```bash
docker build -t twg:dev .
docker run --rm twg:dev version
docker run --rm --cap-add=NET_ADMIN twg:dev firewall-selftest
docker run --rm --cap-add=NET_ADMIN twg:dev \
  drop-exec --uid 65534 --gid 65534 --nofile 64 -- cat /proc/self/status
```

`version` prints the supervisor version, requires `transmission-daemon 4.1.4`, and prints `wg --version`. When the binaries are in the image it also prints `rustnet` 1.7.0 and `wireguard-go` 0.0.20250522. A missing binary prints `rustnet absent` or `wireguard-go absent` and `version` still exits 0. `firewall-selftest` installs the kill switch in that container and removes it on the way out. `drop-exec` should show `CapBnd` as all zeros. The bounding set is dropped before `execve`. Dropping it needs `SETPCAP`, which is in Docker's default set and is kept by `--cap-add=NET_ADMIN`.

A bare `run` with no WireGuard file exits 1. `list-providers`, `check-snapshot`, `hook-up`, and `hook-down` exit 2.

## Credits and licenses

The Go supervisor in this repository is [Apache-2.0](LICENSE). Copyright 2026 lostinfuture.

The image also contains other programs, on their own terms:

- [Transmission](https://github.com/transmission/transmission) 4.1.4, GPL-2.0-only OR GPL-3.0-only, with the OpenSSL exception in its `COPYING`. Some files are MIT.
- [wireguard-tools](https://git.zx2c4.com/wireguard-tools/) 1.0.20260223, GPL-2.0-only. The image installs the `wg` package only. `wg-quick` is not installed.
- [wireguard-go](https://git.zx2c4.com/wireguard-go/) 0.0.20250522, MIT. Built from the tag tarball with `CGO_ENABLED=0`, not from the Alpine package.
- [Rustnet](https://github.com/domcyrus/rustnet) 1.7.0, Apache-2.0, on amd64 and arm64.
- [flood-for-transmission](https://github.com/johman10/flood-for-transmission) v1.0.1, GPL-3.0-only.
- [Transmissionic](https://github.com/lostinfuture/transmissionic) v1.9.0, MIT.

The image label `org.opencontainers.image.licenses` is the SPDX combination of those notices. Copies of the upstream license files are under `/usr/share/licenses/` in the image.
