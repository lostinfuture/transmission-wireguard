# transmission-wireguard

Transmission and kernel WireGuard in one container, with an iptables kill switch. The supervisor is PID 1. Transmission starts only after a fresh WireGuard handshake.

This tree is the v0.1.0 implementation. The operator README lands with the image publish. `v0.1.0` is the kernel dataplane. `wireguard-go` and Rustnet are not in that tag.

Build and test on the Docker host:

```bash
scripts/remote.sh test
scripts/remote.sh build
```
