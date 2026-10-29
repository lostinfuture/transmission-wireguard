#!/bin/sh
# Kernel-dataplane scenarios against twg:dev. Does not publish 9091 and does not modprobe.
set -eu

HERE=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
NET=twg-e2e
SUBNET=172.30.88.0/24
PEER_IP=172.30.88.2
DNS_IP=172.30.88.53

usage() {
	echo "usage: test/e2e/run.sh {ka25|ka-absent|dead|dual-a|all}" >&2
	exit 2
}

if ! docker image inspect twg:dev >/dev/null 2>&1; then
	echo "twg:dev is missing; build it before e2e" >&2
	exit 1
fi

if [ ! -d /sys/module/wireguard ]; then
	echo "host /sys/module/wireguard is absent; the container may autoload the module; this script does not modprobe"
fi

cleanup() {
	docker rm -f twg-e2e-sut twg-e2e-peer twg-e2e-dns >/dev/null 2>&1 || true
	i=0
	while [ "$i" -lt 10 ]; do
		docker volume rm twg-e2e-conf >/dev/null 2>&1 && break
		if ! docker volume inspect twg-e2e-conf >/dev/null 2>&1; then
			break
		fi
		i=$((i + 1))
		sleep 1
	done
	if docker network inspect "$NET" >/dev/null 2>&1; then
		i=0
		while [ "$i" -lt 10 ]; do
			docker network rm "$NET" >/dev/null 2>&1 && break
			i=$((i + 1))
			sleep 1
		done
	fi
	true
}
trap cleanup EXIT

fail() {
	echo "FAIL: $*" >&2
	docker logs twg-e2e-sut 2>&1 | tail -n 120 >&2 || true
	docker logs twg-e2e-peer 2>&1 | tail -n 40 >&2 || true
	docker logs twg-e2e-dns 2>&1 | tail -n 40 >&2 || true
	exit 1
}

setup_net() {
	cleanup
	trap cleanup EXIT
	docker network create --subnet "$SUBNET" "$NET" >/dev/null
	docker volume create twg-e2e-conf >/dev/null
}

gen_priv() {
	docker run --rm --entrypoint wg twg:dev genkey | tr -d '\r\n'
}

pub_of() {
	printf '%s\n' "$1" | docker run --rm -i --entrypoint wg twg:dev pubkey | tr -d '\r\n'
}

write_conf() {
	docker run --rm -i --entrypoint /bin/sh -v twg-e2e-conf:/etc/wireguard:z twg:dev -c \
		'chmod 0700 /etc/wireguard && cat > /etc/wireguard/wg0.conf && chmod 0600 /etc/wireguard/wg0.conf && chown 0:0 /etc/wireguard /etc/wireguard/wg0.conf'
}

start_peer() {
	sut_pub=$1
	peer_priv=$2
	script=$(cat <<EOF
set -eu
umask 077
printf '%s\n' '$peer_priv' > /tmp/priv
ip link add dev wg0 type wireguard
ip -4 address add 10.88.0.1/24 dev wg0
wg set wg0 listen-port 51820 private-key /tmp/priv peer '$sut_pub' allowed-ips 10.88.0.2/32
rm -f /tmp/priv
ip link set dev wg0 up
echo peer-ready
while true; do sleep 3600; done
EOF
)
	docker run -d --name twg-e2e-peer \
		--network "$NET" --ip "$PEER_IP" \
		--cap-add NET_ADMIN \
		--security-opt no-new-privileges:true \
		--entrypoint /bin/sh \
		twg:dev -c "$script" >/dev/null
}

wait_log() {
	name=$1
	pat=$2
	secs=$3
	i=0
	while [ "$i" -lt "$secs" ]; do
		if docker logs "$name" 2>&1 | grep -q "$pat"; then
			return 0
		fi
		running=$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)
		if [ "$running" != "true" ]; then
			return 1
		fi
		i=$((i + 1))
		sleep 1
	done
	return 1
}

assert_key_hidden() {
	name=$1
	key=$2
	if docker logs "$name" 2>&1 | grep -F -q -- "$key"; then
		fail "private key appeared in $name logs"
	fi
}

start_sut() {
	timeout=$1
	shift
	# Remaining args are extra docker run flags, inserted before the image.
	docker run -d --name twg-e2e-sut \
		--network "$NET" \
		--cap-add NET_ADMIN \
		--security-opt no-new-privileges:true \
		--tmpfs /run \
		--stop-timeout 45 \
		-v twg-e2e-conf:/etc/wireguard:ro,z \
		-e PUID=1000 \
		-e PGID=1000 \
		-e WG_HANDSHAKE_TIMEOUT="$timeout" \
		"$@" \
		twg:dev >/dev/null
}

conf_body() {
	priv=$1
	peer_pub=$2
	endpoint=$3
	keep=$4
	keep_line=""
	if [ -n "$keep" ]; then
		keep_line="PersistentKeepalive = $keep"
	fi
	cat <<EOF
[Interface]
PrivateKey = $priv
Address = 10.88.0.2/32
MTU = 1420

[Peer]
PublicKey = $peer_pub
Endpoint = $endpoint
AllowedIPs = 0.0.0.0/0
$keep_line
EOF
}

live_pair() {
	keep=$1
	setup_net
	sut_priv=$(gen_priv)
	peer_priv=$(gen_priv)
	sut_pub=$(pub_of "$sut_priv")
	peer_pub=$(pub_of "$peer_priv")
	conf_body "$sut_priv" "$peer_pub" "${PEER_IP}:51820" "$keep" | write_conf
	start_peer "$sut_pub" "$peer_priv"
	if ! wait_log twg-e2e-peer peer-ready 20; then
		fail "peer did not come up"
	fi
	start_sut 20
	if ! wait_log twg-e2e-sut "transmission started" 150; then
		fail "transmission did not start (keepalive=${keep:-absent})"
	fi
	if ! docker logs twg-e2e-sut 2>&1 | grep -q "tunnel up"; then
		fail "tunnel up was not logged"
	fi
	assert_key_hidden twg-e2e-sut "$sut_priv"
	assert_key_hidden twg-e2e-sut "$peer_priv"
	if ! docker exec twg-e2e-sut sh -c 'test ! -e /run/wg-supervisor/privatekey && test ! -e /run/wg-supervisor/presharedkey'; then
		fail "key file remained under /run/wg-supervisor"
	fi
	docker stop -t 45 twg-e2e-sut >/dev/null
	code=$(docker inspect -f '{{.State.ExitCode}}' twg-e2e-sut)
	if [ "$code" != "0" ]; then
		fail "docker stop exit $code, want 0"
	fi
	echo "ok keepalive=${keep:-absent}"
}

scenario_dead() {
	setup_net
	sut_priv=$(gen_priv)
	peer_pub=$(pub_of "$(gen_priv)")
	conf_body "$sut_priv" "$peer_pub" "203.0.113.10:9" "" | write_conf
	start_sut 5
	code=$(docker wait twg-e2e-sut)
	if [ "$code" != "1" ]; then
		fail "dead endpoint exit $code, want 1"
	fi
	if ! docker logs twg-e2e-sut 2>&1 | grep -q "handshake timed out"; then
		fail "dead endpoint did not log handshake timed out"
	fi
	assert_key_hidden twg-e2e-sut "$sut_priv"
	echo "ok dead"
}

scenario_dual_a() {
	setup_net
	docker run -d --name twg-e2e-dns \
		--network "$NET" --ip "$DNS_IP" \
		-v "$HERE:/src:z" -w /src \
		-e GOTOOLCHAIN=local \
		golang:1.22-alpine \
		go run dns.go >/dev/null
	if ! wait_log twg-e2e-dns "dns listening" 90; then
		fail "dns server did not listen"
	fi
	sut_priv=$(gen_priv)
	peer_pub=$(pub_of "$(gen_priv)")
	conf_body "$sut_priv" "$peer_pub" "peer.test:51820" "" | write_conf
	start_sut 8 --dns "$DNS_IP" --dns-search=.
	code=$(docker wait twg-e2e-sut)
	if [ "$code" != "1" ]; then
		fail "dual-a exit $code, want 1"
	fi
	pin=$(docker logs twg-e2e-sut 2>&1 | grep "endpoint pinned" || true)
	if ! printf '%s\n' "$pin" | grep -q "ip=203.0.113.10"; then
		fail "dual-a did not pin 203.0.113.10: $pin"
	fi
	if ! printf '%s\n' "$pin" | grep -q "unused=1"; then
		fail "dual-a unused count: $pin"
	fi
	if printf '%s\n' "$pin" | grep -q "203.0.113.11"; then
		fail "dual-a tried the second address: $pin"
	fi
	if ! docker logs twg-e2e-sut 2>&1 | grep -q "handshake timed out"; then
		fail "dual-a did not time out on the first address"
	fi
	assert_key_hidden twg-e2e-sut "$sut_priv"
	echo "ok dual-a"
}

[ $# -eq 1 ] || usage
case "$1" in
ka25)
	live_pair 25
	;;
ka-absent)
	live_pair ""
	;;
dead)
	scenario_dead
	;;
dual-a)
	scenario_dual_a
	;;
all)
	live_pair 25
	live_pair ""
	scenario_dead
	scenario_dual_a
	;;
*)
	usage
	;;
esac
