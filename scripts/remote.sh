#!/bin/sh
# Build and test on the Docker host. The workstation has no Docker.
set -eu

HOST="${TWG_HOST:-lostinfuture@192.168.1.15}"
DEST="${TWG_DEST:-build/transmission-wireguard}"
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)

usage() {
	echo "usage: scripts/remote.sh {sync|test|build|selftest|e2e}" >&2
	exit 2
}

sync_tree() {
	ssh "$HOST" "mkdir -p ~/$DEST"
	if command -v rsync >/dev/null 2>&1; then
		rsync -az --delete --exclude .git --exclude private "$ROOT"/ "$HOST:~/$DEST/"
	else
		ssh "$HOST" "rm -rf ~/$DEST && mkdir -p ~/$DEST"
		tar -C "$ROOT" --exclude .git --exclude private -czf - . | ssh "$HOST" "tar -C ~/$DEST -xzf -"
	fi
}

remote() {
	ssh "$HOST" "cd ~/$DEST && $*"
}

[ $# -eq 1 ] || usage
case "$1" in
sync)
	sync_tree
	;;
test)
	sync_tree
	remote 'docker run --rm -v "$PWD":/src:z -w /src -e GOTOOLCHAIN=local -e CGO_ENABLED=0 golang:1.22-alpine sh -c "test -z \"\$(gofmt -l .)\" && go vet ./... && go test -count=1 ./..."'
	;;
build)
	sync_tree
	remote 'docker buildx build --load --build-arg SUPERVISOR_VERSION=dev -t twg:dev .'
	;;
selftest)
	remote 'docker run --rm twg:dev version && docker run --rm --cap-add NET_ADMIN twg:dev firewall-selftest'
	;;
e2e)
	remote 'sh test/e2e/run.sh all'
	;;
*)
	usage
	;;
esac
