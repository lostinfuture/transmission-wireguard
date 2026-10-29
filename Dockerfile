# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.24
ARG SUPERVISOR_VERSION=0.1.0
ARG TRANSMISSION_VERSION=4.1.4
ARG TRANSMISSION_URL=https://github.com/transmission/transmission/releases/download/4.1.4/transmission-4.1.4.tar.xz
ARG TRANSMISSION_SHA256=86e7aa020cdf64826447034bc85f4d3b7c848d8c0891d9dc9b9fddfb2c805d22
ARG FLOOD_VERSION=1.0.1
ARG FLOOD_URL=https://github.com/johman10/flood-for-transmission/releases/download/v1.0.1/flood-for-transmission.tar.gz
ARG FLOOD_SHA256=0797c3d7c081665bfa876cbc78938204e1c811d5e1d09a3cb7040f365c19aa27
ARG FLOOD_REVISION=6d6c6fda7a507c864085d3c159ca6fe2886de06d
ARG FLOOD_LICENSE_URL=https://raw.githubusercontent.com/johman10/flood-for-transmission/6d6c6fda7a507c864085d3c159ca6fe2886de06d/LICENSE
ARG FLOOD_LICENSE_SHA256=3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986
ARG TRANSMISSIONIC_VERSION=1.9.0
ARG TRANSMISSIONIC_URL=https://github.com/lostinfuture/transmissionic/releases/download/v1.9.0/Transmissionic-webui-v1.9.0.zip
ARG TRANSMISSIONIC_SHA256=3bbeca59cda846041963bf668e57810829ac1ecc3d0ef01c70f2b68234e0e351
ARG TRANSMISSIONIC_REVISION=d5825a48b188c0089c80acb62b57bb54e24e641b
ARG WIREGUARD_GO_VERSION=0.0.20250522
ARG WIREGUARD_GO_URL=https://git.zx2c4.com/wireguard-go/snapshot/wireguard-go-0.0.20250522.tar.xz
ARG WIREGUARD_GO_SHA256=c7eeffb13e5eb43b93e54a21d78dd71414771af9e07112da5275690493695c9c
# The snapshot pins x/net v0.39.0 and x/crypto v0.37.0. Trivy reports those as high.
ARG X_NET_VERSION=v0.62.0
ARG X_CRYPTO_VERSION=v0.58.0
ARG RUSTNET_VERSION=1.7.0
ARG RUSTNET_URL=https://github.com/domcyrus/rustnet/archive/refs/tags/v1.7.0.tar.gz
ARG RUSTNET_SHA256=9d3f6509da06f832c04c5accc7b777c18f3de8b32c885137c9a1346990694dda

FROM alpine:${ALPINE_VERSION} AS transmission-src
ARG TRANSMISSION_URL TRANSMISSION_SHA256
RUN apk add --no-cache ca-certificates wget xz \
    && wget -O /tmp/transmission.tar.xz "${TRANSMISSION_URL}" \
    && echo "${TRANSMISSION_SHA256}  /tmp/transmission.tar.xz" | sha256sum -c \
    && mkdir -p /src \
    && tar -xJf /tmp/transmission.tar.xz -C /src --strip-components=1 \
    && rm /tmp/transmission.tar.xz

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS supervisor
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG SUPERVISOR_VERSION
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN apk add --no-cache go \
    && case "${TARGETARCH}" in \
         arm) export GOARM="${TARGETVARIANT#v}" ;; \
       esac \
    && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
         go build -trimpath -ldflags "-s -w -X main.version=${SUPERVISOR_VERSION} -X main.transmission=4.1.4" \
         -o /out/wg-supervisor ./cmd/wg-supervisor

FROM alpine:${ALPINE_VERSION} AS transmission-build
RUN apk add --no-cache \
        build-base cmake samurai pkgconf \
        openssl-dev curl-dev libevent-dev libdeflate-dev libpsl-dev linux-headers libcap
COPY --from=transmission-src /src /src
WORKDIR /src
RUN cmake -S . -B build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr \
        -DENABLE_DAEMON=ON \
        -DENABLE_GTK=OFF \
        -DENABLE_QT=OFF \
        -DENABLE_MAC=OFF \
        -DENABLE_CLI=OFF \
        -DENABLE_UTILS=OFF \
        -DENABLE_TESTS=OFF \
        -DENABLE_NLS=OFF \
        -DINSTALL_LIB=OFF \
        -DINSTALL_DOC=ON \
        -DREBUILD_WEB=OFF \
        -DINSTALL_WEB=ON \
        -DENABLE_UTP=ON \
        -DWITH_CRYPTO=openssl \
        -DWITH_SYSTEMD=OFF \
        -DUSE_SYSTEM_EVENT2=ON \
        -DUSE_SYSTEM_DEFLATE=ON \
        -DUSE_SYSTEM_PSL=ON \
        -DUSE_SYSTEM_MINIUPNPC=OFF \
        -DUSE_SYSTEM_NATPMP=OFF \
        -DUSE_SYSTEM_DHT=OFF \
        -DUSE_SYSTEM_UTP=OFF \
        -DUSE_SYSTEM_B64=OFF \
    && cmake --build build \
    && cmake --install build \
    && test -x /usr/bin/transmission-daemon \
    && test -d /usr/share/transmission/public_html \
    && test ! -e /usr/bin/transmission-remote \
    && if getcap /usr/bin/transmission-daemon | grep -q .; then exit 1; fi

FROM alpine:${ALPINE_VERSION} AS flood
ARG FLOOD_URL FLOOD_SHA256 FLOOD_LICENSE_URL FLOOD_LICENSE_SHA256 FLOOD_REVISION
RUN apk add --no-cache ca-certificates wget tar \
    && wget -O /tmp/flood.tar.gz "${FLOOD_URL}" \
    && echo "${FLOOD_SHA256}  /tmp/flood.tar.gz" | sha256sum -c \
    && mkdir -p /opt/transmission-ui \
    && tar -xzf /tmp/flood.tar.gz -C /opt/transmission-ui \
    && test -f /opt/transmission-ui/flood-for-transmission/index.html \
    && mkdir -p /usr/share/licenses/flood-for-transmission \
    && wget -O /usr/share/licenses/flood-for-transmission/LICENSE "${FLOOD_LICENSE_URL}" \
    && echo "${FLOOD_LICENSE_SHA256}  /usr/share/licenses/flood-for-transmission/LICENSE" | sha256sum -c \
    && printf '%s\n' \
        "https://github.com/johman10/flood-for-transmission/releases/tag/v1.0.1" \
        "${FLOOD_URL}" \
        "${FLOOD_REVISION}" \
        > /usr/share/licenses/flood-for-transmission/SOURCE \
    && rm /tmp/flood.tar.gz

FROM alpine:${ALPINE_VERSION} AS transmissionic
ARG TRANSMISSIONIC_VERSION TRANSMISSIONIC_URL TRANSMISSIONIC_SHA256 TRANSMISSIONIC_REVISION
RUN apk add --no-cache ca-certificates wget unzip \
    && wget -O /tmp/transmissionic.zip "${TRANSMISSIONIC_URL}" \
    && echo "${TRANSMISSIONIC_SHA256}  /tmp/transmissionic.zip" | sha256sum -c \
    && mkdir -p /tmp/unpack \
    && unzip -q /tmp/transmissionic.zip -d /tmp/unpack \
    && test -f /tmp/unpack/web/index.html \
    && test -f /tmp/unpack/web/LICENSE \
    && test -f /tmp/unpack/web/NOTICE \
    && test -f /tmp/unpack/web/default.json \
    && grep -q "Copyright (c) 2021 Transmissionic" /tmp/unpack/web/LICENSE \
    && grep -q "Copyright (c) 2026 lostinfuture" /tmp/unpack/web/NOTICE \
    && grep -q "script-src 'self'" /tmp/unpack/web/index.html \
    && grep -q 'src="js/' /tmp/unpack/web/index.html \
    && mkdir -p /opt/transmission-ui /usr/share/licenses/transmissionic \
    && mv /tmp/unpack/web /opt/transmission-ui/transmissionic \
    && cp /opt/transmission-ui/transmissionic/LICENSE /usr/share/licenses/transmissionic/LICENSE \
    && cp /opt/transmission-ui/transmissionic/NOTICE /usr/share/licenses/transmissionic/NOTICE \
    && printf '%s\n' \
        "https://github.com/lostinfuture/transmissionic/releases/tag/v${TRANSMISSIONIC_VERSION}" \
        "${TRANSMISSIONIC_URL}" \
        "${TRANSMISSIONIC_REVISION}" \
        > /usr/share/licenses/transmissionic/SOURCE \
    && rm -rf /tmp/transmissionic.zip /tmp/unpack \
    && if find /opt/transmission-ui/transmissionic \( -name '*.sh' -o -name '*.py' \) | grep -q .; then echo "script left in transmissionic" >&2; exit 1; fi

FROM --platform=$BUILDPLATFORM alpine:${ALPINE_VERSION} AS wireguard-go
ARG TARGETOS TARGETARCH TARGETVARIANT
ARG WIREGUARD_GO_URL WIREGUARD_GO_SHA256
ARG X_NET_VERSION X_CRYPTO_VERSION
RUN apk add --no-cache ca-certificates wget xz go \
    && wget -O /tmp/wireguard-go.tar.xz "${WIREGUARD_GO_URL}" \
    && echo "${WIREGUARD_GO_SHA256}  /tmp/wireguard-go.tar.xz" | sha256sum -c \
    && mkdir -p /src \
    && tar -xJf /tmp/wireguard-go.tar.xz -C /src --strip-components=1 \
    && rm /tmp/wireguard-go.tar.xz \
    && cd /src \
    && case "${TARGETARCH}" in \
         arm) export GOARM="${TARGETVARIANT#v}" ;; \
       esac \
    && GOTOOLCHAIN=local go get "golang.org/x/net@${X_NET_VERSION}" "golang.org/x/crypto@${X_CRYPTO_VERSION}" \
    && GOTOOLCHAIN=local go mod tidy \
    && GOTOOLCHAIN=local CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
         go build -mod=mod -trimpath -buildvcs=false -ldflags "-s -w" -o /out/wireguard-go . \
    && test -x /out/wireguard-go \
    && go version -m /out/wireguard-go | grep -q "golang.org/x/net[[:space:]]${X_NET_VERSION}" \
    && go version -m /out/wireguard-go | grep -q "golang.org/x/crypto[[:space:]]${X_CRYPTO_VERSION}" \
    && grep -q "Permission is hereby granted" /src/LICENSE \
    && cp /src/LICENSE /out/LICENSE

FROM alpine:${ALPINE_VERSION} AS rustnet
ARG TARGETARCH RUSTNET_URL RUSTNET_SHA256 RUSTNET_VERSION
RUN mkdir -p /out/bin /out/licenses \
    && if [ "${RUSTNET_SHA256}" = "UNPINNED" ]; then echo "RUSTNET_SHA256 is UNPINNED" >&2; exit 1; fi \
    && case "${TARGETARCH}" in \
         amd64|arm64) \
           apk add --no-cache ca-certificates wget build-base \
             cargo rustfmt clang llvm linux-headers \
             libpcap-dev elfutils-dev zlib-dev pkgconf \
           && wget -O /tmp/rustnet.tar.gz "${RUSTNET_URL}" \
           && echo "${RUSTNET_SHA256}  /tmp/rustnet.tar.gz" | sha256sum -c \
           && mkdir -p /src \
           && tar -xzf /tmp/rustnet.tar.gz -C /src --strip-components=1 \
           && rm /tmp/rustnet.tar.gz \
           && cd /src \
           && cargo build --release --locked \
           && test -x /src/target/release/rustnet \
           && cp /src/target/release/rustnet /out/bin/rustnet \
           && cp /src/LICENSE /out/licenses/LICENSE \
           && test -s /out/licenses/LICENSE \
           ;; \
         *) \
           echo "skipping rustnet on ${TARGETARCH}" \
           ;; \
       esac

FROM alpine:${ALPINE_VERSION}
RUN apk add --no-cache \
        ca-certificates \
        tzdata \
        iptables \
        iproute2 \
        wireguard-tools-wg \
        openssl \
        libevent \
        libcurl \
        libpsl \
        libdeflate \
        libstdc++ \
        libgcc \
        libcap \
        libpcap \
        libelf \
        zlib \
    && apk upgrade --no-cache
COPY --from=transmission-build /usr/bin/transmission-daemon /usr/bin/transmission-daemon
COPY --from=transmission-build /usr/share/transmission/public_html /usr/share/transmission/public_html
COPY --from=transmission-src /src/COPYING /usr/share/licenses/transmission/COPYING
COPY --from=flood /opt/transmission-ui/flood-for-transmission /opt/transmission-ui/flood-for-transmission
COPY --from=flood /usr/share/licenses/flood-for-transmission /usr/share/licenses/flood-for-transmission
COPY --from=transmissionic /opt/transmission-ui/transmissionic /opt/transmission-ui/transmissionic
COPY --from=transmissionic /usr/share/licenses/transmissionic /usr/share/licenses/transmissionic
COPY --from=supervisor /out/wg-supervisor /usr/bin/wg-supervisor
COPY --from=wireguard-go /out/wireguard-go /usr/bin/wireguard-go
COPY --from=wireguard-go /out/LICENSE /usr/share/licenses/wireguard-go/LICENSE
COPY --from=rustnet /out/ /tmp/rustnet/
COPY sbom/rustnet.cdx.json /usr/share/licenses/rustnet/rustnet.cdx.json
RUN set -o pipefail \
    && if [ -x /tmp/rustnet/bin/rustnet ]; then \
         mv /tmp/rustnet/bin/rustnet /usr/bin/rustnet \
         && mv /tmp/rustnet/licenses/LICENSE /usr/share/licenses/rustnet/LICENSE \
         && chmod 0755 /usr/bin/rustnet; \
       fi \
    && rm -rf /tmp/rustnet \
    && chmod 0755 /usr/bin/transmission-daemon /usr/bin/wg-supervisor /usr/bin/wireguard-go \
    && test -f /opt/transmission-ui/flood-for-transmission/index.html \
    && test -s /usr/share/licenses/flood-for-transmission/LICENSE \
    && grep -q 6d6c6fda7a507c864085d3c159ca6fe2886de06d /usr/share/licenses/flood-for-transmission/SOURCE \
    && test -f /opt/transmission-ui/transmissionic/index.html \
    && test -s /usr/share/licenses/transmissionic/LICENSE \
    && grep -q "Copyright (c) 2021 Transmissionic" /usr/share/licenses/transmissionic/LICENSE \
    && grep -q d5825a48b188c0089c80acb62b57bb54e24e641b /usr/share/licenses/transmissionic/SOURCE \
    && command -v wg \
    && ! command -v wg-quick \
    && ! command -v bash \
    && ! command -v python3 \
    && ! command -v natpmpc \
    && bins="/usr/bin/transmission-daemon" \
    && if [ -x /usr/bin/rustnet ]; then bins="$bins /usr/bin/rustnet"; fi \
    && ldd $bins | tee /tmp/ldd.out \
    && ! grep -E -q 'not found|Error relocating|Error loading' /tmp/ldd.out \
    && rm /tmp/ldd.out \
    && if getcap $bins /usr/bin/wireguard-go | grep -q .; then exit 1; fi \
    && test -s /usr/share/licenses/wireguard-go/LICENSE \
    && grep -q "Permission is hereby granted" /usr/share/licenses/wireguard-go/LICENSE \
    && /usr/bin/wireguard-go --version | grep -q 0.0.20250522 \
    && if [ -x /usr/bin/rustnet ]; then \
         test -s /usr/share/licenses/rustnet/LICENSE \
         && grep -q "Apache License" /usr/share/licenses/rustnet/LICENSE \
         && grep -q '"name": "rustnet"' /usr/share/licenses/rustnet/rustnet.cdx.json \
         && grep -q 'pkg:github/domcyrus/rustnet@v1.7.0' /usr/share/licenses/rustnet/rustnet.cdx.json \
         && grep -q '"value": "absent"' /usr/share/licenses/rustnet/rustnet.cdx.json \
         && /usr/bin/rustnet --version | grep -q 1.7.0 \
         && if getcap /usr/bin/rustnet | grep -q .; then exit 1; fi; \
       fi \
    && apk del libcap
ARG SUPERVISOR_VERSION
LABEL org.opencontainers.image.title=transmission-wireguard \
      org.opencontainers.image.description="Transmission and WireGuard in one container, with a kill switch." \
      org.opencontainers.image.version="${SUPERVISOR_VERSION}" \
      org.opencontainers.image.source=https://github.com/lostinfuture/transmission-wireguard \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT AND (GPL-2.0-only OR GPL-3.0-only) AND GPL-2.0-only AND GPL-3.0-only" \
      dev.lostinfuture.transmission.version=4.1.4 \
      dev.lostinfuture.wireguard-tools.version=1.0.20260223 \
      dev.lostinfuture.wireguard-go.version=0.0.20250522 \
      dev.lostinfuture.rustnet.version=1.7.0 \
      dev.lostinfuture.flood.revision=6d6c6fda7a507c864085d3c159ca6fe2886de06d \
      dev.lostinfuture.transmissionic.version=1.9.0 \
      autoheal=true
EXPOSE 9091
VOLUME ["/data", "/config"]
HEALTHCHECK --interval=30s --timeout=15s --start-period=210s --retries=3 \
    CMD ["/usr/bin/wg-supervisor", "healthcheck"]
ENTRYPOINT ["/usr/bin/wg-supervisor"]
CMD ["run"]
