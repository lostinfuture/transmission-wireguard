# syntax=docker/dockerfile:1

ARG ALPINE_VERSION=3.24
ARG SUPERVISOR_VERSION=0.1.0
ARG TRANSMISSION_VERSION=4.1.4
ARG TRANSMISSION_URL=https://github.com/transmission/transmission/releases/download/4.1.4/transmission-4.1.4.tar.xz
ARG TRANSMISSION_SHA256=86e7aa020cdf64826447034bc85f4d3b7c848d8c0891d9dc9b9fddfb2c805d22

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
    && apk upgrade --no-cache
COPY --from=transmission-build /usr/bin/transmission-daemon /usr/bin/transmission-daemon
COPY --from=transmission-build /usr/share/transmission/public_html /usr/share/transmission/public_html
COPY --from=transmission-src /src/COPYING /usr/share/licenses/transmission/COPYING
COPY --from=supervisor /out/wg-supervisor /usr/bin/wg-supervisor
RUN set -o pipefail \
    && chmod 0755 /usr/bin/transmission-daemon /usr/bin/wg-supervisor \
    && command -v wg \
    && ! command -v wg-quick \
    && ! command -v bash \
    && ! command -v python3 \
    && ! command -v natpmpc \
    && ldd /usr/bin/transmission-daemon | tee /tmp/ldd.out \
    && ! grep -E -q 'not found|Error relocating|Error loading' /tmp/ldd.out \
    && rm /tmp/ldd.out \
    && if getcap /usr/bin/transmission-daemon | grep -q .; then exit 1; fi \
    && apk del libcap
ARG SUPERVISOR_VERSION
LABEL org.opencontainers.image.title=transmission-wireguard \
      org.opencontainers.image.description="Transmission and WireGuard in one container, with a kill switch." \
      org.opencontainers.image.version="${SUPERVISOR_VERSION}" \
      org.opencontainers.image.source=https://github.com/lostinfuture/transmission-wireguard \
      org.opencontainers.image.licenses="Apache-2.0 AND MIT AND (GPL-2.0-only OR GPL-3.0-only) AND GPL-2.0-only AND GPL-3.0-only" \
      dev.lostinfuture.transmission.version=4.1.4 \
      dev.lostinfuture.wireguard-tools.version=1.0.20260223 \
      autoheal=true
EXPOSE 9091
VOLUME ["/data", "/config"]
ENTRYPOINT ["/usr/bin/wg-supervisor"]
CMD ["run"]
