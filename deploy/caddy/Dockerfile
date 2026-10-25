# syntax=docker/dockerfile:1.27.0@sha256:bde3983e9c939224420ddaf6b784cc30e09b035a4dea01f581230c50809f372e
# Rebuild the supported Caddy release with patched Go and HTTP/2 dependencies.
# Both inputs are immutable. Only certificates, the rebuilt binary and notices ship.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
ARG TARGETARCH
ARG SOURCE_DATE_EPOCH=1792886400
# These are the upstream image's tags, excluding unused SQL and Badger drivers.
# Keep symbols so the binary scanner can distinguish linked code from unused modules.
RUN GOOS=linux GOARCH=$TARGETARCH go build -mod=readonly -tags=nomysql,nopgx,nobadger -trimpath -buildvcs=false -ldflags='-buildid=' -o /caddy .

FROM caddy:2.11.7-alpine@sha256:eb4d35b7452d1ab6171fbdbe8d9275b2301dad6dad92115d91e19fb9b24d510f AS certificates
FROM scratch
ARG SOURCE_DATE_EPOCH=1792886400
COPY --from=certificates /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /caddy /usr/bin/caddy
COPY THIRD_PARTY_NOTICES.md /usr/share/doc/caddy/THIRD_PARTY_NOTICES.md
ENV XDG_CONFIG_HOME=/config XDG_DATA_HOME=/data
WORKDIR /srv
EXPOSE 80 443 443/udp 2019
VOLUME /config /data
ENTRYPOINT ["/usr/bin/caddy"]
CMD ["run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
