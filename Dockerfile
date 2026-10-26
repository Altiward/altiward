# One image for production: altiward-api serving the console from its own origin.
#   docker build -t altiward-api .
#   docker run -p 8080:8080 -e ALTIWARD_DATABASE_URL=... -e ALTIWARD_AGENT_TOKENS=... \
#     -e ALTIWARD_CONSOLE_TOKENS=... altiward-api
# Put TLS in front of it; the API speaks plain HTTP.

# The console and the binary build on the runner's own platform and the Go build
# cross-compiles, so a multi-platform build runs nothing under emulation.
FROM --platform=$BUILDPLATFORM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS console
WORKDIR /src/console
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/ ./
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS api
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
COPY integrations/go.mod integrations/go.mod
RUN go mod download
COPY backend/ backend/
COPY integrations/ integrations/
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/altiward-api ./backend/cmd/altiward-api

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=api /out/altiward-api /usr/local/bin/altiward-api
COPY --from=console /src/console/dist /srv/console
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md /usr/share/doc/altiward/
COPY THIRD_PARTY_NOTICES.md /srv/console/third-party-notices.txt
ENV ALTIWARD_LISTEN_ADDR=:8080 \
    ALTIWARD_CONSOLE_DIR=/srv/console
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s CMD ["/usr/local/bin/altiward-api", "health"]
USER nonroot
ENTRYPOINT ["/usr/local/bin/altiward-api"]
