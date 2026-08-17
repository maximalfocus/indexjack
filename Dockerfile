# Both stages are pinned by immutable digest so that a build is reproducible and
# an upstream tag move cannot change what runs.
FROM golang:1.26-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build

ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local

WORKDIR /src
# The module has no third-party requirements, so the build needs no network.
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/indexjack ./cmd/indexjack

# A static, shell-less base: there is no interpreter in the runtime image for a
# package artifact to reach even if one somehow tried.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a

COPY --from=build /out/indexjack /usr/local/bin/indexjack
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/indexjack"]
CMD ["--help"]
