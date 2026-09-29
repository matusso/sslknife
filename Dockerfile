# Build and run SSLKnife in server mode.
#   docker build -t sslknife .
#   docker run --rm -it -v sslknife-data:/data sslknife init
#   docker run -p 127.0.0.1:8443:8443 -v sslknife-data:/data \
#     -e SSLKNIFE_PASSWORD_FILE=/run/secrets/sslknife sslknife
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/sslknife . && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/sslknife /usr/local/bin/sslknife
# The volume starts as a private directory owned by the runtime user.
COPY --from=build --chown=65532:65532 --chmod=0700 /out/data /data
ENV SSLKNIFE_DATA_DIR=/data SSLKNIFE_CONFIG=/data/config.yaml SSLKNIFE_NO_KEYRING=1
VOLUME ["/data"]
EXPOSE 8443
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/sslknife"]
# Listen on all container interfaces; publish the port on the host's
# loopback only (-p 127.0.0.1:8443:8443) unless remote access is intended.
CMD ["server", "--listen", "0.0.0.0:8443", "--allowed-host", "localhost"]
