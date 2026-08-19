ARG GO_VERSION=1.26.6
FROM golang:${GO_VERSION}-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/azure-apim-emulator ./cmd/azure-apim-emulator && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/azure-apim-emulator /usr/local/bin/azure-apim-emulator
COPY --chown=nonroot:nonroot --from=build /out/data /data
ENV APIM_ADDR=:8445
ENV APIM_DATA_DIR=/data
EXPOSE 8445
VOLUME ["/data"]
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD ["/usr/local/bin/azure-apim-emulator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/azure-apim-emulator"]
