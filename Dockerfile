ARG GO_VERSION=1.26.6
# VERSION is stamped into the binary so a running container can say which
# release it is. Without it the image reports `dev` while the tarball from the
# same tag reports its number, which is two answers to one question.
ARG VERSION=dev
FROM golang:${GO_VERSION}-bookworm AS build
ARG VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/azure-apim-emulator ./cmd/azure-apim-emulator && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/azure-apim-emulator /usr/local/bin/azure-apim-emulator
COPY --chown=nonroot:nonroot --from=build /out/data /data
ENV APIM_ADDR=:8445
ENV APIM_DATA_DIR=/data
EXPOSE 8445
VOLUME ["/data"]
HEALTHCHECK --interval=5s --timeout=3s --retries=10 CMD ["/usr/local/bin/azure-apim-emulator", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/azure-apim-emulator"]
