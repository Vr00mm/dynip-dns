FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o /out/dynip-dns ./cmd/dynip-dns/

FROM alpine:3.20
RUN adduser -D -H -s /sbin/nologin appuser
COPY --from=build /out/dynip-dns /usr/local/bin/dynip-dns
EXPOSE 53/udp 53/tcp
USER root
ENTRYPOINT ["/usr/local/bin/dynip-dns"]
