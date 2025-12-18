FROM docker.io/golang:1.25-alpine3.23 AS builder
RUN mkdir /src /deps
RUN apk update && apk add git build-base binutils-gold
WORKDIR /deps
ADD go.mod /deps
RUN go mod download
ADD / /src
WORKDIR /src
RUN go build -a -o rancher-fip-lb-controller cmd/lb-controller/main.go
FROM docker.io/alpine:3.23
RUN adduser -S -D -H -h /app rancher-fip-lb-controller
USER rancher-fip-lb-controller
COPY --from=builder /src/rancher-fip-lb-controller /app/
WORKDIR /app
ENTRYPOINT ["./rancher-fip-lb-controller"]