# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /tcpdump .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /tcpdump /usr/local/bin/tcpdump-server
EXPOSE 5221
USER nobody
ENTRYPOINT ["/usr/local/bin/tcpdump-server"]
