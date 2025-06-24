FROM golang:1.23-alpine3.22
WORKDIR /workdir
COPY . .
RUN go build -o outline ./cmd/outline-ss-server

FROM alpine:3.13
COPY --from=0 "/workdir/outline" "/bin/outline"
ENTRYPOINT ["/bin/outline"]