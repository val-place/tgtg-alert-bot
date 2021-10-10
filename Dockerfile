FROM golang:1.17-alpine as builder
WORKDIR /build
COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o app ./cmd/toogoodtogo/main.go

FROM scratch
WORKDIR /app
COPY --from=builder /build/app /app/
COPY --from=builder /usr/local/go/lib/time/zoneinfo.zip /
ENV ZONEINFO=/zoneinfo.zip
CMD ["./app"]
