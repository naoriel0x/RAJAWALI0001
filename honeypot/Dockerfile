FROM golang:1.23-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/rajawali-honeypot ./cmd/main.go

FROM alpine:3.20
RUN addgroup -S rajawali && adduser -S -G rajawali rajawali
COPY --from=builder /out/rajawali-honeypot /usr/local/bin/rajawali-honeypot
USER rajawali
EXPOSE 2222 8080
ENTRYPOINT ["/usr/local/bin/rajawali-honeypot"]