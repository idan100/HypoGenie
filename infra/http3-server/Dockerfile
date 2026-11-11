FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod .
COPY main.go .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -a -o server main.go

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app
COPY --from=builder /app/server .
EXPOSE 443/udp
CMD ["./server"]
