# syntax=docker/dockerfile:1.7
FROM golang:1.27-alpine AS builder

RUN apk add --no-cache ca-certificates git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/auth ./cmd/auth \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/wallet ./cmd/wallet \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/migrate ./cmd/migrate

FROM alpine:3.21 AS runtime

RUN addgroup -S -g 10001 securewallet \
    && adduser -S -D -H -u 10001 -G securewallet securewallet \
    && apk add --no-cache ca-certificates tzdata wget \
    && mkdir -p /var/lib/securewallet \
    && chown -R securewallet:securewallet /var/lib/securewallet

WORKDIR /app
COPY --from=builder /out/auth /app/auth
COPY --from=builder /out/wallet /app/wallet
COPY --from=builder /out/migrate /app/migrate

USER securewallet:securewallet
EXPOSE 8081 8082

CMD ["/app/wallet"]
