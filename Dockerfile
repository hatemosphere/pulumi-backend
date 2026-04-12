FROM golang:1.26.2-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /pulumi-backend ./cmd/pulumi-backend/

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /pulumi-backend /pulumi-backend

USER nobody

EXPOSE 8080

ENV PULUMI_BACKEND_DB=/data/pulumi-backend.db

ENTRYPOINT ["/pulumi-backend"]
