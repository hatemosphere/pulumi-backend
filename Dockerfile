# Build Stage
# Use the official Golang alpine image for a minimal build environment
FROM golang:1.25.6-alpine AS builder

# Install build dependencies: git for fetching Go modules; gcc/musl-dev for CGO (SQLite requires CGO)
RUN apk add --no-cache git build-base

# Set the working directory inside the container
WORKDIR /app

# Copy dependency mappings first to cache them as a Docker layer
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY cmd/ cmd/
COPY internal/ internal/

# Build the Go application
# CGO_ENABLED=1 is required for the modernc.org/sqlite driver (or standard go-sqlite3)
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-w -s" -o /pulumi-backend ./cmd/pulumi-backend/main.go

# Runtime Stage
# Use a minimal Alpine Linux image for the runtime
FROM alpine:3.23

# Add CA certificates for HTTPS/OIDC communication
# Add tzdata for time-based features (e.g. JWT expirations/Tokens)
RUN apk add --no-cache ca-certificates tzdata

# Create a non-root user and group for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set working directory and configure data mounting points
WORKDIR /home/appuser
RUN mkdir -p /home/appuser/data && chown appuser:appgroup /home/appuser/data

# Copy the pre-built binary from the builder stage
COPY --from=builder --chown=appuser:appgroup /pulumi-backend ./pulumi-backend

# Switch to the non-root user
USER appuser

# Expose the API port
EXPOSE 8080

# Environment variables to run out-of-the-box
ENV PULUMI_BACKEND_PORT=8080
ENV PULUMI_BACKEND_DB=/home/appuser/data/pulumi-backend.db

# Exec format for clean shutdown signals
ENTRYPOINT ["./pulumi-backend"]
