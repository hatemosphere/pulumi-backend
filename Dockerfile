# Build Stage
# Use the official Golang alpine image for a minimal build environment
FROM golang:1.26.0-alpine AS builder

# Install git for fetching Go modules
RUN apk add --no-cache git

# Set the working directory inside the container
WORKDIR /app

# Copy dependency mappings first to cache them as a Docker layer
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the application source code
COPY cmd/ cmd/
COPY internal/ internal/

# Build the Go application (CGO disabled — modernc.org/sqlite is pure Go)
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /pulumi-backend ./cmd/pulumi-backend/main.go

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
