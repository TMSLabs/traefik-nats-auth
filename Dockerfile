FROM golang:1.25.7-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates make

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build with version info
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME

RUN CGO_ENABLED=0 go build \
  -ldflags="-w -s -X main.Version=${VERSION} -X main.Commit=${COMMIT} -X main.BuildTime=${BUILD_TIME}" \
  -o auth-service \
  ./cmd/auth-service

FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata curl

# Create app user
RUN addgroup -g 1000 appuser && \
  adduser -D -u 1000 -G appuser appuser

WORKDIR /app

# Copy binary
COPY --from=builder /app/auth-service .

# Copy config template (optional)
# COPY --from=builder /app/config /app/config

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["./auth-service"]
CMD ["serve"]
