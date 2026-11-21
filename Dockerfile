# syntax=docker/dockerfile:1.7
# ---- frontend ----
FROM node:22-alpine AS web
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
# Vite writes into ../backend/internal/web/dist
RUN mkdir -p ../backend/internal/web && npm run build

# ---- backend ----
FROM golang:1.27-alpine AS build
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
COPY --from=web /src/backend/internal/web/dist ./internal/web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/cynews ./cmd/cynews

# ---- runtime ----
FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="CyNewsFeed" \
      org.opencontainers.image.description="Cybersecurity news aggregator with AI briefings, alert rules, detections, IOC sharing and a research agent" \
      org.opencontainers.image.source="https://github.com/Lariat-Labs/CyNewsFeed" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=build /out/cynews /cynews
ENV PORT=8080 LOG_FORMAT=json
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/cynews"]
CMD ["serve"]
