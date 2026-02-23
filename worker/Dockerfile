FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/worker ./cmd/worker

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates git curl tar \
  && rm -rf /var/lib/apt/lists/*

# Semgrep
RUN curl -fsSL https://github.com/semgrep/semgrep/releases/latest/download/semgrep_linux_x86_64.tar.gz \
  | tar -xz -C /usr/local/bin --strip-components=1 semgrep

# Gitleaks
RUN curl -fsSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.4_linux_x64.tar.gz \
  | tar -xz -C /usr/local/bin gitleaks

# Trivy
RUN curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY --from=build /out/worker /app/worker
ENV TRIVY_NO_PROGRESS=true
CMD ["/app/worker"]
