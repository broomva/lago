# Multi-stage build for lagod
# Clones sibling dependencies (aiOS, vigil) and builds the workspace

FROM rust:1-bookworm AS builder

# Install protoc for gRPC compilation
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone sibling dependencies
RUN git clone --depth 1 https://github.com/broomva/aiOS.git ../aiOS
RUN git clone --depth 1 https://github.com/broomva/vigil.git ../vigil

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/

# Build release binary
RUN cargo build --release -p lagod

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/lagod /usr/local/bin/lagod

# Default data directory (mount a volume here)
ENV LAGO_DATA_DIR=/data/.lago
ENV RUST_LOG=info

EXPOSE 8080 50051

CMD ["lagod", "--data-dir", "/data/.lago", "--http-port", "8080", "--grpc-port", "50051"]
