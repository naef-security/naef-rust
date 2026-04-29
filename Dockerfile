FROM rust:latest AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN cargo build --release \
    --bin kda --bin kda-service --bin dsmtp \
    --bin vda --bin vda-service \
    --bin tebs

# ============================================================
# KDA Image
# ============================================================
FROM rust:latest AS naef-kda

RUN apt-get update && apt-get install -y unzip curl && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && ./aws/install && \
    rm -rf awscliv2.zip aws && \
    apt-get remove -y unzip curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/kda .
COPY --from=builder /build/target/release/kda-service .
COPY --from=builder /build/target/release/dsmtp .
COPY .env /app/.env
COPY init_120.json /app/init_120.json

RUN mkdir -p /app/NAEF /app/exchange /app/beacon

# Copy both local and distributed entrypoints/sync
COPY docker/kda/sync.sh /app/sync-local.sh
COPY docker/kda/entrypoint.sh /app/entrypoint-local.sh
COPY deploy/kda/sync.sh /app/sync-s3.sh
COPY deploy/kda/entrypoint.sh /app/entrypoint-s3.sh
RUN chmod +x /app/sync-local.sh /app/entrypoint-local.sh /app/sync-s3.sh /app/entrypoint-s3.sh

# Default: local mode. Override with NAEF_MODE=s3
ENV NAEF_MODE=local
COPY docker/kda/entrypoint-router.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

# ============================================================
# VDA Image
# ============================================================
FROM rust:latest AS naef-vda

RUN apt-get update && apt-get install -y unzip curl && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && ./aws/install && \
    rm -rf awscliv2.zip aws && \
    apt-get remove -y unzip curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/vda .
COPY --from=builder /build/target/release/vda-service .

RUN mkdir -p /app/NAEF /app/exchange /app/beacon

COPY docker/vda/sync.sh /app/sync-local.sh
COPY docker/vda/entrypoint.sh /app/entrypoint-local.sh
COPY deploy/vda/sync.sh /app/sync-s3.sh
COPY deploy/vda/entrypoint.sh /app/entrypoint-s3.sh
RUN chmod +x /app/sync-local.sh /app/entrypoint-local.sh /app/sync-s3.sh /app/entrypoint-s3.sh

ENV NAEF_MODE=local
COPY docker/vda/entrypoint-router.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

# ============================================================
# TEBS Image
# ============================================================
FROM rust:latest AS naef-tebs

RUN apt-get update && apt-get install -y unzip curl && \
    curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip -q awscliv2.zip && ./aws/install && \
    rm -rf awscliv2.zip aws && \
    apt-get remove -y unzip curl && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/target/release/tebs .

RUN mkdir -p /app/beacon

COPY docker/tebs/entrypoint.sh /app/entrypoint-local.sh
COPY deploy/tebs/entrypoint.sh /app/entrypoint-s3.sh
RUN chmod +x /app/entrypoint-local.sh /app/entrypoint-s3.sh

ENV NAEF_MODE=local
COPY docker/tebs/entrypoint-router.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
