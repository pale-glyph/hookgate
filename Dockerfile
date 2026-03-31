# --- build stage ---
FROM rust:1.94-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
# cache deps
RUN mkdir src && echo "fn main(){}" > src/main.rs && cargo build --release && rm -f target/release/paleglyph-hookgate* src/main.rs
COPY src ./src
RUN cargo build --release

# --- runtime stage ---
FROM alpine:3.21

RUN addgroup -S hookgate && adduser -S hookgate -G hookgate

COPY --from=builder /build/target/release/paleglyph-hookgate /usr/local/bin/hookgate

USER hookgate
EXPOSE 3000

# mount your hookgate.yaml at /etc/hookgate/hookgate.yaml
ENV HOOKGATE_CONFIG=/etc/hookgate/hookgate.yaml

ENTRYPOINT ["hookgate"]
