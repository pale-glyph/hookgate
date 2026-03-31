# hookgate

**hookgate** is a lightweight webhook gateway written in Rust. It receives incoming webhook requests, optionally verifies their HMAC-SHA256 signatures, and forwards the payloads into Redis Streams for downstream consumption.

## Features

- Route webhooks to named Redis Streams
- Signature verification: GitHub-style (`X-Hub-Signature-256`) and [Svix](https://svix.com/)
- 1 MiB body limit to prevent resource exhaustion
- YAML-based configuration
- Docker-ready

## Quick Start

```bash
cp example/hookgate.yaml hookgate.yaml
# edit hookgate.yaml to set redis_url, bind address, and your hook routes
HOOKGATE_CONFIG=hookgate.yaml cargo run --release
```

## Configuration

```yaml
bind: "0.0.0.0:3000"          # optional, defaults to 0.0.0.0:3000
redis_url: "redis://127.0.0.1:6379"

hooks:
  - source: /webhooks/github   # path hookgate listens on
    stream: github_stream      # Redis Stream key to publish to
    secret: "your-secret"      # optional HMAC secret
    scheme: hub                # hub (default) or svix
```

## Environment Variables

| Variable           | Default          | Description                        |
|--------------------|------------------|------------------------------------|
| `HOOKGATE_CONFIG`  | `hookgate.yaml`  | Path to the YAML configuration file |
| `RUST_LOG`         | `hookgate=info`  | Log level filter                   |

## Docker

```bash
docker build -t hookgate .
docker run -p 3000:3000 -v $(pwd)/hookgate.yaml:/hookgate.yaml hookgate
```

## License

This project is licensed under the [MIT License](LICENSE).
