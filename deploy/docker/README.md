# Container Topologies for Concert

Concert ships minimal `gcr.io/distroless/static-debian12:nonroot` images for the three compile-time editions and three companion daemons (running strictly as `UID/GID 65532`, read-only root filesystem compatible, zero shell or package manager):

| Image | Dockerfile | Binary | License | Exposed Ports |
| --- | --- | --- | --- | --- |
| **Core** | `Dockerfile` | `/usr/local/bin/concert` | Apache-2.0 | `80/tcp`, `443/tcp`, `443/udp` (HTTP/3), `8080/tcp`, `8081/tcp` |
| **WordPress / FastCGI** | `Dockerfile.wpconcert` | `/usr/local/bin/wpconcert` | Apache-2.0 | `80/tcp`, `443/tcp`, `443/udp`, `8080/tcp`, `8081/tcp` |
| **Enterprise** | `Dockerfile.econcert` | `/usr/local/bin/econcert` | Apache-2.0 | `80/tcp`, `443/tcp`, `443/udp`, `8080/tcp`, `8081/tcp`, `8082/tcp` |
| **KV / Shared Queue** | `Dockerfile.kv` | `/usr/local/bin/concert-kv` | Apache-2.0 | `6379/tcp`, `6380/tcp` |
| **Page Cache** | `Dockerfile.cache` | `/usr/local/bin/concert-cache` | Apache-2.0 | `6390/tcp`, `9390/tcp` |
| **Watchdog Supervisor** | `Dockerfile.watchdog` | `/usr/local/bin/concert-watchdog` | Apache-2.0 | *(outbound probe / supervisor)* |

## Building Images

```sh
# Local host architecture images (concert, wpconcert, econcert, concert-kv, concert-cache, concert-watchdog)
make docker

# Multi-arch Linux images (linux/amd64 + linux/arm64) via Buildx
make docker-buildx IMAGE_PREFIX=ghcr.io/andreimerlescu

# Optional FIPS 140-3 container build
GOFIPS140=v1.0.0 docker build -f Dockerfile.econcert --build-arg GOFIPS140 -t econcert:v0.3.0-fips .
```

## Ready-to-Run Docker Compose Topologies

1. **Standalone Core (`concert` + `Concertfile`):**
   ```sh
   docker compose -f deploy/docker/compose.standalone.yml up --build
   ```
   Public proxy on `http://127.0.0.1:8080`, Admin Portal on `http://127.0.0.1:8081`.

2. **WordPress + PHP-FPM (`wpconcert` + `wordpress:php8.3-fpm` + MariaDB):**
   ```sh
   docker compose -f deploy/docker/compose.wordpress.yml up --build
   ```
   `wpconcert` serves static files directly off the shared read-only webroot (`/var/www/html:ro`), runs a 15-second cart-safe micro-cache, and speaks FastCGI over TCP (`fcgi://wordpress:9000`) with zero nginx or Apache in front.

3. **Enterprise Active-Active Mesh (`econcert` 2 Edges → 2 Leaves + `concert-kv` HA):**
   ```sh
   docker compose -f deploy/docker/compose.enterprise.yml up --build
   ```
   Edge 1 (`:8080` / Portal `:8081`) and Edge 2 (`:8090` / Portal `:8091`) share `CONCERT_ADMIT_SECRET`, `CONCERT_HOP_SECRET`, and `concert-kv` (`CONCERT_KV_ADDR=concert-kv:6379`), routing traffic-weighted capacity across `leaf-1` and `leaf-2`. For production, enable TLS + mTLS (`CONCERT_HOP_REQUIRE_MTLS=true`) and mount 0600 secrets via Docker/Kubernetes secrets (`*_FILE`, including `CONCERT_KV_PASSWORD_FILE`).

## Kubernetes

- **Core Edition (`concert`):** [deploy/k8s/concert-deployment.yaml](../k8s/concert-deployment.yaml)
- **Hardened Enterprise Edition (`econcert`):** [deploy/k8s/deployment.yaml](../k8s/deployment.yaml)
