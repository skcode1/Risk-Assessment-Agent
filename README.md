# Risk-Assessment-Agent for INFILTRIX

A high-throughput, event-driven cyber risk assessment engine designed for enterprise Security Operations Centers (SOC). The service ingests telemetry from Endpoint Detection and Response (EDR), Security Information and Event Management (SIEM), and identity platforms, applies deterministic scoring models across behavioral and temporal indicators, and generates auditable, explainable risk assessments.

---

## Architecture Overview

The system runs as an unprivileged, non-root microservice engineered with stateless evaluation kernels, PostgreSQL-backed immutable audit logs, and Redis temporal sliding-window counters.

```text
       [ Upstream Telemetry Sources ]
         (EDR, SIEM, Webhooks, APIs)
                      │
                      ▼
        ┌───────────────────────────┐
        │   Reverse Proxy / Ingress  │ (TLS Termination, Rate Limiting)
        └─────────────┬─────────────┘
                      │
                      ▼
  ┌───────────────────────────────────────┐
  │      FastAPI / Uvicorn Service        │  (Non-Root 'appuser')
  │                                       │
  │   ┌───────────────────────────────┐   │
  │   │   JWT RBAC & Scope Enforcer   │   │
  │   └───────────────┬───────────────┘   │
  │                   ▼                   │
  │   ┌───────────────────────────────┐   │
  │   │ Risk Orchestration Core (ROC) │   │
  │   └───────┬───────────────┬───────┘   │
  │           │               │           │
  │           ▼               ▼           │
  │     [Calculators]   [PII Redactor]    │
  │     • Behavior      (SHA-256 Mask)    │
  │     • Frequency                       │
  │     • Sensitivity                     │
  │     • History                         │
  └───────────┬───────────────┬───────────┘
              │               │
      AsyncPG │         Redis │ Pub/Sub & Counters
              ▼               ▼
   ┌─────────────────┐  ┌───────────────────┐
   │ PostgreSQL (15+)│  │  Redis Cache (7+)  │
   │  • Immutable    │  │ • Rate Limits     │
   │    Audit Logs   │  │ • Sliding Windows │
   │  • Assessments  │  │ • Deduplication   │
   └─────────────────┘  └───────────────────┘
```

---

## Configuration & Environment Variables

All settings are validated at startup using Pydantic Settings. Configure these variables in `.env` or inject them directly via your container orchestration secrets manager.

### Core Application Settings

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `PROJECT_NAME` | `string` | `Cyber Risk Orchestration Engine` | Identifier for logs, traces, and metrics. |
| `ENVIRONMENT` | `string` | `production` | Deployment environment (`production`, `staging`, `development`). |
| `DEBUG` | `boolean` | `false` | Verbose exceptions. **Must be `false` in production.** |
| `API_V1_STR` | `string` | `/api/v1` | Base route prefix for API endpoints. |

### Authentication & Authorization (RBAC)

| Variable | Type | Required | Description |
| --- | --- | --- | --- |
| `JWT_SECRET_KEY` | `string` | **Yes** | High-entropy key ($\ge 32$ bytes) for HMAC token signing and verification. |
| `JWT_ALGORITHM` | `string` | `HS256` | Cryptographic algorithm for JWT verification. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `integer` | `60` | Lifespan of generated authorization tokens. |

### Database (PostgreSQL)

| Variable | Type | Required | Description |
| --- | --- | --- | --- |
| `POSTGRES_SERVER` | `string` | **Yes** | Hostname or IP address of the PostgreSQL server. |
| `POSTGRES_PORT` | `integer` | `5432` | PostgreSQL listener port. |
| `POSTGRES_DB` | `string` | **Yes** | Target database name. |
| `POSTGRES_USER` | `string` | **Yes** | Application database user. |
| `POSTGRES_PASSWORD` | `string` | **Yes** | Password for the database user. |
| `ASYNC_DATABASE_URI` | `string` | **Auto** | Evaluated as `postgresql+asyncpg://${USER}:${PASS}@${SERVER}:${PORT}/${DB}`. |
| `DB_POOL_SIZE` | `integer` | `20` | Persistent connection pool size. |
| `DB_MAX_OVERFLOW` | `integer` | `10` | Temporary connection limit under peak load. |
| `DB_ECHO` | `boolean` | `false` | Log raw SQL to stdout. **Must be `false` in production.** |

### Cache & Ephemeral Counters (Redis)

| Variable | Type | Required | Description |
| --- | --- | --- | --- |
| `REDIS_HOST` | `string` | **Yes** | Hostname or IP of the Redis server. |
| `REDIS_PORT` | `integer` | `6379` | Listener port for Redis. |
| `REDIS_PASSWORD` | `string` | Optional | Redis authentication password. |
| `REDIS_DB` | `integer` | `0` | Redis logical database index for counter windows. |
| `REDIS_URL` | `string` | **Auto** | Evaluated as `redis://[:${PASSWORD}@]${REDIS_HOST}:${REDIS_PORT}/${REDIS_DB}`. |

### Telemetry & Observability

| Variable | Type | Default | Description |
| --- | --- | --- | --- |
| `OTEL_SDK_DISABLED` | `boolean` | `false` | Master toggle to disable OpenTelemetry tracing and metrics. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `string` | `http://localhost:4317` | Collector endpoint for distributed traces and metrics. |
| `OTEL_SERVICE_NAME` | `string` | `risk-assessment-agent` | Service namespace identified in distributed trace spans. |
| `PROMETHEUS_METRICS_ENABLED` | `boolean` | `true` | Exposes `/metrics` for Prometheus scrapers. |

---

## API Specification & Contracts

All evaluation endpoints require valid Bearer JWT authentication with explicitly scoped RBAC claims.

### Endpoints

| Method | Endpoint | Auth | Required Scopes | Description |
| --- | --- | --- | --- | --- |
| `POST` | `/api/v1/risk-assessments` | Bearer JWT | `assessments:write` | Ingests telemetry, executes scoring kernel, persists record. |
| `GET` | `/api/v1/risk-assessments/{id}` | Bearer JWT | `assessments:read` | Fetches an immutable assessment record by UUID. |
| `GET` | `/health` | None | None | Liveness probe verifying event loop responsiveness. |
| `GET` | `/health/ready` | None | None | Readiness probe verifying PostgreSQL and Redis connections. |
| `GET` | `/metrics` | None | None | Prometheus-formatted metrics scrape endpoint. |

### Scoring Formula & Thresholds

Composite scores are deterministically computed using four weighted components:

$$\text{Risk Score} = 0.4 \times \text{Behavior} + 0.3 \times \text{Frequency} + 0.2 \times \text{Sensitivity} + 0.1 \times \text{History}$$

* **LOW:** $0.0 \le \text{Score} < 40.0$
* **MEDIUM:** $40.0 \le \text{Score} < 65.0$
* **HIGH:** $65.0 \le \text{Score} < 85.0$
* **CRITICAL:** $85.0 \le \text{Score} \le 100.0$

### Sample Request: `POST /api/v1/risk-assessments`

```bash
curl -i -X POST "http://localhost:8000/api/v1/risk-assessments" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${JWT_TOKEN}" \
  -d '{
    "detection_event": {
      "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
      "source_type": "EDR",
      "severity": "HIGH",
      "metrics": {
        "confidence": 95.0,
        "fidelity": 0.95
      },
      "context": {
        "source_ip": "192.0.2.10",
        "destination_ip": "192.0.2.20",
        "hostname": "test-workstation-01",
        "username": "svc_secops",
        "rule_id": "AUTH-BRUTE-001",
        "rule_name": "Repeated Authentication Failure",
        "raw_payload": {
          "event_type": "authentication_failure",
          "failed_attempts": 40,
          "window_seconds": 300
        }
      }
    },
    "investigation_result": {
      "telemetry": {
        "event_frequency": 40,
        "historical_incident_count": 0,
        "severity_hint": 75.0,
        "endpoint_class": "WORKSTATION"
      },
      "touched_endpoints_detail": [
        {
          "endpoint_id": "test-workstation-01",
          "endpoint_class": "WORKSTATION",
          "is_compromised": false
        }
      ]
    }
  }'
```

### Sample Response (`201 Created`)

```json
{
  "assessment_id": "ea4c2c2f-6256-444f-a50a-2f1bceec66ed",
  "correlation_id": "550e8400-e29b-41d4-a716-446655440000",
  "source_ip": "192.0.2.10",
  "risk_score": 79.8,
  "rating": "HIGH",
  "components": {
    "behavior": 92.0,
    "frequency": 100.0,
    "sensitivity": 65.0,
    "history": 0.0
  },
  "created_at": "2026-10-20T03:00:00Z"
}
```

---

## Production Deployment & Container Verification

Follow these steps to deploy and verify the production-hardened release image.

### Prerequisites

* Docker Engine $\ge 24.0$ with the `docker-buildx` plugin enabled
* Network access to PyPI and Docker Hub
* Running instances of PostgreSQL ($\ge 15$) and Redis ($\ge 7$)

### 1. Clone the Release

Clone the verified tag using a shallow clone:

```bash
git clone --depth 1 --branch v1.0.0 https://github.com/skcode1/Risk-Assessment-Agent.git
cd Risk-Assessment-Agent
```

### 2. Configure Environment Variables

Create your environment configuration file from the template:

```bash
cp backend/.env.example .env
# Edit .env and supply your database credentials, Redis URL, and high-entropy JWT secrets
```

### 3. Build the Hardened Container Image

Build the multi-stage, non-root runtime image:

```bash
docker build -t risk-assessment-agent:v1.0.0 -f backend/Dockerfile .
```

### 4. Verify Security Gate (Trivy CVE & Secret Scan)

Ensure the image satisfies zero-tolerance security requirements (**0 HIGH**, **0 CRITICAL** vulnerabilities):

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$HOME/.cache/trivy:/root/.cache/trivy" \
  aquasec/trivy:latest image \
  --severity HIGH,CRITICAL \
  --ignore-unfixed \
  --exit-code 1 \
  risk-assessment-agent:v1.0.0
```

### 5. Launch the Service

Launch the risk engine in detached mode with automatic restart policies:

```bash
docker run -d \
  --name risk-assessment-engine \
  --restart unless-stopped \
  -p 8000:8000 \
  --env-file .env \
  risk-assessment-agent:v1.0.0
```

### 6. Verify Service Readiness

Confirm process startup and query the readiness endpoint:

```bash
# Check startup logs
docker logs --tail 20 risk-assessment-engine

# Verify application readiness probe
curl -f -s -o /dev/null -w "HTTP Status: %{http_code}\n" http://localhost:8000/health/ready
```

---

## Production Verification Checklist

Run this 7-point audit checklist against the running container using an ephemeral test token to guarantee engine invariants before routing live production traffic:

1. **Authorization & Schema Enforcement:** Requests without valid JWTs return `401 Unauthorized`; malformed schemas return `422 Unprocessable Entity`.
2. **Sub-Score Integrity:** Response strictly provides all four components: `behavior`, `frequency`, `sensitivity`, and `history`.
3. **Deterministic Mathematical Correctness:** The returned `risk_score` matches the weighted formula $0.4B + 0.3F + 0.2S + 0.1H$ rounded to 1 decimal place.
4. **Rating Threshold Alignment:** The rating tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) maps accurately to the computed score boundaries.
5. **Traceability:** Every evaluation returns a unique 36-character UUID `assessment_id` alongside the input `correlation_id`.
6. **Data Store Persistence:** The assessment and immutable audit records are verified present in the PostgreSQL database.
7. **Zero Information Leakage:** Stack traces, internal SQL strings, database URLs, and environment secrets remain completely absent from API responses and client-facing error payloads.
